//! Pure document-to-document mutation for [`Operation::EnsureMarkedArrayElement`]
//! (ADR-0023 D3, FORNX-428 S6). Mirrors `claude_adapter::install_claude_hooks`/
//! `uninstall_claude_hooks` exactly, generalized from a hardcoded path
//! (`hooks.<event>`) to a manifest-declared RFC 6901 JSON pointer.
//!
//! `apply_document`/`revert_document` take and return `serde_json::Value` --
//! no I/O. [`plan_apply`] is the only function here that touches a
//! filesystem, and it only reads (never writes) the target file, mirroring
//! `claude_adapter::plan_install_at`'s read-only contract.

use crate::adapter_manifest::{AdapterManifest, Operation};
use crate::adapter_registry::AdapterActionResult;

/// Splits an RFC 6901 pointer into its unescaped segments. `~1` -> `/`,
/// `~0` -> `~`, applied exactly once per segment (unescaping twice would
/// let `~01` address a different node than RFC 6901 specifies).
fn pointer_segments(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return Vec::new();
    }
    pointer
        .split('/')
        .skip(1) // leading "/" produces an empty first split segment
        .map(|seg| seg.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Resolves `pointer` within `root`, creating missing intermediate
/// *objects* only, and returns a mutable reference to the terminal array.
/// Refuses (returns `Err`, never overwrites) if an existing intermediate
/// value is not an object, or the terminal value exists and is not an
/// array -- the same non-clobber rule `install_claude_hooks` enforces.
fn resolve_array_mut<'a>(
    root: &'a mut serde_json::Value,
    pointer: &str,
) -> anyhow::Result<&'a mut Vec<serde_json::Value>> {
    let segments = pointer_segments(pointer);
    anyhow::ensure!(
        !segments.is_empty(),
        "operation pointer {pointer:?} must address a nested array, not the document root"
    );

    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;
        let obj = current.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!(
                "existing value at a prefix of {pointer:?} is not an object -- refusing to overwrite it"
            )
        })?;
        if is_last {
            let entry = obj
                .entry(segment.clone())
                .or_insert_with(|| serde_json::json!([]));
            anyhow::ensure!(
                entry.is_array(),
                "existing value at {pointer:?} is not an array -- refusing to overwrite it"
            );
            return Ok(entry.as_array_mut().expect("just checked is_array"));
        }
        current = obj
            .entry(segment.clone())
            .or_insert_with(|| serde_json::json!({}));
    }
    unreachable!("loop always returns on the last segment")
}

fn has_marker(element: &serde_json::Value, marker_key: &str, marker_value: &str) -> bool {
    element.get(marker_key).and_then(|v| v.as_str()) == Some(marker_value)
}

/// Applies every operation to `document`, idempotently. Returns the new
/// document; the caller compares against the original to compute `changed`.
pub fn apply_document(
    document: &serde_json::Value,
    operations: &[Operation],
) -> anyhow::Result<serde_json::Value> {
    let mut doc = document.clone();
    for op in operations {
        let Operation::EnsureMarkedArrayElement {
            pointer,
            marker_key,
            marker_value,
            element,
        } = op;
        let array = resolve_array_mut(&mut doc, pointer)?;
        let already_present = array
            .iter()
            .any(|e| has_marker(e, marker_key, marker_value));
        if !already_present {
            array.push(element.clone());
        }
    }
    Ok(doc)
}

/// Removes exactly the marker-bearing elements every operation declares,
/// pruning containers emptied by that removal only -- never a container
/// that still holds an unrelated element.
pub fn revert_document(
    document: &serde_json::Value,
    operations: &[Operation],
) -> serde_json::Value {
    let mut doc = document.clone();
    for op in operations {
        let Operation::EnsureMarkedArrayElement {
            pointer,
            marker_key,
            marker_value,
            ..
        } = op;
        let segments = pointer_segments(pointer);
        if segments.is_empty() {
            continue;
        }
        remove_marked(&mut doc, &segments, marker_key, marker_value);
    }
    doc
}

fn remove_marked(
    current: &mut serde_json::Value,
    segments: &[String],
    marker_key: &str,
    marker_value: &str,
) {
    let Some((head, rest)) = segments.split_first() else {
        return;
    };
    let Some(obj) = current.as_object_mut() else {
        return;
    };
    let Some(child) = obj.get_mut(head) else {
        return;
    };
    if rest.is_empty() {
        if let Some(arr) = child.as_array_mut() {
            arr.retain(|e| !has_marker(e, marker_key, marker_value));
            if arr.is_empty() {
                obj.remove(head);
            }
        }
        return;
    }
    remove_marked(child, rest, marker_key, marker_value);
    if let Some(child_obj) = obj.get(head).and_then(|c| c.as_object()) {
        if child_obj.is_empty() {
            obj.remove(head);
        }
    }
}

fn load_target(path: &std::path::Path) -> anyhow::Result<serde_json::Value> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let contents = std::fs::read_to_string(path)?;
    if contents.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let value: serde_json::Value = serde_json::from_str(&contents)?;
    anyhow::ensure!(
        value.is_object(),
        "{} does not contain a JSON object at its root -- refusing to touch it",
        path.display()
    );
    Ok(value)
}

/// ADR-0023 D6.5-D6.7: writes `document` to `path` only if `path`'s final
/// component is not a symlink (checked immediately before writing, not
/// only at parse/register time -- a path that became a symlink after
/// registration is still caught here), and only if `path`'s parent already
/// exists (no `create_dir_all` -- unlike the built-in adapters' hardcoded
/// paths, `path` here is manifest-chosen, so granting it directory-creation
/// would hand a manifest a primitive it should not have). The temp file for
/// the atomic write lives in `path`'s own parent with `path`'s filename
/// plus a `.fornax-tmp` suffix, created with `create_new` so an
/// existing/planted temp path is an error, not a silent overwrite.
fn save_target_contained(
    path: &std::path::Path,
    document: &serde_json::Value,
) -> anyhow::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{} has no parent directory -- refusing to write it",
            path.display()
        )
    })?;
    anyhow::ensure!(
        parent.is_dir(),
        "{} does not exist -- external adapters never create directories",
        parent.display()
    );
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(
            !meta.file_type().is_symlink(),
            "{} is a symlink -- refusing to write through it",
            path.display()
        );
    }

    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "{} has no file name -- refusing to write it",
            path.display()
        )
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".fornax-tmp");
    let tmp_path = parent.join(&tmp_name);

    let mut json = serde_json::to_string_pretty(document)?;
    json.push('\n');
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| {
                anyhow::anyhow!("failed to create temp file {}: {e}", tmp_path.display())
            })?;
        f.write_all(json.as_bytes())?;
    }
    let rename_result = std::fs::rename(&tmp_path, path);
    if rename_result.is_err() {
        std::fs::remove_file(&tmp_path).ok();
    }
    rename_result?;
    Ok(())
}

/// `fornax install <external-id>` -- wires this adapter's declared
/// operations into its target file. Idempotent: re-running when already
/// installed is a no-op (no write).
pub fn install_at(manifest: &AdapterManifest) -> anyhow::Result<AdapterActionResult> {
    let before = load_target(&manifest.target_path)?;
    let after = apply_document(&before, &manifest.operations)?;
    let changed = after != before;
    if changed {
        save_target_contained(&manifest.target_path, &after)?;
    }
    let message = if changed {
        format!(
            "Installed {} into {}",
            manifest.display_name,
            manifest.target_path.display()
        )
    } else {
        format!(
            "{} already installed in {}",
            manifest.display_name,
            manifest.target_path.display()
        )
    };
    Ok(AdapterActionResult {
        adapter: manifest.id.clone(),
        action: "install".to_string(),
        changed,
        message,
        path: manifest.target_path.display().to_string(),
    })
}

/// `fornax uninstall <external-id>` -- removes exactly what `install`
/// added, leaving every other entry in the target file untouched. A
/// missing target file is "nothing to remove", not an error.
pub fn uninstall_at(manifest: &AdapterManifest) -> anyhow::Result<AdapterActionResult> {
    if !manifest.target_path.exists() {
        return Ok(AdapterActionResult {
            adapter: manifest.id.clone(),
            action: "uninstall".to_string(),
            changed: false,
            message: format!(
                "No {} entries to remove ({} does not exist)",
                manifest.display_name,
                manifest.target_path.display()
            ),
            path: manifest.target_path.display().to_string(),
        });
    }
    let before = load_target(&manifest.target_path)?;
    let after = revert_document(&before, &manifest.operations);
    let changed = after != before;
    if changed {
        save_target_contained(&manifest.target_path, &after)?;
    }
    let message = if changed {
        format!(
            "Removed {} entries from {}",
            manifest.display_name,
            manifest.target_path.display()
        )
    } else {
        format!(
            "No {} entries found in {}",
            manifest.display_name,
            manifest.target_path.display()
        )
    };
    Ok(AdapterActionResult {
        adapter: manifest.id.clone(),
        action: "uninstall".to_string(),
        changed,
        message,
        path: manifest.target_path.display().to_string(),
    })
}

/// `fornax adapter plan <external-id>` / `fornax adapter doctor
/// <external-id>` -- computes, without writing anything, what `install`
/// would do right now. Read-only: reads the target file if it exists,
/// never writes.
pub fn plan_apply(manifest: &AdapterManifest) -> anyhow::Result<AdapterActionResult> {
    let before = load_target(&manifest.target_path)?;
    let after = apply_document(&before, &manifest.operations)?;
    let changed = after != before;
    let message = if changed {
        format!(
            "Would install {} into {}",
            manifest.display_name,
            manifest.target_path.display()
        )
    } else {
        format!(
            "{} already installed in {}",
            manifest.display_name,
            manifest.target_path.display()
        )
    };
    Ok(AdapterActionResult {
        adapter: manifest.id.clone(),
        action: "plan".to_string(),
        changed,
        message,
        path: manifest.target_path.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(pointer: &str, marker_value: &str) -> Operation {
        Operation::EnsureMarkedArrayElement {
            pointer: pointer.to_string(),
            marker_key: "command".to_string(),
            marker_value: marker_value.to_string(),
            element: serde_json::json!({"type": "command", "command": marker_value}),
        }
    }

    #[test]
    fn apply_creates_missing_intermediate_objects_and_array() {
        let doc = serde_json::json!({});
        let out = apply_document(&doc, &[op("/hooks/PostToolUse", "fornax-hook-acme")]).unwrap();
        assert_eq!(
            out,
            serde_json::json!({"hooks": {"PostToolUse": [
                {"type": "command", "command": "fornax-hook-acme"}
            ]}})
        );
    }

    #[test]
    fn apply_is_idempotent_no_duplicate_element() {
        let doc = serde_json::json!({});
        let once = apply_document(&doc, &[op("/hooks/PostToolUse", "fornax-hook-acme")]).unwrap();
        let twice = apply_document(&once, &[op("/hooks/PostToolUse", "fornax-hook-acme")]).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn apply_leaves_a_foreign_entry_in_the_same_array_untouched() {
        let doc = serde_json::json!({"hooks": {"PostToolUse": [
            {"type": "command", "command": "some-other-tool"}
        ]}});
        let out = apply_document(&doc, &[op("/hooks/PostToolUse", "fornax-hook-acme")]).unwrap();
        let arr = out["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn apply_refuses_non_object_intermediate_rather_than_overwriting() {
        let doc = serde_json::json!({"hooks": "not-an-object"});
        let err = apply_document(&doc, &[op("/hooks/PostToolUse", "x")]).unwrap_err();
        assert!(err.to_string().contains("not an object"));
    }

    #[test]
    fn apply_refuses_non_array_terminal_rather_than_overwriting() {
        let doc = serde_json::json!({"hooks": {"PostToolUse": "not-an-array"}});
        let err = apply_document(&doc, &[op("/hooks/PostToolUse", "x")]).unwrap_err();
        assert!(err.to_string().contains("not an array"));
    }

    #[test]
    fn revert_removes_only_marker_bearing_elements_and_prunes_only_emptied_containers() {
        let doc = serde_json::json!({"hooks": {"PostToolUse": [
            {"type": "command", "command": "fornax-hook-acme"},
            {"type": "command", "command": "some-other-tool"}
        ], "Stop": [
            {"type": "command", "command": "fornax-hook-acme"}
        ]}});
        let out = revert_document(
            &doc,
            &[
                op("/hooks/PostToolUse", "fornax-hook-acme"),
                op("/hooks/Stop", "fornax-hook-acme"),
            ],
        );
        assert_eq!(
            out,
            serde_json::json!({"hooks": {"PostToolUse": [
                {"type": "command", "command": "some-other-tool"}
            ]}})
        );
    }

    #[test]
    fn rfc6901_escape_sequences_are_unescaped_exactly_once() {
        // "/a~1b" addresses key "a/b", not "a", then "b".
        let doc = serde_json::json!({});
        let out = apply_document(&doc, &[op("/a~1b", "x")]).unwrap();
        assert!(out.get("a/b").is_some());
        assert!(out.get("a").is_none());
    }

    #[test]
    fn plan_apply_computes_diff_without_writing() {
        let tmp = std::env::temp_dir().join(format!("fornax-mutate-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let target = tmp.join("settings.json");

        let manifest = AdapterManifest {
            id: "acme-agent".to_string(),
            display_name: "Acme Agent".to_string(),
            summary: "s".to_string(),
            min_fornax_version: (0, 0, 1),
            provenance: "p".to_string(),
            capabilities: vec![],
            target_format: crate::adapter_manifest::TargetFormat::Json,
            target_path: target.clone(),
            operations: vec![op("/hooks/PostToolUse", "fornax-hook-acme")],
        };

        let result = plan_apply(&manifest).unwrap();
        assert!(result.changed);
        assert!(!target.exists(), "plan must never write the target file");
    }
}
