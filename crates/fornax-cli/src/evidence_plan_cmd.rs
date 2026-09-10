//! `fornax evidence-plan` (FORNX-345): renders `GET /api/evidence-plan` --
//! the same recommendation + full fusion detail `fornax decision` renders,
//! followed by the ranked evidence-acquisition plan `fornax_verify::voi`
//! computed for the same claim. See `docs/adr/0015-voi-evidence-planner.md`
//! for what this planner does and does not verify (FORNX-346 boundary).

/// `EvidenceGapKind`/`CandidateAvailability` are serialized without a
/// top-level string tag for unit variants but as `{"variant_name": {..}}`
/// for struct variants (`EvidenceGapKind`) or `{"kind": "variant_name",
/// ...}` for internally-tagged ones (`CandidateAvailability`). This reads
/// either shape without needing the exact wire representation duplicated
/// here: a bare string is the tag itself; an object's `kind` field (if
/// present) or its first key (otherwise) is the tag, and the object itself
/// carries any variant fields.
fn variant_tag_and_fields(v: &serde_json::Value) -> (String, serde_json::Value) {
    match v {
        serde_json::Value::String(s) => (s.clone(), serde_json::Value::Null),
        serde_json::Value::Object(map) => {
            if let Some(kind) = map.get("kind").and_then(|k| k.as_str()) {
                return (kind.to_string(), v.clone());
            }
            if let Some((key, fields)) = map.iter().next() {
                return (key.clone(), fields.clone());
            }
            ("?".to_string(), serde_json::Value::Null)
        }
        _ => ("?".to_string(), serde_json::Value::Null),
    }
}

fn render_gap(g: &serde_json::Value) -> String {
    let (kind, fields) = variant_tag_and_fields(&g.get("kind").cloned().unwrap_or_default());
    let detail = g.get("detail").and_then(|s| s.as_str()).unwrap_or("");
    let signal_class = fields
        .get("signal_class")
        .and_then(|s| s.as_str())
        .map(|s| format!(" [{s}]"))
        .unwrap_or_default();
    let mut out = format!("    - {kind}{signal_class}: {detail}\n");
    let ids_line = |key: &str| -> Option<String> {
        let ids: Vec<&str> = g
            .get(key)
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str())
            .collect();
        if ids.is_empty() {
            None
        } else {
            Some(format!("        {key}: {}\n", ids.join(", ")))
        }
    };
    for key in ["link_ids", "missing_evidence_ids"] {
        if let Some(line) = ids_line(key) {
            out.push_str(&line);
        }
    }
    out
}

fn render_candidate(c: &serde_json::Value) -> String {
    let request = c.get("request").cloned().unwrap_or_default();
    let utility = c.get("utility").cloned().unwrap_or_default();
    let (availability_kind, availability_fields) =
        variant_tag_and_fields(&c.get("availability").cloned().unwrap_or_default());

    let rank = c
        .get("rank")
        .and_then(|r| r.as_u64())
        .map(|r| format!("#{r} "))
        .unwrap_or_default();
    let probe_kind = request.get("kind").and_then(|s| s.as_str()).unwrap_or("?");
    let target_signal_class = request
        .get("target_signal_class")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    let description = request
        .get("description")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let why_it_matters = c
        .get("why_it_matters")
        .and_then(|s| s.as_str())
        .unwrap_or("");

    let mut out = format!(
        "  {rank}{probe_kind} -> {target_signal_class}\n    {description}\n    why: {why_it_matters}\n"
    );

    let dim = |field: &str| -> String {
        utility
            .get(field)
            .and_then(|s| s.as_str())
            .unwrap_or("?")
            .to_string()
    };
    out.push_str(&format!(
        "    discrimination: {}  independence: {}  recency: {}\n",
        dim("discrimination"),
        dim("independence"),
        dim("recency")
    ));
    out.push_str(&format!(
        "    cost: {}  latency: {}  privacy: {}  action_risk: {}\n",
        dim("cost"),
        dim("latency"),
        dim("privacy"),
        dim("action_risk")
    ));

    match availability_kind.as_str() {
        "available" => out.push_str("    availability: ✓ available\n"),
        "requires_approval" => {
            let missing_grant = availability_fields
                .get("missing_grant")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            out.push_str(&format!(
                "    availability: ! requires approval -- grant: {missing_grant}\n"
            ));
        }
        "unavailable" => {
            let reason = availability_fields
                .get("reason")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            out.push_str(&format!("    availability: ✕ unavailable -- {reason}\n"));
        }
        "forbidden" => {
            let reason = availability_fields
                .get("reason")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            out.push_str(&format!("    availability: ⛔ forbidden -- {reason}\n"));
        }
        other => out.push_str(&format!("    availability: ? {other}\n")),
    }
    out
}

/// Renders `GET /api/evidence-plan`'s response: the recommendation and full
/// fusion detail (reusing `render_decision`'s own layout so the two
/// commands read identically up to that point), followed by the plan's
/// gaps and ranked/unavailable acquisition candidates.
///
/// `PlanOutcome::NoUsefulEvidenceAvailable` gets a loud, impossible-to-miss
/// banner rather than being folded quietly into an empty candidate list --
/// "nothing available" is a materially different message from "nothing
/// found".
pub(crate) fn render_evidence_plan(v: &serde_json::Value) -> String {
    let mut out = crate::render_decision(v);

    let found = v.get("found").and_then(|b| b.as_bool()).unwrap_or(false);
    let has_error = v.get("error").is_some();
    if !found || has_error {
        return out;
    }

    let Some(plan) = v.get("plan") else {
        return out;
    };

    let outcome = plan.get("outcome").and_then(|s| s.as_str()).unwrap_or("?");
    let policy_name = plan
        .get("policy_name")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    let policy_version = plan
        .get("policy_version")
        .and_then(|n| n.as_u64())
        .unwrap_or(0);

    out.push_str(&format!(
        "\nevidence plan ({policy_name} v{policy_version}):\n"
    ));

    if outcome == "no_useful_evidence_available" {
        out.push_str("  ⚠⚠⚠ NO USEFUL EVIDENCE AVAILABLE ⚠⚠⚠\n");
        out.push_str(
            "  every candidate that would close a gap is unavailable, forbidden, or requires \
             approval not currently granted -- see below.\n",
        );
    }

    let empty = vec![];
    let gaps = plan
        .get("gaps")
        .and_then(|g| g.as_array())
        .unwrap_or(&empty);
    if gaps.is_empty() {
        out.push_str("  gaps: (none)\n");
    } else {
        out.push_str(&format!("  gaps ({}):\n", gaps.len()));
        for gap in gaps {
            out.push_str(&render_gap(gap));
        }
    }

    let candidates = plan
        .get("candidates")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    if candidates.is_empty() {
        out.push_str("  ranked candidates: (none)\n");
    } else {
        out.push_str(&format!("  ranked candidates ({}):\n", candidates.len()));
        for c in candidates {
            out.push_str(&render_candidate(c));
        }
    }

    let unavailable = plan
        .get("unavailable")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    if !unavailable.is_empty() {
        out.push_str(&format!(
            "  unavailable/forbidden candidates ({}) -- never silently dropped:\n",
            unavailable.len()
        ));
        for c in unavailable {
            out.push_str(&render_candidate(c));
        }
    }

    out
}

/// Icon for an `AcquisitionOutcome` variant name, mirroring
/// `verdict_icon`/`recommendation_icon`'s never-collapse-the-vocabulary
/// discipline.
fn acquisition_outcome_icon(outcome: &str) -> &'static str {
    match outcome {
        "acquired" => "✓",
        "refused" => "!",
        "unavailable" => "?",
        "failed" => "✕",
        "unsupported" => "-",
        _ => "?",
    }
}

/// Renders `POST /api/acquire-evidence`'s response: `fused_before` (via
/// `render_fusion`, wrapped into the envelope shape it expects), the
/// acquisition outcome, and `fused_after` when the probe actually acquired
/// something -- never one without the other when both are present.
pub(crate) fn render_acquire_evidence(v: &serde_json::Value) -> String {
    let claim = v.get("claim").and_then(|s| s.as_str()).unwrap_or("?");
    let session = v.get("session").and_then(|s| s.as_str()).unwrap_or("?");
    let mut out = String::new();

    if let Some(error) = v.get("error").and_then(|s| s.as_str()) {
        out.push_str(&format!(
            "claim: {claim}\nsession: {session}\n  error: {error}\n"
        ));
        return out;
    }
    let found = v.get("found").and_then(|b| b.as_bool()).unwrap_or(false);
    if !found {
        let reason = v
            .get("reason")
            .and_then(|s| s.as_str())
            .unwrap_or("no claim with this id is on record for this session");
        out.push_str(&format!(
            "claim: {claim}\nsession: {session}\n  no such claim on record ({reason})\n"
        ));
        return out;
    }

    if let Some(fused_before) = v.get("fused_before") {
        out.push_str("before:\n");
        out.push_str(&crate::render_fusion(&serde_json::json!({
            "claim": claim,
            "session": session,
            "found": true,
            "graph_source": "acquire-evidence",
            "fused": fused_before,
        })));
    }

    let outcome = v.get("outcome").and_then(|s| s.as_str()).unwrap_or("?");
    let detail_reason = v
        .get("detail")
        .and_then(|d| d.get("reason"))
        .and_then(|s| s.as_str());
    out.push_str(&format!(
        "\nacquisition: {} {}\n",
        acquisition_outcome_icon(outcome),
        outcome.to_uppercase()
    ));
    if let Some(reason) = detail_reason {
        out.push_str(&format!("  {reason}\n"));
    }

    if let Some(fused_after) = v.get("fused_after").filter(|f| !f.is_null()) {
        out.push_str("\nafter:\n");
        out.push_str(&crate::render_fusion(&serde_json::json!({
            "claim": claim,
            "session": session,
            "found": true,
            "graph_source": "acquire-evidence",
            "fused": fused_after,
        })));
    }

    out
}
