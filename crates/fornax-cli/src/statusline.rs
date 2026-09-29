//! `fornax statusline` (HORO-1567): Fornax's structured, read-only provider
//! for the shared Horonom statusline host.
//!
//! FORNX-30 shipped `scripts/fornax-statusline.sh`, which wraps the user's
//! own statusline and appends one Fornax segment. That proved the UX and the
//! failure containment, but it can only ever be the *only* wrapper: Claude
//! Code has exactly one `statusLine.command`, so a second product appending
//! its own segment the same way would have to displace it. The shared host
//! (HORO-1565) owns that single slot instead, and each product contributes a
//! structured answer. This module is Fornax's answer.
//!
//! Three properties are deliberate and worth stating before the code:
//!
//! **No glyph is chosen here.** Iconography belongs to the host, so that two
//! products reporting "needs your attention" cannot pick incompatible emoji.
//! This module emits a semantic state name and the host draws it. That also
//! means the bare-shield presentation defect in the FORNX-30 wrapper simply
//! cannot be reproduced here.
//!
//! **Nothing in the reading is free text from the product.** Every label and
//! reason this module emits is one of a fixed set of literals in this file.
//! `Finding::rationale`, `FindingRow::claim_text` and the `detail` field on
//! `MissingEvidence` are all unbounded prose which the verifiers interpolate
//! user content into — claimed command strings, claimed file paths, claimed
//! branch names. None of them is ever rendered.
//!
//! **Nothing here mutates anything.** Fornax does not gain a second Claude
//! Code settings patcher; enabling and disabling this provider is the shared
//! lifecycle tool's job (HORO-1566). This module reads one HTTP endpoint.

use chrono::{DateTime, SubsecRound, Utc};
use serde_json::{json, Value};

/// Version of the cross-product provider contract (HORO-1564) this module
/// speaks. A host that does not recognise it refuses the whole payload
/// rather than guessing at a meaning, which is why it is stated explicitly
/// on every answer including the failures.
pub const CONTRACT_VERSION: u32 = 1;

/// Provider id, as registered with the host.
pub const PROVIDER_ID: &str = "fornax";

/// Breadth of the state being reported.
///
/// `host`, not `session`, and this is a correctness claim rather than a
/// convenience. The hot path reads `GET /api/status`, which is
/// `Store::recent_findings(1)`: a single `ORDER BY computed_at DESC LIMIT 1`
/// over the findings table with **no session predicate**. The latest finding
/// on this machine may therefore belong to a different session than the one
/// the statusline is being rendered for. Declaring `session` would make the
/// host label it as this session's state, which would be false.
pub const SCOPE: &str = "host";

/// Where Fornax sits relative to other products on the shared line. Lower
/// sorts earlier; the range is deliberately sparse so products can be
/// reordered without renegotiating.
pub const ORDER_HINT: u32 = 300;

/// Why the provider has no live reading to report.
///
/// These are five distinct facts and the contract refuses to collapse them:
/// a stopped daemon is not a daemon reporting nothing, and a probe that
/// failed is not silence. Each maps to its own availability and its own
/// bounded reason code, so a `doctor` surface can tell the user what to
/// actually do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoReading {
    /// Nothing answered on the daemon port.
    DaemonUnreachable,
    /// Something answered, but it is serving a different `$FORNAX_HOME`
    /// (FORNX-339). Fornax fails closed here rather than showing another
    /// home's evidence, so the honest reading is that we did not find out.
    DaemonIdentityMismatch,
    /// Something answered without identifying its `$FORNAX_HOME` at all.
    /// Also a fail-closed refusal, and a different one: the peer may not be
    /// a Fornax daemon.
    DaemonIdentityNotReported,
    /// The daemon answered, and its answer was a store error.
    StoreReadFailed,
    /// The daemon answered with something this client cannot parse as a
    /// status response.
    ResponseNotUnderstood,
}

impl NoReading {
    /// The contract availability for this outcome.
    ///
    /// The two identity refusals are `unknown` rather than `unavailable` on
    /// purpose. `unavailable` asserts that the thing is not there; what
    /// actually happened is that Fornax declined to trust the peer, which
    /// leaves the real state unobserved. "We did not find out" is the
    /// truthful reading, and the contract is explicit that it is not
    /// interchangeable with healthy *or* with absent.
    fn availability(self) -> &'static str {
        match self {
            NoReading::DaemonUnreachable => "unavailable",
            NoReading::DaemonIdentityMismatch | NoReading::DaemonIdentityNotReported => "unknown",
            NoReading::StoreReadFailed | NoReading::ResponseNotUnderstood => "error",
        }
    }

    /// Machine-readable reason, for a `doctor` surface and for tests.
    fn reason_code(self) -> &'static str {
        match self {
            NoReading::DaemonUnreachable => "daemon_unreachable",
            NoReading::DaemonIdentityMismatch => "daemon_identity_mismatch",
            NoReading::DaemonIdentityNotReported => "daemon_identity_not_reported",
            NoReading::StoreReadFailed => "store_read_failed",
            NoReading::ResponseNotUnderstood => "response_not_understood",
        }
    }

    /// Short human label. Fixed prose, never an error message: an error
    /// string from this codebase routinely carries a `$FORNAX_HOME` path, a
    /// port, or a home-identity digest, and this value is rendered straight
    /// into the user's terminal.
    ///
    /// Deliberately the *state* rather than the cause, with the cause left to
    /// [`NoReading::reason_code`] and no `reason_label` at all. The host
    /// renders a reason clause beside the label, so a label that already
    /// names the cause is paid for twice in columns it then has to degrade
    /// away. Letting the host prettify the code is also the shared
    /// presentation the contract intends: the same fallback every product
    /// gets, rather than Fornax's own phrasing of it.
    fn label(self) -> &'static str {
        match self {
            NoReading::DaemonUnreachable => "Not running",
            NoReading::DaemonIdentityMismatch | NoReading::DaemonIdentityNotReported => {
                "State not observed"
            }
            NoReading::StoreReadFailed => "Findings unreadable",
            NoReading::ResponseNotUnderstood => "Answer unreadable",
        }
    }
}

/// The segment state that goes with a non-live availability.
///
/// Mirrors the host contract's own mapping so the two cannot drift: `error`
/// becomes `warn` because a failed probe may need the user to act, while
/// `unavailable` and `unknown` state a fact without claiming health. None of
/// them may be `ok`, and the host enforces that independently.
fn state_for(availability: &str) -> &'static str {
    match availability {
        "unavailable" => "neutral",
        "error" => "warn",
        _ => "unknown",
    }
}

/// Build the provider payload for an outcome with no live reading.
///
/// Note what is *not* here: no `segments` claiming `ok`, no count, no
/// confidence, and no empty segment list. An empty answer renders as silence
/// and silence reads as "all clear", which is the failure mode this shape
/// exists to prevent.
pub fn no_reading(kind: NoReading) -> Value {
    let availability = kind.availability();
    json!({
        "contract_version": CONTRACT_VERSION,
        "provider": PROVIDER_ID,
        "provider_version": env!("CARGO_PKG_VERSION"),
        "scope": SCOPE,
        "availability": availability,
        "order_hint": ORDER_HINT,
        "segments": [{
            "key": "availability",
            "state": state_for(availability),
            "label": kind.label(),
            "reason_code": kind.reason_code(),
            "explain_key": "fornax.availability",
        }],
    })
}

/// How one `Verdict` is presented on the shared line.
///
/// A semantic state name, never a glyph, and a spelled-out label, never an
/// abbreviation: the host draws the icon, and `UNVERIFIED` shortened to
/// something like `unv` is exactly the opaque token this design replaces.
struct VerdictRendering {
    state: &'static str,
    label: &'static str,
    /// Bounded reason clause, where this verdict has one worth stating.
    reason_code: Option<&'static str>,
}

/// Map a `fornax_types::Verdict` wire name onto the shared semantic states.
///
/// The five-way taxonomy survives the mapping intact, because that is the
/// whole point of it: `Unverified` is not a failure and it is emphatically
/// not a pass, `Unavailable` means Fornax could not obtain evidence rather
/// than that it found the claim wanting, and `Review` is a request for a
/// human rather than a defect. Collapsing any of them onto `ok` would be the
/// specific lie this ticket exists to prevent.
///
/// An unrecognised verdict is *not* passed through as a label. The verdict
/// set is closed in `fornax-types`, so a name this client has never seen
/// means the daemon is newer than the CLI, which is a fact about versions
/// worth saying plainly — and rendering an unknown string would put
/// unbounded product output on the user's line.
///
/// # Why `unverified` carries `reason_not_recorded`
///
/// HORO-1567 asks for a bounded, privacy-safe reason category beside an
/// UNVERIFIED verdict, *where the authoritative model can supply one*. It
/// cannot, and that was established by elimination against this codebase
/// rather than assumed:
///
/// - `Finding::rationale` is free prose into which the verifiers interpolate
///   claimed command strings, claimed file paths and claimed branch names. It
///   is the one field that would answer the question and the one field that
///   may never be rendered.
/// - An empty `Finding::evidence_ids` does not mean "no evidence was found".
///   `file_modified_verifier_v1` returns exactly that list for the case where
///   a file diff *was* observed and its diff was empty, so emptiness cannot
///   be read as an evidence gap.
/// - The FORNX-89 evidence graph would carry `MissingEvidence` with a typed
///   `SignalAvailability`, but nothing populates it in production: every
///   insert site in `fornax-store` and `fornax-daemon` is inside a test
///   module, and its only production producer, `fusion::project_graph`,
///   matches `Verdict::Unverified` with an empty arm. Its missing-evidence
///   rows exist solely for `Verdict::Unavailable`.
/// - `fusion`'s `UncertaintyBand` and `FusionRule` *are* a closed,
///   privacy-safe vocabulary, but `compute_fusion` loads a whole session's
///   claims, findings and evidence pool, which is not a hot-path operation;
///   and over an unverified finding the projected graph is empty, so the only
///   band it can report is `Undetermined`. That is not a reason either. It
///   belongs to the explain surface, where the cost is affordable.
///
/// So the honest answer is an explicit code saying the reason is not
/// recorded. It is emitted rather than omitted, because the host draws that
/// distinction deliberately: with no reason field at all the rendered line
/// carries no reason clause, which reads as "there was nothing to say",
/// whereas an explicit code renders as "the reason is not recorded". Those
/// are different claims and only this provider can tell them apart.
///
/// No `reason_label` accompanies it. The host's own prettifier turns the code
/// into the same words, so supplying them here would only create a second
/// place for the phrasing to drift.
fn verdict_rendering(verdict: &str) -> VerdictRendering {
    match verdict {
        "verified" => VerdictRendering {
            state: "ok",
            label: "Verified",
            reason_code: None,
        },
        "unverified" => VerdictRendering {
            state: "attention",
            label: "Unverified",
            reason_code: Some("reason_not_recorded"),
        },
        "contradicted" => VerdictRendering {
            state: "critical",
            label: "Contradicted",
            reason_code: None,
        },
        "review" => VerdictRendering {
            state: "warn",
            label: "Needs review",
            reason_code: None,
        },
        "unavailable" => VerdictRendering {
            state: "unknown",
            label: "Evidence unavailable",
            reason_code: None,
        },
        _ => VerdictRendering {
            state: "unknown",
            label: "Verdict this client does not know",
            reason_code: Some("client_older_than_daemon"),
        },
    }
}

/// Longest age the contract accepts, in seconds. Mirrored here so a wildly
/// out-of-range timestamp degrades to a clamped age rather than making the
/// host reject the whole payload — a rejected provider renders as an unknown
/// with no reading at all, which is a worse answer than "very old".
const MAX_AGE_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;

/// Turn a finding's `computed_at` into the contract's `observed_at` and an age.
///
/// This is the freshness cue HORO-1567 asks for, and it is derived
/// *structurally* from a timestamp the store already holds — not inferred from
/// how many events were collected, which the ticket rules out and which would
/// be the wrong inference anyway.
///
/// Two conversions are needed. The verifiers write `computed_at` as
/// `chrono::Utc::now().to_rfc3339()`, an offset form (`+00:00`) carrying
/// nanoseconds; the contract requires an explicit `Z` and at most
/// microseconds, and refuses a local offset outright because an age computed
/// from one is ambiguous across machines. Truncating to whole seconds
/// satisfies both and costs nothing a statusline could have displayed.
///
/// A timestamp in the future clamps to zero rather than reporting a negative
/// age. That is not hypothetical: a value under an agent's influence has
/// already produced a nonsense age in the founder's own wrapper, and an age
/// that renders as a huge number is the one reading a user would trust least
/// and understand least.
fn freshness(computed_at: &str, now: DateTime<Utc>) -> Option<(String, i64)> {
    let observed = DateTime::parse_from_rfc3339(computed_at)
        .ok()?
        .with_timezone(&Utc)
        // Truncate before measuring, not after. The two fields then agree by
        // construction, and the rounding error lands on the safe side: a
        // truncated instant is earlier, so the age can only come out larger.
        .trunc_subsecs(0);
    let age = (now - observed).num_seconds().clamp(0, MAX_AGE_SECONDS);
    Some((observed.format("%Y-%m-%dT%H:%M:%SZ").to_string(), age))
}

/// Build the provider payload from a successful `/api/status` body.
///
/// Both shapes the endpoint can return are real answers, and they are
/// different answers. `latest: null` means the daemon is running and has
/// verified nothing yet — which is `neutral`, never `ok`. "Nothing has been
/// checked" is not "everything checks out", and no count is reported either,
/// because a zero here would read as a clean bill of health.
pub fn reading(body: &Value, now: DateTime<Utc>) -> Value {
    let mut observed_at = None;
    let segment = match body.get("latest").filter(|l| !l.is_null()) {
        None => json!({
            "key": "latest_finding",
            "state": "neutral",
            "label": "No findings yet",
            "explain_key": "fornax.latest_finding",
        }),
        Some(latest) => {
            let verdict = latest
                .get("verdict")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let rendering = verdict_rendering(verdict);
            let mut segment = json!({
                "key": "latest_finding",
                "state": rendering.state,
                "label": rendering.label,
                "explain_key": "fornax.latest_finding",
            });
            if let Some(code) = rendering.reason_code {
                segment["reason_code"] = json!(code);
            }
            // A finding whose timestamp will not parse simply has no
            // freshness cue. The alternative — substituting "now" — would
            // present an unreadable timestamp as a fresh reading, which is
            // the one direction that misleads.
            if let Some((stamp, age)) = latest
                .get("computed_at")
                .and_then(|v| v.as_str())
                .and_then(|raw| freshness(raw, now))
            {
                segment["age_seconds"] = json!(age);
                observed_at = Some(stamp);
            }
            segment
        }
    };
    let mut payload = json!({
        "contract_version": CONTRACT_VERSION,
        "provider": PROVIDER_ID,
        "provider_version": env!("CARGO_PKG_VERSION"),
        "scope": SCOPE,
        "availability": "available",
        "order_hint": ORDER_HINT,
        "segments": [segment],
    });
    if let Some(stamp) = observed_at {
        payload["observed_at"] = json!(stamp);
    }
    payload
}

/// What kind of evidence a verifier sought, from its name.
///
/// The verifier set is closed — five names in `fornax-verify` — and a name
/// carries no user content, which is what makes it safe to render. An
/// unrecognised name yields `None` rather than being printed: a name this
/// client does not know is unbounded output as far as it can prove.
///
/// This is deliberately *not* on the statusline. Two facts about one finding
/// already cost the shared line a verdict, a reason clause and an age; a
/// third would push Fornax past its share of a line it shares with the user's
/// own statusline and every other product. HORO-1567's own answer to that is
/// progressive disclosure, so it lives here, where there is room.
fn evidence_sought(verifier_name: &str) -> Option<&'static str> {
    match verifier_name {
        "test_result_verifier_v1" => Some("test results"),
        "command_executed_verifier_v1" => Some("command execution"),
        "command_success_verifier_v1" => Some("command exit status"),
        "file_modified_verifier_v1" => Some("file changes"),
        "git_operation_verifier_v1" => Some("git operations"),
        _ => None,
    }
}

/// Human-readable explanation of the latest finding, for the read-only
/// `explain` surface.
///
/// Given more room than a statusline, this says everything bounded that the
/// authoritative model holds — and says plainly what it does *not* hold,
/// which is the question a user reaches this surface with. What it never
/// prints is the free-text half: `rationale`, `claim_text`, and the `detail`
/// on a `MissingEvidence` row all carry claimed commands, file paths and
/// branch names interpolated by the verifiers.
///
/// Claim and session ids are also left out. They are opaque identifiers that
/// answer no question a reader of this surface is asking, and printing an
/// identifier by default is how identifiers end up pasted into tickets.
pub fn explain_text(status: &Value, fused: Option<&Value>, now: DateTime<Utc>) -> String {
    let mut out = String::from("Fornax — latest finding on this machine (host-wide)\n\n");
    let Some(latest) = status.get("latest").filter(|l| !l.is_null()) else {
        out.push_str("  No findings recorded yet. The daemon is running and has\n");
        out.push_str("  verified nothing so far, which is not the same as a pass.\n");
        return out;
    };
    let verdict = latest
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let rendering = verdict_rendering(verdict);
    out.push_str(&format!("  verdict        {}\n", rendering.label));
    match latest
        .get("computed_at")
        .and_then(|v| v.as_str())
        .and_then(|raw| freshness(raw, now))
    {
        Some((stamp, age)) => out.push_str(&format!("  observed       {stamp} ({age}s ago)\n")),
        None => out.push_str("  observed       timestamp unreadable\n"),
    }
    match latest
        .get("verifier_name")
        .and_then(|v| v.as_str())
        .and_then(evidence_sought)
    {
        Some(kind) => out.push_str(&format!("  evidence for   {kind}\n")),
        None => out.push_str("  evidence for   verifier this client does not know\n"),
    }
    if verdict == "unverified" {
        out.push_str("  reason         not recorded\n\n");
        out.push_str("  Fornax does not record a reason category for an unverified\n");
        out.push_str("  finding. The finding does carry a free-text rationale, which\n");
        out.push_str("  this surface deliberately does not show: the verifiers write\n");
        out.push_str("  claimed commands, file paths and branch names into it.\n");
        out.push_str("  `fornax detail` will show it, at that cost.\n");
    }
    out.push_str(&explain_fused(fused));
    out
}

/// The fused view, appended to [`explain_text`].
///
/// This is where fusion's vocabulary is affordable: `UncertaintyBand` and
/// `FusionRule` are closed, stable, snake_case names carrying no user
/// content, and the whole-session load that produces them is fine off the hot
/// path. `RationaleEntry::detail` is free text and is not printed.
fn explain_fused(fused: Option<&Value>) -> String {
    let mut out = String::from("\n  Fused view (read-only)\n");
    let Some(fused) = fused else {
        out.push_str("    unavailable — the fused view could not be computed\n");
        return out;
    };
    if fused.get("found").and_then(|f| f.as_bool()) != Some(true) {
        out.push_str("    no fused view for this claim yet\n");
        return out;
    }
    let uncertainty = fused
        .pointer("/fused/uncertainty")
        .and_then(|u| u.as_str())
        .unwrap_or("unreported");
    out.push_str(&format!("    uncertainty  {uncertainty}\n"));
    let rules: Vec<String> = fused
        .pointer("/fused/rationale")
        .and_then(|r| r.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let rule = e.get("rule").and_then(|r| r.as_str())?;
                    let effect = e.get("effect").and_then(|r| r.as_str())?;
                    Some(format!("{rule} ({effect})"))
                })
                .collect()
        })
        .unwrap_or_default();
    if rules.is_empty() {
        out.push_str("    rules        none recorded\n");
    } else {
        for rule in rules {
            out.push_str(&format!("    rule         {rule}\n"));
        }
    }
    out
}

/// Read the one endpoint the hot path is allowed to touch.
///
/// Exactly one local HTTP `GET`, no retry and no fallback to a heavier
/// endpoint: this runs on every statusline refresh, so a second request is a
/// second chance to be the reason the user's line is late. `/api/status` is
/// `recent_findings(1)`, measured at about 18 ms against a warm daemon.
///
/// The FORNX-339 identity check is applied here exactly as every other
/// client applies it — a peer that cannot prove which `$FORNAX_HOME` it
/// serves is refused — but the outcome is returned as a typed [`NoReading`]
/// rather than an error string, because the two refusal cases must render as
/// two different reason codes.
pub async fn probe() -> Result<Value, NoReading> {
    let url = format!("{}/api/status", crate::base_url());
    let response = reqwest::get(&url)
        .await
        .map_err(|_| NoReading::DaemonUnreachable)?;
    let expected = fornax_types::home_identity(&crate::fornax_home());
    match crate::read_daemon_identity(&response) {
        Some(actual) if actual == expected => {}
        Some(_) => return Err(NoReading::DaemonIdentityMismatch),
        None => return Err(NoReading::DaemonIdentityNotReported),
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|_| NoReading::ResponseNotUnderstood)?;
    if body.get("error").is_some() {
        return Err(NoReading::StoreReadFailed);
    }
    Ok(body)
}

/// Read the fused view for the latest finding, for the `explain` surface only.
///
/// `GET /api/fusion` runs the baseline fusion policy over a whole session's
/// claims, findings and evidence pool. That is far too expensive for a
/// statusline refresh and is why the provider payload does not carry any of
/// it; here, where the user has asked one question and is waiting for one
/// answer, the cost is affordable.
///
/// Every failure collapses to `None`. The explain surface renders that as an
/// explicit "unavailable" line rather than omitting the section, because a
/// missing section reads as "there was nothing to say".
pub async fn probe_fusion(latest: &Value) -> Option<Value> {
    let claim = latest.get("claim_id").and_then(|v| v.as_str())?;
    let session = latest.get("session_id").and_then(|v| v.as_str())?;
    let url = format!(
        "{}/api/fusion?claim={}&session={}",
        crate::base_url(),
        claim,
        session
    );
    let response = reqwest::get(&url).await.ok()?;
    let expected = fornax_types::home_identity(&crate::fornax_home());
    if crate::read_daemon_identity(&response) != Some(expected.as_str()) {
        return None;
    }
    response.json::<Value>().await.ok()
}

/// What the `explain` surface prints when there is no reading at all.
///
/// Says which of the five refusals happened and what the user can do about
/// it. The statusline gets a bounded reason code for the same fact; this
/// surface has room to say what the code means, which is the whole point of
/// there being two surfaces.
pub fn explain_unavailable(kind: NoReading) -> String {
    let detail = match kind {
        NoReading::DaemonUnreachable => {
            "No Fornax daemon answered on this machine. Start it, or set \
             FORNAX_HTTP_PORT if it listens somewhere else."
        }
        NoReading::DaemonIdentityMismatch => {
            "A daemon answered but serves a different FORNAX_HOME than this \
             client was configured with, so its findings are not this home's \
             findings. Fornax refuses to read them rather than report another \
             home's state as yours."
        }
        NoReading::DaemonIdentityNotReported => {
            "A daemon answered but did not identify which FORNAX_HOME it \
             serves, so this client cannot prove the findings are yours. That \
             is usually an older daemon still running; restart it."
        }
        NoReading::StoreReadFailed => {
            "The daemon is running but could not read its findings store."
        }
        NoReading::ResponseNotUnderstood => {
            "The daemon answered with something this client could not parse, \
             which usually means the two are different versions."
        }
    };
    format!(
        "Fornax — latest finding on this machine (host-wide)\n\n  {}\n  {}\n",
        kind.label(),
        detail
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed clock, so an age assertion is an assertion about arithmetic and
    /// not about how long the test took to run.
    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// The free-text fields, carrying the kind of interpolated user content
    /// the verifiers really write into them. Every privacy assertion in this
    /// module searches rendered output for these markers.
    const RATIONALE: &str =
        "no test-result evidence for claimed command \"pytest /Users/someone/private/repo\"";
    const CLAIM_TEXT: &str = "I ran the tests in /Users/someone/private/repo and they all passed";

    /// An `/api/status` body with one finding, shaped as `FindingRow`'s
    /// `Serialize` really produces it — every field present, including the
    /// two that may never be rendered. A fixture that omitted them could not
    /// prove they are not rendered.
    fn status_with(verdict: &str) -> Value {
        json!({"latest": {
            "id": "62d3a1f0-0000-4000-8000-000000000001",
            "claim_id": "62d3a1f0-0000-4000-8000-000000000002",
            "session_id": "62d3a1f0-0000-4000-8000-000000000003",
            "verdict": verdict,
            "evidence_ids": "[]",
            "verifier_name": "test_result_verifier_v1",
            "rationale": RATIONALE,
            "claim_text": CLAIM_TEXT,
            "computed_at": "2026-09-29T11:59:00.123456789+00:00",
        }})
    }

    fn segment(payload: &Value) -> Value {
        payload["segments"][0].clone()
    }

    #[test]
    fn verified_is_the_only_verdict_that_renders_as_ok() {
        let seg = segment(&reading(&status_with("verified"), now()));
        assert_eq!(seg["state"], "ok");
        assert_eq!(seg["label"], "Verified");
        // A pass needs no reason clause, and inventing one would put a
        // qualifier on the one verdict that does not want one.
        assert!(seg.get("reason_code").is_none());
    }

    #[test]
    fn the_other_four_verdicts_stay_distinct_and_none_of_them_is_ok() {
        // ADR-0001's five-state vocabulary, never collapsed: `Unverified` is
        // not a failure and emphatically not a pass, `Unavailable` means
        // Fornax could not obtain evidence rather than that it found the
        // claim wanting, and `Review` asks for a human rather than reporting
        // a defect.
        let cases = [
            ("unverified", "attention", "Unverified"),
            ("contradicted", "critical", "Contradicted"),
            ("review", "warn", "Needs review"),
            ("unavailable", "unknown", "Evidence unavailable"),
        ];
        let mut states = Vec::new();
        for (verdict, state, label) in cases {
            let seg = segment(&reading(&status_with(verdict), now()));
            assert_eq!(seg["state"], state, "state for {verdict}");
            assert_eq!(seg["label"], label, "label for {verdict}");
            assert_ne!(seg["state"], "ok", "{verdict} must never read as a pass");
            states.push(seg["state"].clone());
        }
        states.dedup();
        assert_eq!(states.len(), 4, "two verdicts collapsed onto one state");
    }

    #[test]
    fn unverified_states_its_missing_reason_explicitly() {
        // Omitting the field would render as *no reason clause*, which reads
        // as "there was nothing to say". An explicit code renders as "the
        // reason is not recorded". Only this provider can tell them apart.
        let seg = segment(&reading(&status_with("unverified"), now()));
        assert_eq!(seg["reason_code"], "reason_not_recorded");
        // No label: the host's prettifier produces the same words, and a
        // second copy would only drift.
        assert!(seg.get("reason_label").is_none());
    }

    #[test]
    fn a_verdict_this_client_does_not_know_is_reported_as_a_version_gap() {
        let seg = segment(&reading(&status_with("some_future_verdict"), now()));
        assert_eq!(seg["state"], "unknown");
        assert_eq!(seg["reason_code"], "client_older_than_daemon");
        // The raw name is not passed through as a label: the verdict set is
        // closed in `fornax-types`, so an unrecognised string is unbounded
        // product output as far as this client can prove.
        assert!(!seg["label"]
            .as_str()
            .unwrap()
            .contains("some_future_verdict"));
    }

    #[test]
    fn no_findings_yet_is_neutral_and_carries_no_count() {
        let payload = reading(&json!({"latest": null}), now());
        let seg = segment(&payload);
        assert_eq!(seg["state"], "neutral");
        assert_ne!(seg["state"], "ok", "nothing checked is not everything fine");
        // A zero here would render as a clean bill of health.
        assert!(seg.get("count").is_none());
        assert!(seg.get("total").is_none());
        // Nothing was observed, so there is nothing to be fresh or stale.
        assert!(seg.get("age_seconds").is_none());
        assert!(payload.get("observed_at").is_none());
    }

    #[test]
    fn freshness_converts_the_stores_offset_timestamp_to_the_contracts_z_form() {
        // The verifiers write `Utc::now().to_rfc3339()`: a `+00:00` offset
        // with nanoseconds. The contract requires a literal `Z` and at most
        // microseconds, and refuses an offset outright because an age
        // computed from one is ambiguous across machines.
        let payload = reading(&status_with("verified"), now());
        assert_eq!(payload["observed_at"], "2026-09-29T11:59:00Z");
        assert_eq!(segment(&payload)["age_seconds"], 60);
    }

    #[test]
    fn a_future_timestamp_clamps_to_zero_rather_than_reporting_a_negative_age() {
        // Not hypothetical: a timestamp under an agent's influence has
        // already produced a nonsense age in the founder's own wrapper, and a
        // huge number is the reading a user would trust and understand least.
        let mut body = status_with("verified");
        body["latest"]["computed_at"] = json!("2026-09-29T12:05:00+00:00");
        assert_eq!(segment(&reading(&body, now()))["age_seconds"], 0);
    }

    #[test]
    fn an_unreadable_timestamp_yields_no_freshness_cue_at_all() {
        // Substituting "now" would present an unreadable timestamp as a fresh
        // reading, which is the one direction that misleads. No cue is the
        // honest answer, and the verdict is still worth reporting without one.
        let mut body = status_with("verified");
        body["latest"]["computed_at"] = json!("last Tuesday");
        let payload = reading(&body, now());
        assert!(payload.get("observed_at").is_none());
        let seg = segment(&payload);
        assert!(seg.get("age_seconds").is_none());
        assert_eq!(seg["label"], "Verified");
    }

    #[test]
    fn an_absurdly_old_timestamp_clamps_instead_of_failing_the_whole_payload() {
        // The host rejects an age past its own ceiling, and a rejected
        // provider renders as an unknown with no reading at all. "Very old"
        // is a worse answer than the truth and a much better one than that.
        let mut body = status_with("verified");
        body["latest"]["computed_at"] = json!("1970-01-01T00:00:00+00:00");
        assert_eq!(
            segment(&reading(&body, now()))["age_seconds"],
            MAX_AGE_SECONDS
        );
    }

    #[test]
    fn availability_is_still_available_when_there_are_no_findings() {
        // The daemon answered. "Running and has verified nothing" is a live
        // reading, not an absence of one, and reporting it as unavailable
        // would blame the wrong thing.
        assert_eq!(
            reading(&json!({"latest": null}), now())["availability"],
            "available"
        );
    }
}
