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

use chrono::{DateTime, Utc};
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
fn verdict_rendering(verdict: &str) -> VerdictRendering {
    match verdict {
        "verified" => VerdictRendering {
            state: "ok",
            label: "Verified",
        },
        "unverified" => VerdictRendering {
            state: "attention",
            label: "Unverified",
        },
        "contradicted" => VerdictRendering {
            state: "critical",
            label: "Contradicted",
        },
        "review" => VerdictRendering {
            state: "warn",
            label: "Needs review",
        },
        "unavailable" => VerdictRendering {
            state: "unknown",
            label: "Evidence unavailable",
        },
        _ => VerdictRendering {
            state: "unknown",
            label: "Verdict this client does not know",
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
        .with_timezone(&Utc);
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
