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

use std::io::{IsTerminal, Read};
use std::time::Duration;

use chrono::{DateTime, SubsecRound, Utc};
use serde_json::{json, Value};

/// Version of the host-compositor identity-stdin document (HORO-1602) this
/// client understands. An unrecognised version is treated exactly like
/// absent stdin -- there is no partial-trust reading of a document shape
/// this client was not built to parse.
const IDENTITY_STDIN_VERSION: u64 = 1;

/// Read `provider_session_id` from the host's identity-stdin document, per
/// `governance/product/statusline-host-compositor.md`'s "Provider identity
/// context" section in `horonomy/.github`.
///
/// Every failure mode here -- a TTY, no bytes, unparseable JSON, the wrong
/// `identity_stdin_version`, a missing or empty `provider_session_id`, or a
/// raw Claude Code payload piped in directly (it has `session_id`, not this
/// document's shape, and no version field at all) -- collapses to `None`,
/// which is byte-identical to "the host sent nothing." This client never
/// falls back to guessing a session id from any other source (PID, cwd,
/// environment): absent identity is absent identity.
///
/// Guards against blocking on a human-run `fornax statusline provider`
/// (`docs/dogfooding-status-line.md` tells users to run this by hand) by
/// skipping the read entirely when stdin is a terminal -- reading from an
/// interactive TTY would hang waiting for input that is never coming.
pub fn read_identity_stdin() -> Option<String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return None;
    }
    let mut buf = Vec::with_capacity(256);
    stdin.lock().take(4096).read_to_end(&mut buf).ok()?;
    parse_identity_document(&buf)
}

/// The parsing half of [`read_identity_stdin`], split out so every failure
/// mode (malformed JSON, wrong version, missing/empty field, a raw Claude
/// Code payload with no version field at all) is unit-testable without
/// faking process stdin.
fn parse_identity_document(buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }
    let doc: Value = serde_json::from_slice(buf).ok()?;
    if doc.get("identity_stdin_version")?.as_u64()? != IDENTITY_STDIN_VERSION {
        return None;
    }
    let session_id = doc.get("provider_session_id")?.as_str()?;
    if session_id.is_empty() {
        return None;
    }
    Some(session_id.to_string())
}

/// Version of the cross-product provider contract (HORO-1564) this module
/// speaks. A host that does not recognise it refuses the whole payload
/// rather than guessing at a meaning, which is why it is stated explicitly
/// on every answer including the failures.
pub const CONTRACT_VERSION: u32 = 1;

/// Provider id, as registered with the host.
pub const PROVIDER_ID: &str = "fornax";

/// Default breadth of the state being reported, when no provider-session
/// identity is known or the daemon did not confirm it filtered by one.
///
/// This was unconditionally the right answer before HORO-1601/1602: the hot
/// path read `GET /api/status`, which was `Store::recent_findings(1)` — a
/// single `ORDER BY computed_at DESC LIMIT 1` over the findings table with
/// **no session predicate** — so the latest finding on this machine could
/// belong to a different session than the one the statusline is being
/// rendered for, and declaring `session` would have made the host label it
/// as this session's state, which would have been false. `GET /api/status`
/// now also accepts `?session=`, and [`reading`] declares `session` instead
/// of this constant exactly when the daemon's response proves it actually
/// honored that parameter (`"session_scoped": true`) — never merely because
/// the CLI asked for it. This constant remains the honest default for every
/// case that confirmation does not cover: no identity resolved at all, or an
/// older daemon that does not understand the parameter yet.
pub const SCOPE: &str = "host";

/// Where Fornax sits relative to other products on the shared line. Lower
/// sorts earlier; the range is deliberately sparse so products can be
/// reordered without renegotiating.
pub const ORDER_HINT: u32 = 300;

/// Fornax decides its own Clear-mode projection rather than leaving the host
/// to infer one (HORO-1632).
///
/// The host has a documented fallback ladder that ranks segments by severity
/// and position, and for a provider that has not spoken it is a reasonable
/// guess. For Fornax it is the wrong question. Clear mode asks "what is the
/// one thing a glance should tell me", and Fornax's answer is fixed by the
/// product's own semantics: **the verification state, and nothing else.**
/// Verified, Unverified, Needs review, Contradicted, Evidence unavailable and
/// "nothing verified yet" are six readings of one fact, and which of them is
/// current is never a severity judgement the host should be making — a
/// `Contradicted` finding is not an outage, and inferring `exception` from its
/// `critical` state says Fornax is broken when what it means is that Fornax
/// worked and the claim did not hold.
///
/// Every payload this module emits carries exactly one segment, so declaring
/// authority does not change today's rendering. That is the point of doing it
/// now rather than later: the host's inference and Fornax's intent currently
/// agree by arithmetic, and a declaration is what keeps them agreeing when
/// Fornax grows a second segment. Nothing then has to be renegotiated, and no
/// host-side product conditional ever has to exist.
///
/// The host validates the claim instead of trusting it — under `provider` it
/// requires at least one segment, a `clear_role` on every segment, at most one
/// `posture`, and at least one `posture` or `exception` — and refuses a payload
/// that does not hold up rather than silently re-inferring. Both shapes below
/// are built to satisfy that, and the tests check each outcome individually.
pub const CLEAR_AUTHORITY: &str = "provider";

/// The Clear-mode part the verification segment plays: Fornax's posture.
///
/// `posture` is "the standing reading of this product", which is exactly what a
/// verdict is — it remains true until the next verification changes it, and it
/// is the one fact worth a glance. Not `vital`, which is a live measurement
/// qualifying a posture, and emphatically not `exception` for the unhappy
/// verdicts: `Contradicted` and `Evidence unavailable` are Fornax reporting
/// successfully, so routing them to the host's stop-work rung would borrow the
/// vocabulary of a broken product to describe a working one.
const CLEAR_ROLE_VERDICT: &str = "posture";

/// The Clear-mode part the availability segment plays: an exception.
///
/// This is the one case where Fornax genuinely cannot answer — no daemon, no
/// answer in time, an untrusted peer, an unreadable store. There is no
/// verification state to show, so the absence *is* the reading, and `exception`
/// is the host's rung for "this product cannot tell you". It also satisfies the
/// host's "a posture or an exception" rule without inventing a posture Fornax
/// does not have.
const CLEAR_ROLE_AVAILABILITY: &str = "exception";

/// How long the hot-path probe may wait for the daemon.
///
/// Under the host's own default per-provider budget (250 ms), so that a slow
/// daemon produces a truthful payload rather than getting killed mid-write
/// and contributing nothing. A loopback `GET` against `/api/status` measures
/// about 30 ms warm end to end; anything an order of magnitude past that is
/// a fact worth reporting, not worth waiting for.
pub const HOT_PATH_BUDGET: Duration = Duration::from_millis(200);

/// How long the `explain` surface may wait. Larger on purpose: the user asked
/// a question and is waiting for the answer, so a slow daemon is worth
/// waiting out rather than reporting as a timeout.
pub const EXPLAIN_BUDGET: Duration = Duration::from_secs(3);

/// Why the provider has no live reading to report.
///
/// These are six distinct facts and the contract refuses to collapse them:
/// a stopped daemon is not a daemon reporting nothing, and a probe that
/// failed is not silence. Each maps to its own availability and its own
/// bounded reason code, so a `doctor` surface can tell the user what to
/// actually do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoReading {
    /// Nothing answered on the daemon port.
    DaemonUnreachable,
    /// Something is listening, but did not answer inside the render budget.
    /// A separate fact from a stopped daemon: reporting a slow daemon as
    /// "not running" would send the user to start one that is already up.
    DaemonTooSlow,
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
            NoReading::DaemonTooSlow
            | NoReading::DaemonIdentityMismatch
            | NoReading::DaemonIdentityNotReported => "unknown",
            NoReading::StoreReadFailed | NoReading::ResponseNotUnderstood => "error",
        }
    }

    /// Machine-readable reason, for a `doctor` surface and for tests.
    fn reason_code(self) -> &'static str {
        match self {
            NoReading::DaemonUnreachable => "daemon_unreachable",
            NoReading::DaemonTooSlow => "daemon_too_slow",
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
            NoReading::DaemonTooSlow => "No answer in time",
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
        "clear_authority": CLEAR_AUTHORITY,
        "segments": [{
            "key": "availability",
            "state": state_for(availability),
            "label": kind.label(),
            "reason_code": kind.reason_code(),
            "explain_key": "fornax.availability",
            "clear_role": CLEAR_ROLE_AVAILABILITY,
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
///
/// `scope` (HORO-1601/1602) is declared `session` only when `body` itself
/// carries `"session_scoped": true` — the daemon's own confirmation that it
/// understood `?session=` and actually filtered by it, not merely that the
/// CLI *asked* for session scoping. An older daemon that ignores the query
/// parameter and answers cross-session, or a daemon this client did not ask
/// for session scoping at all, both leave `session_scoped` absent, and this
/// falls back to [`SCOPE`] (`host`) — never guessed, never defaulted to the
/// more specific claim.
pub fn reading(body: &Value, now: DateTime<Utc>) -> Value {
    let scope = if body.get("session_scoped").and_then(Value::as_bool) == Some(true) {
        "session"
    } else {
        SCOPE
    };
    let mut observed_at = None;
    let segment = match body.get("latest").filter(|l| !l.is_null()) {
        None => json!({
            "key": "latest_finding",
            "state": "neutral",
            "label": "No findings yet",
            "explain_key": "fornax.latest_finding",
            // Still the verification state, and still Fornax's posture. "Nothing
            // verified yet" is a reading of the same fact as "Verified" — the
            // daemon is up and has an answer about how much it has established —
            // so it is not an exception and the host must not infer one.
            "clear_role": CLEAR_ROLE_VERDICT,
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
                // Declared from the segment's *meaning*, not from its state, so
                // every verdict — including `critical` for Contradicted and
                // `unknown` for a verdict newer than this client — projects to
                // the same Clear role. A state-dependent role here would be the
                // host's severity ladder rebuilt inside the provider.
                "clear_role": CLEAR_ROLE_VERDICT,
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
        "scope": scope,
        "availability": "available",
        "order_hint": ORDER_HINT,
        "clear_authority": CLEAR_AUTHORITY,
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
///
/// `requested_session` (HORO-1601/1602) is whatever identity this client
/// resolved before probing, independent of whether the daemon confirmed it
/// — passed through so the header can name *which* of the three cases
/// applied instead of a single hardcoded claim: scoped to this session,
/// host-wide because no session identity was available, or host-wide
/// because this daemon did not confirm it understood `?session=`.
pub fn explain_text(
    status: &Value,
    fused: Option<&Value>,
    now: DateTime<Utc>,
    requested_session: Option<&str>,
) -> String {
    let confirmed = status.get("session_scoped").and_then(Value::as_bool) == Some(true);
    let header = match (requested_session, confirmed) {
        (Some(_), true) => "Fornax — latest finding for this session\n\n",
        (Some(_), false) => {
            "Fornax — latest finding on this machine (host-wide — this daemon did not \
             confirm session-scoped filtering)\n\n"
        }
        (None, _) => "Fornax — latest finding on this machine (host-wide — no session identity available)\n\n",
    };
    let mut out = String::from(header);
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
/// `recent_findings(1)`; the whole subcommand measures 22-82 ms warm in a
/// debug build, median about 30 ms.
///
/// The FORNX-339 identity check is applied here exactly as every other
/// client applies it — a peer that cannot prove which `$FORNAX_HOME` it
/// serves is refused — but the outcome is returned as a typed [`NoReading`]
/// rather than an error string, because the two refusal cases must render as
/// two different reason codes.
///
/// `session`, when present (HORO-1601/1602), is sent as `?session=` via
/// `reqwest`'s own query-building (`RequestBuilder::query`), never
/// hand-formatted into the URL string -- a raw `format!` would need its own
/// percent-encoding for a session id that happens to contain `&`/`=`/etc.,
/// which `query` already does correctly.
pub async fn probe(budget: Duration, session: Option<&str>) -> Result<Value, NoReading> {
    let url = format!("{}/api/status", crate::base_url());
    let client = reqwest::Client::builder()
        .timeout(budget)
        .build()
        .map_err(|_| NoReading::DaemonUnreachable)?;
    let mut request = client.get(&url);
    if let Some(session_id) = session {
        request = request.query(&[("session", session_id)]);
    }
    let response = request.send().await.map_err(|e| {
        if e.is_timeout() {
            NoReading::DaemonTooSlow
        } else {
            NoReading::DaemonUnreachable
        }
    })?;
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
    let client = reqwest::Client::builder()
        .timeout(EXPLAIN_BUDGET)
        .build()
        .ok()?;
    let response = client.get(&url).send().await.ok()?;
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
        NoReading::DaemonTooSlow => {
            "Something is listening on the Fornax port but did not answer \
             inside the render budget, so the daemon is up and its state is \
             simply unread. If this persists, check the daemon's load."
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

    /// Every way the probe can come back empty-handed. Kept as one list so
    /// that adding a sixth variant without deciding what it means is a
    /// compile error here rather than a silent `unknown` on someone's line.
    const ALL_NO_READINGS: [NoReading; 6] = [
        NoReading::DaemonUnreachable,
        NoReading::DaemonTooSlow,
        NoReading::DaemonIdentityMismatch,
        NoReading::DaemonIdentityNotReported,
        NoReading::StoreReadFailed,
        NoReading::ResponseNotUnderstood,
    ];

    #[test]
    fn each_no_reading_outcome_keeps_its_own_availability_and_reason() {
        let expected = [
            (NoReading::DaemonUnreachable, "unavailable", "neutral"),
            // Not `unavailable`: Fornax declined to trust the peer, which
            // leaves the real state unobserved rather than absent.
            (NoReading::DaemonIdentityMismatch, "unknown", "unknown"),
            (NoReading::DaemonIdentityNotReported, "unknown", "unknown"),
            // A failed probe may need the user to act, so it warns.
            (NoReading::StoreReadFailed, "error", "warn"),
            (NoReading::ResponseNotUnderstood, "error", "warn"),
        ];
        let mut codes = Vec::new();
        for (kind, availability, state) in expected {
            let payload = no_reading(kind);
            assert_eq!(payload["availability"], availability, "{kind:?}");
            let seg = segment(&payload);
            assert_eq!(seg["state"], state, "{kind:?}");
            codes.push(seg["reason_code"].as_str().unwrap().to_string());
        }
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), 5, "two outcomes share one reason code");
    }

    #[test]
    fn no_outcome_without_a_reading_can_be_mistaken_for_a_healthy_one() {
        for kind in ALL_NO_READINGS {
            let payload = no_reading(kind);
            let segments = payload["segments"].as_array().unwrap();
            // An empty answer renders as silence, and silence reads as "all
            // clear". This is the failure this shape exists to prevent.
            assert_eq!(segments.len(), 1, "{kind:?} must still say something");
            let seg = &segments[0];
            assert_ne!(seg["state"], "ok", "{kind:?}");
            // A count would be a measurement, and nothing was measured. Zero
            // in particular would read as a clean bill of health.
            assert!(seg.get("count").is_none(), "{kind:?}");
            assert!(seg.get("total").is_none(), "{kind:?}");
            assert!(seg.get("confidence").is_none(), "{kind:?}");
            assert_ne!(payload["availability"], "available", "{kind:?}");
        }
    }

    /// Every verdict name the daemon can send, plus one it cannot.
    ///
    /// The last entry is deliberately not a real verdict: a client older than
    /// the daemon is a live case, and its Clear role must come out the same as
    /// every other verdict's. Listing it here means a future change that routes
    /// the unknown case somewhere else fails this test rather than shipping.
    const ALL_VERDICTS: [&str; 6] = [
        "verified",
        "unverified",
        "contradicted",
        "review",
        "unavailable",
        "a_verdict_from_a_newer_daemon",
    ];

    #[test]
    fn every_verdict_declares_the_verification_state_as_fornaxs_clear_posture() {
        // The whole product claim of HORO-1632 in one assertion: Clear mode
        // shows the verification state and nothing else, for all six readings,
        // and that is a fact the payload states rather than one the host infers.
        for verdict in ALL_VERDICTS {
            let payload = reading(&status_with(verdict), now());
            assert_eq!(payload["clear_authority"], "provider", "{verdict}");
            assert_eq!(segment(&payload)["clear_role"], "posture", "{verdict}");
        }
    }

    #[test]
    fn the_clear_role_does_not_track_the_segment_state() {
        // The guard against the thing this ticket exists to stop: a severity
        // ladder rebuilt inside the provider. These four verdicts span `ok`,
        // `critical`, `warn` and `unknown`, so if the role were derived from
        // state in any way, these would not all be equal.
        let roles: Vec<String> = ["verified", "contradicted", "review", "unavailable"]
            .iter()
            .map(|v| {
                let payload = reading(&status_with(v), now());
                let seg = segment(&payload);
                // Guard the guard: a test over four identical states would
                // pass vacuously, so assert the states really do differ.
                format!("{}:{}", seg["state"].as_str().unwrap(), seg["clear_role"])
            })
            .collect();
        let mut states: Vec<&str> = roles.iter().map(|r| r.split(':').next().unwrap()).collect();
        states.sort();
        states.dedup();
        assert_eq!(states.len(), 4, "the fixture no longer spans four states");
        for role in &roles {
            assert!(role.ends_with(":\"posture\""), "{role}");
        }
    }

    #[test]
    fn nothing_verified_yet_is_a_posture_and_not_an_exception() {
        // "The daemon is up and has established nothing" is a reading of the
        // verification state, so it belongs on the same rung as a verdict. An
        // exception here would say Fornax cannot answer, when it just has.
        let payload = reading(&json!({"latest": null}), now());
        assert_eq!(payload["clear_authority"], "provider");
        assert_eq!(segment(&payload)["clear_role"], "posture");
    }

    #[test]
    fn every_no_reading_outcome_declares_its_availability_as_the_exception() {
        // The mirror image: here Fornax genuinely cannot report a verification
        // state, so the absence is the reading and `exception` is its rung.
        for kind in ALL_NO_READINGS {
            let payload = no_reading(kind);
            assert_eq!(payload["clear_authority"], "provider", "{kind:?}");
            assert_eq!(segment(&payload)["clear_role"], "exception", "{kind:?}");
        }
    }

    #[test]
    fn every_payload_satisfies_the_hosts_rules_for_a_declared_projection() {
        // Declaring authority is a claim the host *validates*: at least one
        // segment, a role on every segment, at most one posture, and at least
        // one posture or exception. A payload that declares and then fails any
        // of those is refused outright — it renders as nothing at all, not as a
        // fallback — so every shape this module can emit is checked here rather
        // than trusting that two call sites got it right.
        let mut payloads: Vec<Value> = ALL_VERDICTS
            .iter()
            .map(|v| reading(&status_with(v), now()))
            .collect();
        payloads.push(reading(&json!({"latest": null}), now()));
        payloads.extend(ALL_NO_READINGS.iter().map(|k| no_reading(*k)));
        assert_eq!(payloads.len(), 13, "a shape stopped being covered");
        for payload in &payloads {
            assert_eq!(payload["clear_authority"], "provider");
            let segments = payload["segments"].as_array().unwrap();
            assert!(!segments.is_empty());
            let roles: Vec<&str> = segments
                .iter()
                .map(|s| {
                    s["clear_role"]
                        .as_str()
                        .expect("every segment must declare a role")
                })
                .collect();
            assert!(roles.iter().filter(|r| **r == "posture").count() <= 1);
            assert!(roles.iter().any(|r| *r == "posture" || *r == "exception"));
        }
    }

    #[test]
    fn declaring_a_clear_projection_adds_two_keys_and_changes_nothing_else() {
        // Detail mode must be untouched, and the honest form of that claim is
        // not "the payload is byte-identical" — it gained two keys — but "every
        // key that existed before is unchanged, and the only new ones are the
        // declaration itself". Anything else moving means Detail moved too,
        // because Detail renders the same snapshot.
        let strip = |mut payload: Value| -> Value {
            assert_eq!(payload["clear_authority"], "provider");
            payload
                .as_object_mut()
                .unwrap()
                .remove("clear_authority")
                .unwrap();
            for seg in payload["segments"].as_array_mut().unwrap() {
                assert!(seg.as_object_mut().unwrap().remove("clear_role").is_some());
            }
            payload
        };
        // The expected values are written out rather than recomputed, so this
        // is a comparison against the pre-HORO-1632 payload and not against
        // whatever the code happens to produce now.
        assert_eq!(
            strip(reading(&status_with("contradicted"), now())),
            json!({
                "contract_version": 1,
                "provider": "fornax",
                "provider_version": env!("CARGO_PKG_VERSION"),
                "scope": "host",
                "availability": "available",
                "order_hint": 300,
                "observed_at": "2026-09-29T11:59:00Z",
                "segments": [{
                    "key": "latest_finding",
                    "state": "critical",
                    "label": "Contradicted",
                    "explain_key": "fornax.latest_finding",
                    "age_seconds": 60,
                }],
            })
        );
        assert_eq!(
            strip(no_reading(NoReading::DaemonUnreachable)),
            json!({
                "contract_version": 1,
                "provider": "fornax",
                "provider_version": env!("CARGO_PKG_VERSION"),
                "scope": "host",
                "availability": "unavailable",
                "order_hint": 300,
                "segments": [{
                    "key": "availability",
                    "state": "neutral",
                    "label": "Not running",
                    "reason_code": "daemon_unreachable",
                    "explain_key": "fornax.availability",
                }],
            })
        );
    }

    /// Substrings that must never appear in anything either surface prints.
    ///
    /// The first three are the free-text fields themselves. `sk-`, `ghp_` and
    /// `Bearer` are shapes a credential takes: no code path here reads a
    /// credential, and these assertions exist so that a future one cannot
    /// start without a test noticing.
    const FORBIDDEN: [&str; 6] = [
        "private/repo",
        "pytest",
        "I ran the tests",
        "sk-",
        "ghp_",
        "Bearer",
    ];

    fn assert_nothing_forbidden(where_: &str, rendered: &str) {
        for needle in FORBIDDEN {
            assert!(
                !rendered.contains(needle),
                "{where_} leaked {needle:?}:\n{rendered}"
            );
        }
    }

    #[test]
    fn no_free_text_product_field_reaches_the_provider_payload() {
        // The fixture's `rationale` and `claim_text` carry exactly what the
        // verifiers really interpolate: a claimed command and a claimed path.
        // Both are in the input; neither may be in the output.
        for verdict in [
            "verified",
            "unverified",
            "contradicted",
            "review",
            "unavailable",
            "some_future_verdict",
        ] {
            let payload = reading(&status_with(verdict), now());
            assert_nothing_forbidden(
                &format!("provider payload for {verdict}"),
                &payload.to_string(),
            );
        }
    }

    #[test]
    fn no_free_text_product_field_reaches_the_explain_surface() {
        // Same guarantee where the temptation is strongest: this surface has
        // room to print the rationale and deliberately does not.
        let text = explain_text(&status_with("unverified"), None, now(), None);
        assert_nothing_forbidden("explain", &text);
        // And with a fused view, whose rationale entries carry their own free
        // text in `detail`.
        let fused = json!({
            "found": true,
            "fused": {
                "uncertainty": "undetermined",
                "rationale": [{
                    "rule": "verdict_decided",
                    "effect": "decided",
                    "detail": "nobody looked for pytest in /Users/someone/private/repo",
                }],
            },
        });
        let text = explain_text(&status_with("unverified"), Some(&fused), now(), None);
        assert_nothing_forbidden("explain with fused view", &text);
        // The closed vocabularies it *is* allowed to print are still printed,
        // so this is not passing by rendering nothing.
        assert!(text.contains("undetermined"));
        assert!(text.contains("verdict_decided"));
    }

    #[test]
    fn neither_surface_prints_an_opaque_identifier() {
        // Claim and session ids answer no question either surface is asked,
        // and printing an identifier by default is how identifiers end up
        // pasted into tickets.
        let body = status_with("unverified");
        let ids = [
            "62d3a1f0-0000-4000-8000-000000000001",
            "62d3a1f0-0000-4000-8000-000000000002",
            "62d3a1f0-0000-4000-8000-000000000003",
        ];
        let rendered = format!(
            "{}{}",
            reading(&body, now()),
            explain_text(&body, None, now(), None)
        );
        for id in ids {
            assert!(!rendered.contains(id), "leaked {id}");
        }
    }

    #[test]
    fn no_failure_label_carries_a_home_path_a_port_or_an_identity_digest() {
        // These labels are rendered straight into the user's terminal, and an
        // error string from this codebase routinely carries all three.
        for kind in ALL_NO_READINGS {
            let rendered = format!("{}{}", no_reading(kind), explain_unavailable(kind));
            assert!(!rendered.contains('/'), "{kind:?} rendered a path");
            assert!(!rendered.contains("127.0.0.1"), "{kind:?} rendered a host");
            assert!(!rendered.contains("4317"), "{kind:?} rendered a port");
        }
    }

    #[test]
    fn explain_says_the_reason_is_not_recorded_rather_than_omitting_it() {
        // The whole point of this surface is that a user arrives asking "why
        // is this unverified". Leaving the absence to be inferred from a
        // missing line is the answer that sends them looking for a bug.
        let text = explain_text(&status_with("unverified"), None, now(), None);
        assert!(text.contains("reason         not recorded"));
        assert!(text.contains("does not record a reason category"));
    }

    #[test]
    fn explain_does_not_volunteer_a_reason_line_for_a_verdict_that_has_no_gap() {
        // `verified` and `contradicted` are decided answers. A "reason: not
        // recorded" line beside them would invent a doubt.
        for verdict in ["verified", "contradicted", "review"] {
            let text = explain_text(&status_with(verdict), None, now(), None);
            assert!(!text.contains("not recorded"), "{verdict}");
        }
    }

    #[test]
    fn explain_names_the_kind_of_evidence_the_verifier_sought() {
        // The closed five-name set from `fornax-verify`, and the cue this
        // surface exists to carry instead of the statusline.
        let text = explain_text(&status_with("unverified"), None, now(), None);
        assert!(text.contains("evidence for   test results"), "{text}");
    }

    #[test]
    fn an_unrecognised_verifier_name_is_reported_as_unknown_not_printed() {
        // A name this client has never seen is unbounded output as far as it
        // can prove, so it is described rather than echoed.
        let mut body = status_with("unverified");
        body["latest"]["verifier_name"] = json!("some_future_verifier_v9");
        let text = explain_text(&body, None, now(), None);
        assert!(!text.contains("some_future_verifier_v9"), "{text}");
        assert!(
            text.contains("verifier this client does not know"),
            "{text}"
        );
    }

    #[test]
    fn explain_distinguishes_no_fused_view_from_no_answer_about_one() {
        // Three different facts, and a missing section would read as the
        // absence of all three.
        let body = status_with("unverified");
        let unreachable = explain_text(&body, None, now(), None);
        assert!(unreachable.contains("unavailable"), "{unreachable}");

        let not_found = explain_text(&body, Some(&json!({"found": false})), now(), None);
        assert!(not_found.contains("no fused view for this claim yet"));

        let found = explain_text(
            &body,
            Some(&json!({"found": true, "fused": {"uncertainty": "undetermined"}})),
            now(),
            None,
        );
        assert!(found.contains("uncertainty  undetermined"));
        // No rationale array at all is "none recorded", not silence.
        assert!(found.contains("rules        none recorded"), "{found}");
    }

    #[test]
    fn explain_reports_no_findings_without_calling_it_a_pass() {
        let text = explain_text(&json!({"latest": null}), None, now(), None);
        assert!(text.contains("No findings recorded yet"));
        assert!(text.contains("not the same as a pass"));
    }

    #[test]
    fn every_unavailable_explanation_says_what_to_do_about_it() {
        // A diagnostic that names a state without naming a next step is a
        // dead end, and four of these five are user-fixable.
        for kind in ALL_NO_READINGS {
            let text = explain_unavailable(kind);
            assert!(text.contains(kind.label()), "{kind:?}");
            // Longer than the label alone, i.e. it actually explains.
            assert!(
                text.len() > kind.label().len() + 60,
                "{kind:?} explained nothing"
            );
        }
    }

    // --- HORO-1601/1602: session-scoped reading and identity-stdin parsing ---

    #[test]
    fn reading_declares_session_scope_only_when_the_daemon_confirms_it() {
        let mut body = status_with("verified");
        body["session_scoped"] = json!(true);
        assert_eq!(reading(&body, now())["scope"], "session");
    }

    #[test]
    fn reading_stays_host_scoped_when_the_daemon_does_not_confirm_session_scoping() {
        // No `session_scoped` key at all -- an older daemon, or this client
        // never asked for session scoping.
        assert_eq!(reading(&status_with("verified"), now())["scope"], "host");
    }

    #[test]
    fn reading_stays_host_scoped_when_session_scoped_is_explicitly_false() {
        let mut body = status_with("verified");
        body["session_scoped"] = json!(false);
        assert_eq!(reading(&body, now())["scope"], "host");
    }

    #[test]
    fn reading_stays_host_scoped_when_session_scoped_is_the_wrong_type() {
        // A malformed or forward-incompatible daemon response must never be
        // interpreted as confirmation by accident -- only a literal JSON
        // `true` counts.
        let mut body = status_with("verified");
        body["session_scoped"] = json!("true");
        assert_eq!(reading(&body, now())["scope"], "host");
    }

    #[test]
    fn a_zero_finding_session_reports_no_findings_yet_under_session_scope() {
        // The daemon confirmed session scoping and genuinely has nothing for
        // this session -- this must render as the ordinary "no findings"
        // posture under `[session]`, never silently fall back to the
        // cross-session latest finding.
        let body = json!({"latest": null, "session_scoped": true});
        let payload = reading(&body, now());
        assert_eq!(payload["scope"], "session");
        assert_eq!(segment(&payload)["label"], "No findings yet");
    }

    #[test]
    fn explain_text_names_which_of_the_three_scope_cases_applied() {
        let scoped = json!({"latest": null, "session_scoped": true});
        assert!(explain_text(&scoped, None, now(), Some("sess-a"))
            .starts_with("Fornax — latest finding for this session"));

        let unconfirmed = json!({"latest": null});
        assert!(explain_text(&unconfirmed, None, now(), Some("sess-a"))
            .contains("host-wide — this daemon did not confirm session-scoped filtering"));

        let no_identity = json!({"latest": null});
        assert!(explain_text(&no_identity, None, now(), None)
            .contains("host-wide — no session identity available"));
    }

    #[test]
    fn identity_document_with_correct_version_and_session_id_is_accepted() {
        let doc = json!({"identity_stdin_version": 1, "provider_session_id": "claude-sess-7e21"});
        assert_eq!(
            parse_identity_document(doc.to_string().as_bytes()),
            Some("claude-sess-7e21".to_string())
        );
    }

    #[test]
    fn identity_document_is_rejected_for_every_malformed_or_absent_shape() {
        let cases: &[(&str, &[u8])] = &[
            ("empty bytes", b""),
            ("not json at all", b"not json"),
            (
                "version as a bool",
                br#"{"identity_stdin_version": true, "provider_session_id": "x"}"#,
            ),
            (
                "version 2, not understood by this client",
                br#"{"identity_stdin_version": 2, "provider_session_id": "x"}"#,
            ),
            (
                "missing provider_session_id",
                br#"{"identity_stdin_version": 1}"#,
            ),
            (
                "empty provider_session_id",
                br#"{"identity_stdin_version": 1, "provider_session_id": ""}"#,
            ),
            (
                "provider_session_id wrong type",
                br#"{"identity_stdin_version": 1, "provider_session_id": 7}"#,
            ),
            // A raw Claude Code host payload has `session_id`, not this
            // document's `provider_session_id`, and no version field at all.
            (
                "raw Claude Code payload piped in directly",
                br#"{"session_id": "claude-sess-7e21", "cwd": "/Users/someone/secret-repo"}"#,
            ),
        ];
        for (name, bytes) in cases {
            assert_eq!(parse_identity_document(bytes), None, "{name}");
        }
    }
}
