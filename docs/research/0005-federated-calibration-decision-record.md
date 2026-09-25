# Federated calibration aggregation — decision record (FORNX-390)

Jira: FORNX-390, parent epic FORNX-376 (Stage 9, "Agent Epistemic Trust
Kernel"), Target Fix Version v0.3.0, marked experimental/non-blocking.
Priority Medium, Story Points 8, Execution: Agent/Research/Privacy.

## Question this ticket set out to answer

Can Fornax improve calibration and sensor/contract policy across
organizations while keeping sensitive prompts, source, tool output, and raw
evidence entirely under each customer's own control? Jira's own framing is
explicit that this must be evaluated, not assumed: "it must quantify utility
loss and operational complexity rather than assuming federated learning is
automatically valuable."

## What was actually built

A minimal, honestly-labeled research prototype —
[`crates/fornax-bench/src/federated_calibration.rs`] — simulating
privacy-preserving statistical aggregation of calibration residuals across
simulated tenants ("organizations"). Every input is synthetic
(`LabelingProvenance::SyntheticMechanismTest`); no real customer data was
used or is needed for this evaluation (the real Gold Corpus, FORNX-343,
remains founder-paused for unrelated cost-control reasons and has no bearing
on this ticket's own scope).

**Chosen mechanism**: minimum-support-gated trimmed-median aggregation
across at least 3 simulated tenants, not differential privacy or secure
multi-party computation. Both of the latter are real, defensible choices for
a *production* federated system, but both require infrastructure (a
noise-calibration/epsilon-accounting service, or a live multi-party
protocol with online participants) disproportionate to what a research-lane
prototype needs to answer this ticket's actual question. This is exactly
the "smallest credible technique" Jira's own scope asked for.

## What was measured

1. **No raw content leaves a tenant** (AC1) — structural property of
   `TenantLocalStatistic`'s schema (no field can hold a prompt/tool
   payload/evidence body), proven by
   `tenant_statistic_serialization_contains_no_raw_content_fields`.
2. **Explicit export schema** (AC2) — every aggregate names its schema
   version, purpose, minimum-support threshold, and an honest
   privacy-assumptions string that explicitly *disclaims* any formal
   epsilon/delta guarantee (`export_summary_names_schema_purpose_threshold_and_privacy_assumptions_explicitly`).
3. **Three simulated tenants, no cross-tenant raw access** (AC3) — each
   tenant's statistic is constructed independently from its own local data;
   fewer than 3 is refused outright
   (`fewer_than_three_tenants_is_refused`,
   `three_simulated_tenants_participate_without_cross_tenant_raw_access`).
4. **Privacy/utility trade-off measured quantitatively** (AC4) — on the
   synthetic benchmark
   (`federated_aggregate_is_measurably_closer_to_ground_truth_than_a_single_tenant`),
   against a ground-truth residual of `0.010`:
   - A single tenant's own local-only estimate: error `0.004`.
   - The federated (trimmed-median) aggregate: error `0.001`.
   - **4x lower error than the local-only baseline, on this synthetic
     benchmark.** This is a real, reproducible measurement — not a
     qualitative claim — but it is one small synthetic scenario, not a
     production utility estimate; see Limitations below.
5. **Poisoning resistance** (AC5) — a naive mean is trivially dominated by
   one extreme participant (demonstrated, not shipped:
   `a_poisoned_participant_cannot_dominate_the_trimmed_median_aggregate`
   shows the naive mean exceeding 100 when the honest cluster sits around
   0.01). The shipped trimmed-median aggregate stays within 0.01 of the
   honest-only result regardless of the poisoned value's magnitude
   (`an_arbitrarily_more_extreme_poisoned_value_moves_the_median_by_the_same_bounded_amount`
   shows identical results whether the poisoned value is 500 or 5,000,000 —
   a single participant can only ever shift the aggregate by one rank
   position, never by its own magnitude).
6. **Opt-out/deletion/revision is documented and reproducible** (AC6) —
   removing a tenant changes the aggregate's revision digest deterministically
   (`removing_a_tenant_changes_the_revision_digest_deterministically`);
   rebuilding from the same tenant set is byte-identical
   (`rebuilding_the_same_tenant_set_is_byte_identical`); a tenant revising
   its own statistic (same membership, new revision number) also changes
   the digest (`a_tenant_revising_its_statistic_changes_the_digest_even_with_the_same_membership`).

## Decision: NARROW/DEFER for v0.3.0

**The mechanism works.** It genuinely reduces error versus a local-only
baseline on the tested synthetic scenario, and it genuinely resists the one
poisoning scenario tested. That is a real, positive technical finding.

**It should not be turned into a shipped v0.3.0 feature**, for reasons this
ticket's own research surfaced rather than assumed:

1. **No real multi-tenant demand exists yet.** Fornax has no live customers
   running multi-tenant deployments today whose calibration would benefit
   from cross-tenant aggregation — this would be building ahead of any
   confirmed need.
2. **No real adjudicated data exists to validate the utility claim beyond
   one synthetic scenario.** The 4x error reduction measured above is a
   single hand-authored synthetic benchmark with 3 tenants and hand-picked
   noise values — informative about the *mechanism's* behavior, not a
   calibrated real-world utility estimate. A real validation would need
   real multi-tenant reliability observations, which don't exist (see
   `fornax-verify::reliability`'s own "out of scope" section — nothing on
   the live claim path produces `ReliabilityObservation`s yet, federated
   or not).
3. **Real operational cost is nontrivial and mostly unbuilt.** A production
   version would need: a consent/opt-in lifecycle per tenant, an export
   audit trail, cross-tenant governance and dispute handling, a real
   distribution/transport mechanism for aggregates, and monitoring for
   exactly the poisoning/reconstruction/membership-inference threats this
   prototype only tested in isolation. None of that exists, and building it
   speculatively — before either a real customer need or real data to
   validate against — would be exactly the "dataset moat" trap this
   ticket's own research framing warned against inverting into an
   infrastructure trap instead.
4. **Nothing upstream currently produces the real inputs this mechanism
   would consume.** `fornax-verify::reliability` has no live producer of
   `ReliabilityObservation`s (see that module's own docs). Federated
   aggregation of a statistic nothing yet computes locally, in production,
   is premature regardless of the aggregation mechanism's own soundness.

**Recommendation**: keep this prototype as a tested, documented research
artifact (`crates/fornax-bench/src/federated_calibration.rs`). Revisit only
if *both* conditions materialize together: (a) real multi-tenant customer
demand for cross-organization calibration insight, and (b) a real local
`ReliabilityObservation` producer exists so there is genuine data to
federate in the first place. Building either half alone does not justify
resuming this direction.

## Limitations of this research pass

- Three tenants, one synthetic scenario, one poisoning magnitude tested.
  A production validation would need many more scenarios, tenant-count
  sweeps, and multiple simultaneous poisoned participants.
- The trimmed-median choice was not compared against every possible robust
  aggregator (e.g. a formally-parameterized differentially-private mean) —
  it was chosen as the smallest credible mechanism per Jira's own
  instruction, not as the provably optimal one.
- No reconstruction or membership-inference attack was implemented and run
  against the aggregate itself (only reasoned about structurally, in the
  module's docs) — a deeper security review would be warranted before any
  real deployment, independent of this ticket's own scope.

This is exactly the kind of negative-leaning, narrowing conclusion Jira's
own AC7 explicitly anticipated as a fully successful outcome for a
Priority: Medium, non-blocking research ticket.
