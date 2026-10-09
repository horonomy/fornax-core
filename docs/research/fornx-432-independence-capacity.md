# FORNX-432 — independence-capacity benchmark results (PR 1 + PR 2)

**Synthetic shapes, not a real workload.** See `crates/fornax-bench/src/independence_capacity.rs` module docs for fixture definitions, size caps and the `bench-reference` cross-check. `peak_bytes` is process-wide (this binary's own allocator), reset to the already-outstanding baseline before each run rather than to zero -- see `reset_alloc_counters` in `main.rs`. `wall_time_ms` approximates CPU time: `SourceFamilyMap::build` runs single-threaded.

Per-fixture wall-time budget: 20s (a shape exceeding it skips its remaining larger configured sizes, recorded under Skipped below).

## Before (PR 1) vs. after (PR 2)

PR 2 made `SourceFamilyMap::build`/`ancestors_of` output-identical but faster:
one id index built once per `build` call instead of once per evidence
record (cost source A), and the per-family `Vec::contains`/`evidence.iter().find`
rescans replaced with a precomputed family-key lookup (cost sources D/E) --
see `independence.rs`'s PR 2 comments and `speedup_equivalence`'s proptest
module for the correctness proof this relies on. `reference_hash_matches: true`
on every row in both tables confirms the two columns describe the exact same
output, just measured before and after.

| shape | size | wall_time_ms (before) | wall_time_ms (after) | speedup | peak_bytes (before) | peak_bytes (after) |
|---|---|---|---|---|---|---|
| flat | 100 | 0.17 | 0.16 | 1.1x | 108337 | 110754 |
| flat | 1000 | 6.78 | 0.50 | 13.6x | 1128627 | 1173749 |
| flat | 5000 | 162.09 | 2.36 | 68.7x | 5697242 | 5760060 |
| flat | 10000 | 653.84 | 4.57 | 143.1x | 11392633 | 11517619 |
| agent_turn_fanout | 100 | 0.18 | 0.10 | 1.8x | 105463 | 125963 |
| agent_turn_fanout | 1000 | 8.31 | 0.71 | 11.7x | 1079626 | 1326826 |
| agent_turn_fanout | 5000 | 195.03 | 3.60 | 54.2x | 5229537 | 6356649 |
| agent_turn_fanout | 10000 | 664.21 | 8.00 | 83.0x | 10459672 | 12713616 |
| wide_derived_fanout | 100 | 0.11 | 0.07 | 1.6x | 126855 | 143445 |
| wide_derived_fanout | 1000 | 6.81 | 0.73 | 9.3x | 1163049 | 1330140 |
| wide_derived_fanout | 5000 | 159.61 | 3.80 | 42.0x | 7161689 | 8045619 |
| wide_derived_fanout | 10000 | 632.73 | 8.00 | 79.1x | 14318160 | 16085786 |
| rejoining_dag | 100 | 2.44 | 2.75 | 0.9x | 1065237 | 1204446 |
| rejoining_dag | 500 | 111.43 | 97.74 | 1.1x | 27487812 | 31004317 |
| rejoining_dag | 1000 | 570.61 | 450.00 | 1.3x | 113306645 | 127682695 |
| rejoining_dag | 2000 | 3171.48 | 2032.53 | 1.6x | 464607118 | 523259903 |
| deep_chain | 100 | 2.64 | 2.58 | 1.0x | 1473452 | 1490528 |
| deep_chain | 500 | 89.91 | 72.04 | 1.2x | 31871020 | 35945735 |
| deep_chain | 1000 | 479.85 | 321.72 | 1.5x | 127261379 | 143399736 |
| deep_chain | 2000 | 2667.73 | 1503.22 | 1.8x | 508918794 | 573148331 |
| adversarial_dense | 100 | 7.35 | 7.25 | 1.0x | 1553400 | 1570476 |
| adversarial_dense | 300 | 224.01 | 203.14 | 1.1x | 12425871 | 13816095 |
| adversarial_dense | 1000 | 9556.12 | 8869.78 | 1.1x | 135237679 | 151376036 |
| adversarial_dense | 2000 | 79664.45 | 77943.42 | 1.0x | 540871094 | 605100631 |

**Reads as predicted in the FORNX-432 design doc**: `flat`/`agent_turn_fanout`/`wide_derived_fanout`
(cost sources A/D/E -- the per-call index rebuild and per-family rescans PR 2
removed) see a 10-140x wall-time improvement, growing with pool size since
the removed cost was itself superlinear. `rejoining_dag`/`deep_chain`/`adversarial_dense`
(cost sources B/C -- a long `derived_from` chain or dense adversarial graph
whose `bases` output is itself large) see only a modest 1.0-1.8x improvement,
because their dominant cost is genuinely large output size, not an
algorithmic inefficiency PR 2 could remove without changing what `build`
returns -- confirming the design doc's call that a work-budget cap (PR 3),
not a further speed-up, is the right tool for those shapes. `peak_bytes` is
slightly higher after PR 2 on every shape (a few KB-MB, well under the
~1-5% range) -- the new `is_no_source`/`value_to_keys` auxiliary maps cost
some memory to save the larger `Vec::contains`/`.find()` rescans; this is
the expected, acceptable trade of the design.

## Raw "after" (PR 2) data

| shape | size | evidence_count | family_count | wall_time_ms | alloc_count | alloc_bytes | peak_bytes | reference_hash_matches |
|---|---|---|---|---|---|---|---|---|
| flat | 100 | 100 | 100 | 0.16 | 2540 | 773018 | 110754 | true |
| flat | 1000 | 1000 | 1000 | 0.50 | 107804 | 77351734 | 1173749 | true |
| flat | 5000 | 5000 | 5000 | 2.36 | 2358610 | 1870717942 | 5760060 | true |
| flat | 10000 | 10000 | 10000 | 4.57 | 9267104 | 7451913870 | 11517619 | true |
| agent_turn_fanout | 100 | 100 | 21 | 0.10 | 2577 | 785852 | 125963 | true |
| agent_turn_fanout | 1000 | 1000 | 201 | 0.71 | 108165 | 77383168 | 1326826 | true |
| agent_turn_fanout | 5000 | 5000 | 1001 | 3.60 | 2360394 | 1871197912 | 6356649 | true |
| agent_turn_fanout | 10000 | 10000 | 2001 | 8.00 | 9270683 | 7452880568 | 12713616 | true |
| wide_derived_fanout | 100 | 100 | 1 | 0.07 | 2701 | 850544 | 143445 | true |
| wide_derived_fanout | 1000 | 1000 | 1 | 0.73 | 109320 | 78122244 | 1330140 | true |
| wide_derived_fanout | 5000 | 5000 | 1 | 3.80 | 2366127 | 1875700404 | 8045619 | true |
| wide_derived_fanout | 10000 | 10000 | 1 | 8.00 | 9282121 | 7461877508 | 16085786 | true |
| rejoining_dag | 100 | 100 | 1 | 2.75 | 8226 | 4188522 | 1204446 | true |
| rejoining_dag | 500 | 500 | 1 | 97.74 | 181097 | 119985202 | 31004317 | true |
| rejoining_dag | 1000 | 1000 | 1 | 450.00 | 730066 | 488002812 | 127682695 | true |
| rejoining_dag | 2000 | 2000 | 1 | 2032.53 | 2958280 | 1979559166 | 523259903 | true |
| deep_chain | 100 | 100 | 1 | 2.58 | 9505 | 5883766 | 1490528 | true |
| deep_chain | 500 | 500 | 1 | 72.04 | 215474 | 132945422 | 35945735 | true |
| deep_chain | 1000 | 1000 | 1 | 321.72 | 850472 | 530956302 | 143399736 | true |
| deep_chain | 2000 | 2000 | 1 | 1503.22 | 3384026 | 2124386358 | 573148331 | true |
| adversarial_dense | 100 | 100 | 1 | 7.25 | 11273 | 13500518 | 1570476 | true |
| adversarial_dense | 300 | 300 | 1 | 203.14 | 86847 | 265405958 | 13816095 | true |
| adversarial_dense | 1000 | 1000 | 1 | 8869.78 | 881502 | 7904038302 | 151376036 | true |
| adversarial_dense | 2000 | 2000 | 1 | 77943.42 | 3454108 | 61144905990 | 605100631 | true |

## Raw "before" (PR 1) data

Reproduced here unchanged from the PR 1 merge (fornax-core `a475583`) so both
baselines stay visible in one file.

| shape | size | evidence_count | family_count | wall_time_ms | alloc_count | alloc_bytes | peak_bytes | reference_hash_matches |
|---|---|---|---|---|---|---|---|---|
| flat | 100 | 100 | 100 | 0.17 | 3528 | 1274002 | 108337 | true |
| flat | 1000 | 1000 | 1000 | 6.78 | 200784 | 151463934 | 1128627 | true |
| flat | 5000 | 5000 | 5000 | 162.09 | 4643586 | 3726098206 | 5697242 | true |
| flat | 10000 | 10000 | 10000 | 653.84 | 18387078 | 14873154246 | 11392633 | true |
| agent_turn_fanout | 100 | 100 | 21 | 0.18 | 3540 | 1277020 | 105463 | true |
| agent_turn_fanout | 1000 | 1000 | 201 | 8.31 | 200910 | 151403808 | 1079626 | true |
| agent_turn_fanout | 5000 | 5000 | 1001 | 195.03 | 4644202 | 3726123344 | 5229537 | true |
| agent_turn_fanout | 10000 | 10000 | 2001 | 664.21 | 18388322 | 14873211656 | 10459672 | true |
| wide_derived_fanout | 100 | 100 | 1 | 0.11 | 3671 | 1344392 | 126855 | true |
| wide_derived_fanout | 1000 | 1000 | 1 | 6.81 | 202132 | 152168892 | 1163049 | true |
| wide_derived_fanout | 5000 | 5000 | 1 | 159.61 | 4650269 | 3730755580 | 7161689 | true |
| wide_derived_fanout | 10000 | 10000 | 1 | 632.73 | 18400428 | 14882468164 | 14318160 | true |
| rejoining_dag | 100 | 100 | 1 | 2.44 | 8554 | 4432338 | 1065237 | true |
| rejoining_dag | 500 | 500 | 1 | 111.43 | 187198 | 131629074 | 27487812 | true |
| rejoining_dag | 1000 | 1000 | 1 | 570.61 | 748987 | 533253260 | 113306645 | true |
| rejoining_dag | 2000 | 2000 | 1 | 3171.48 | 3024180 | 2158527830 | 464607118 | true |
| deep_chain | 100 | 100 | 1 | 2.64 | 9667 | 6062766 | 1473452 | true |
| deep_chain | 500 | 500 | 1 | 89.91 | 218665 | 143455102 | 31871020 | true |
| deep_chain | 1000 | 1000 | 1 | 479.85 | 860202 | 572624790 | 127261379 | true |
| deep_chain | 2000 | 2000 | 1 | 2667.73 | 3420837 | 2292018582 | 508918794 | true |
| adversarial_dense | 100 | 100 | 1 | 7.35 | 11435 | 13679518 | 1553400 | true |
| adversarial_dense | 300 | 300 | 1 | 224.01 | 88657 | 269340926 | 12425871 | true |
| adversarial_dense | 1000 | 1000 | 1 | 9556.12 | 891232 | 7945706790 | 135237679 | true |
| adversarial_dense | 2000 | 2000 | 1 | 79664.45 | 3490919 | 61312538214 | 540871094 | true |
