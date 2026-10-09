# FORNX-432 PR 1 — independence-capacity benchmark results

**Synthetic shapes, not a real workload.** See `crates/fornax-bench/src/independence_capacity.rs` module docs for fixture definitions, size caps and the `bench-reference` cross-check. `peak_bytes` is process-wide (this binary's own allocator), reset to the already-outstanding baseline before each run rather than to zero -- see `reset_alloc_counters` in `main.rs`. `wall_time_ms` approximates CPU time: `SourceFamilyMap::build` runs single-threaded.

Per-fixture wall-time budget: 20s (a shape exceeding it skips its remaining larger configured sizes, recorded under Skipped below).

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
