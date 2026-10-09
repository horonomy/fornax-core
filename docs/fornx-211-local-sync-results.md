# FORNX-211 — local-sync capacity harness, first measured results

First slice only: local-sync leg (adapter intake → `fornax-daemon` UDS →
`fornax-store`), measured against the SLI/SLO FORNX-210 §1 defines (p99 <
500ms event-arrival to durable-commit). Ingest/processing/SaaS load paths
need their own harness against deployed Cloud Run/Pub/Sub infra — out of
scope here, tracked as FORNX-211 follow-up work.

Tool: `crates/fornax-load-harness` (`fornax-load-harness` binary). Runs
against a real `fornax-daemon` process with an isolated `$FORNAX_HOME`
(own socket, own sqlite file) — never a real user daemon. Submits synthetic
`AgentEvent`s over the real UDS ingest path, polls `fornax-store` for the
durable row, reports percentile latency, throughput, and sqlite/WAL growth.

## Run 1 — steady (one event at a time, 300 events)

```json
{
  "profile": "steady",
  "requested_count": 300,
  "submitted": 300,
  "committed": 300,
  "budget_events_lost_or_late": 0,
  "p50_ms": 11.15,
  "p90_ms": 20.44,
  "p99_ms": 82.83,
  "max_ms": 192.99,
  "throughput_events_per_sec": 67.83,
  "wall_clock_ms": 4423,
  "db_bytes_before": 4096,
  "db_bytes_after": 569344,
  "wal_bytes_after": 4865752
}
```

## Run 2 — burst (50 concurrent events per burst, 300 total, same daemon instance continued)

```json
{
  "profile": "burst",
  "requested_count": 300,
  "submitted": 300,
  "committed": 300,
  "budget_events_lost_or_late": 0,
  "p50_ms": 83.30,
  "p90_ms": 148.95,
  "p99_ms": 175.23,
  "max_ms": 179.54,
  "throughput_events_per_sec": 322.58,
  "wall_clock_ms": 930,
  "db_bytes_before": 569344,
  "db_bytes_after": 811008,
  "wal_bytes_after": 4865752
}
```

## Reading

- **FORNX-210's p99 < 500ms target: met** in both profiles (82.8ms steady,
  175.2ms burst) on this reference machine (Apple Silicon dev laptop, debug
  build, no other heavy local load) — matches the SLO doc's own caveat that
  the target was not yet measured against anything until this harness
  existed.
- **Zero error-budget events** (lost/late commits) in either run. This is
  one data point, not a soak result — a longer/larger run is the natural
  next slice (see Known limitations).
- Burst p99 (175ms) is ~2x steady p99 (83ms) — consistent with
  `AppState::processing`'s global mutex (see `fornax-daemon/src/main.rs`'s
  `run_uds_server` doc comment) serializing concurrent submissions rather
  than processing them in parallel. Expected, not a defect — flagging for
  FORNX-212 (backpressure) since this is the first real evidence of how
  that serialization behaves under concurrent load, not just by code
  inspection.
- `debug` build only (not `--release`) — these numbers are not a release
  capacity claim, only a first baseline. A release-profile run is the
  natural next measurement before FORNX-434's SCALE READY gate treats any
  number here as load-bearing.

## Known limitations (explicit, not silently dropped)

- **300 events, not a true soak.** The harness's `soak` profile exists and
  uses identical mechanics to `steady`, but a multi-hour run (the shape
  that would actually expose a leak) was not run this pass — flagged as
  FORNX-211 follow-up, not claimed here.
- **Debug build, single machine, no concurrent system load** — no DB
  saturation or resource-exhaustion scenario exercised yet (that's this
  same harness run at much higher count/concurrency, plus
  resource-monitoring instrumentation this pass doesn't have).
- **Ingest/processing/SaaS paths are untouched.** This only proves the
  local-sync leg; FORNX-210 §2-4's SLOs remain unmeasured.
- Storage growth here (sqlite ~807KB delta, WAL ~4.6MB for 600 events) is a
  first real number for FORNX-213's storage-growth question but is not
  FORNX-213 itself — no retention-sweep/reclamation behavior was exercised
  in this run (`fornax-store`'s `SweepReport` machinery is untouched here).
