# Registering an external adapter

The registry accepts data-only configuration manifests and separately versioned
shared host-adapter descriptors. Both use `fornax adapter register`. After the
review and digest-confirmation steps,
inspect the retained record with either command:

```sh
fornax adapter info <id>
fornax adapter inspect <id> --json
```

`info` and `inspect` use the same read-only view. The JSON form uses CLI
operation-envelope v1 with operation `inspect`. A disabled or rejected
registration remains inspectable so the operator can see its state and a
bounded reason. An unknown id, or an unreadable, malformed, unsupported, or
oversized registry fails with a stable reason code.

Some delivered S6 registrations contain `schema_version: 0` because the
original writer persisted the default value. Inspection preserves that
record and reports `legacy_registry_schema_version_zero`; it does not rewrite
the index. An omitted version is reported as omitted with effective legacy version 1.
Version 1 and the closed version 2 format are supported; later versions fail
closed. Inspection never migrates storage.

Inspection re-reads only the Fornax-owned registry index and the selected
owned manifest copy. It never opens the recorded source path or the manifest's
target file. The source path is retained display metadata. A digest match
confirms that the owned bytes match the local registry pin; it does not prove
publisher identity, code trust, host installation, or native host observation.
A configuration manifest declares configuration operations only and does not
supply an executable driver. A host descriptor may declare executable paths and
runtime-file pins; inspection does not open, hash, or execute those paths.

External inspection uses held directory descriptors and no-follow,
nonblocking regular-file reads on Unix. Other platforms report
a platform-unsupported reason; they do not silently follow links.

Configuration IDs that are valid under the external manifest rules but do
not fit the narrower host-adapter SPI namespace are preserved exactly in
`result.registration.id`; the envelope's `adapter_id` is `null` and reports
`config_id_outside_host_spi_namespace`.

## Host descriptor registration

Use the existing shared host-adapter manifest, with top-level
`manifest_kind: "host-adapter"`. Its ID is runtime data; no new CLI command or
built-in host table entry is required. Review the exact source bytes first:

```sh
fornax adapter register --manifest ./host-adapter.json --json
fornax adapter register --manifest ./host-adapter.json --confirm-digest <reviewed-digest> --json
fornax adapter list --json
fornax adapter inspect <adapter-id> --json
```

Review creates no registry state. Confirmation registers the descriptor bytes
only, initially disabled. It neither installs a host integration nor grants
permission to run code. Until the separate execution boundary is available,
host descriptor enablement refuses with `execution_boundary_unavailable`, and
configuration-driver commands refuse this registration kind. A valid future-only
protocol or contract declaration remains inspectable as incompatible.

The first confirmed host descriptor upgrades the existing index to version 2,
retaining configuration metadata and owned manifest bytes. Stop older Fornax
mutators before confirming this storage upgrade. Version 2 keeps its root marker
after the last host registration is removed, so older readers refuse it rather
than silently interpreting an empty index. Registration IDs share one global
namespace across both kinds and built-ins.

Descriptor ingestion is bounded locally: 1 MiB, 32 container levels and 16,384
JSON value nodes. The shared embedded configuration-schema profile remains
bounded to 64 KiB, 16 levels and 4,096 nodes. Each numeric token is limited to
4,096 bytes and an exponent to 128 raw digits. These are explicit local capacity
refusals, not claims that a declaration is semantically invalid. Inspection's
metadata projection omits the inline schema and labels any display truncation;
registration pins the original bytes without rounding arbitrary schema numbers.

Upgraded mutators share one stable kernel lock. It coordinates cooperating
writers, not older binaries or arbitrary same-user file replacements. Atomic
index publication is the registration commit point; a later verification failure
reports committed but unverified state and never retries or rolls back silently.
The operation does not claim crash atomicity across the descriptor and index.
