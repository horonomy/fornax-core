# Registering an external configuration adapter

External adapters are data-only manifest registrations managed by
`fornax adapter register`. After the review and digest-confirmation steps,
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
the index. Schema version 1 is also accepted, while newer versions fail
closed.

Inspection re-reads only the Fornax-owned registry index and the selected
owned manifest copy. It never opens the recorded source path or the manifest's
target file. The source path is retained display metadata. A digest match
confirms that the owned bytes match the local registry pin; it does not prove
publisher identity, code trust, host installation, or native host observation.
The manifest declares configuration operations only and does not supply an
executable driver.

External inspection uses held directory descriptors and no-follow,
nonblocking regular-file reads on Unix. Other platforms report
`inspection_platform_unsupported`; they do not silently follow links.

Configuration IDs that are valid under the external manifest rules but do
not fit the narrower host-adapter SPI namespace are preserved exactly in
`result.registration.id`; the envelope's `adapter_id` is `null` and reports
`config_id_outside_host_spi_namespace`.
