Byte-identical copies of the golden egress-projection fixtures owned by
horonomy/fornax-cloud PR #138 (`crates/fornax-uploader/tests/fixtures/egress-projection/`,
branch `v0.0.9/FORNX-464/fix/uploader_egress_guard`, head bbbbc50).

sha256:
- unconfigured.json bb086fdf129fe1247b2e1a3ec9b8c4ab421a528fa843d8272addf9a5c96a4ce3
- personal.json f6f11c47a3f1af37e1f7e07c620ce8535dc1aed75eee7aeeeb1500b01c510154
- corporate.json 27b17fca5330c5fb08d2fd7a629ef3d97d70f58af4f5fc900902c978a21fde60

`corporate.json` lists an authorization for a corporate profile on purpose:
the uploader must refuse it. Core never emits that shape; only the
`unconfigured` and `personal` fixtures are compared byte-for-byte.
