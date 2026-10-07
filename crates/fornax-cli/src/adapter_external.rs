//! An [`AdapterPlugin`](crate::adapter_registry::AdapterPlugin) backed by a
//! runtime-loaded manifest rather than a compiled-in struct (ADR-0023,
//! FORNX-428 S6). `registry()` holds these behind the exact same trait
//! object type as the built-ins -- nothing downstream of `registry()`
//! (`resolve`, `AdapterArg`, `install`/`uninstall`/`plan`/`doctor`, every
//! `Commands`/`AdapterAction` arm in `main.rs`) needs to know this adapter
//! came from a manifest rather than a struct literal.

use crate::adapter_manifest::AdapterManifest;
use crate::adapter_registry::{AdapterActionResult, AdapterPlugin};
use std::path::PathBuf;

pub struct ExternalAdapter {
    manifest: AdapterManifest,
}

impl ExternalAdapter {
    pub fn new(manifest: AdapterManifest) -> Self {
        Self { manifest }
    }
}

impl AdapterPlugin for ExternalAdapter {
    fn id(&self) -> &str {
        &self.manifest.id
    }

    fn display_name(&self) -> &str {
        &self.manifest.display_name
    }

    fn summary(&self) -> &str {
        &self.manifest.summary
    }

    fn target_path(&self) -> PathBuf {
        self.manifest.target_path.clone()
    }

    fn plan(&self) -> anyhow::Result<AdapterActionResult> {
        anyhow::ensure!(
            self.manifest
                .capabilities
                .contains(&crate::adapter_manifest::Capability::Plan),
            "adapter {:?} does not declare the plan capability",
            self.manifest.id
        );
        crate::adapter_mutate::plan_apply(&self.manifest)
    }

    fn install(&self) -> anyhow::Result<AdapterActionResult> {
        anyhow::ensure!(
            self.manifest
                .capabilities
                .contains(&crate::adapter_manifest::Capability::Install),
            "adapter {:?} does not declare the install capability",
            self.manifest.id
        );
        crate::adapter_mutate::install_at(&self.manifest)
    }

    fn uninstall(&self) -> anyhow::Result<AdapterActionResult> {
        anyhow::ensure!(
            self.manifest
                .capabilities
                .contains(&crate::adapter_manifest::Capability::Uninstall),
            "adapter {:?} does not declare the uninstall capability",
            self.manifest.id
        );
        crate::adapter_mutate::uninstall_at(&self.manifest)
    }
}
