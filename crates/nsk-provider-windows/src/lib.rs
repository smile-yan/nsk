//! # nsk-provider-windows
//!
//! Windows provider — **fail-closed stub** (design document §11).
//!
//! Windows is explicitly out of scope for phase 1 development. The crate
//! builds on every platform so the workspace and diagnostics stay coherent.
//! The future design direction (Job Objects + Restricted Token +
//! AppContainer) is documented in `docs/windows-provider.md`.
//!
//! `prepare` always fails closed: never run an isolation-requesting policy
//! as a plain host process (§2.4).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;

use async_trait::async_trait;
use nsk_core::capability::{
    CapabilityStatus, IsolationCapabilities, Platform, PlatformCapabilities, ResourceCapabilities,
    SecurityCapabilities,
};
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::result::ResourceUsage;
use nsk_provider::traits::{
    PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox, SandboxProvider,
    SpawnContext,
};

/// Windows provider stub.
#[derive(Debug, Default, Clone)]
pub struct WindowsProvider;

impl WindowsProvider {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug)]
pub struct WindowsResources;

impl ProviderResources for WindowsResources {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait]
impl SandboxProvider for WindowsProvider {
    fn name(&self) -> &'static str {
        "windows"
    }

    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError> {
        Ok(PlatformCapabilities {
            platform: Platform::Windows,
            isolation: IsolationCapabilities::unsupported(),
            resources: ResourceCapabilities {
                cgroup_v2: CapabilityStatus::Unsupported,
                controllers: nsk_core::capability::CgroupControllers::unsupported(),
                // No POSIX rlimits on Windows; Job Objects are the planned
                // mechanism and are not implemented in phase 1.
                rlimits: CapabilityStatus::Unsupported,
                process_tree_kill: CapabilityStatus::Available, // Job Objects concept proven by OS
                disk_quota: CapabilityStatus::Unsupported,
            },
            security: SecurityCapabilities::unsupported(),
            diagnostics: vec![Diagnostic::info(
                codes::CAPABILITY_UNAVAILABLE,
                "Windows provider is a fail-closed stub in phase 1; Job Objects / Restricted Token / AppContainer are future work",
            )],
        })
    }

    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError> {
        Err(SandboxError::CapabilityInsufficient {
            code: codes::ISOLATION_FAILED.to_string(),
            message: format!(
                "Windows provider cannot satisfy the requested isolation policy (sandbox {}): \
                 phase-1 stub; use Linux for isolated execution or the explicit mock provider for tests",
                ctx.id
            ),
        })
    }

    async fn spawn(
        &self,
        _prepared: PreparedSandbox,
        _ctx: SpawnContext,
    ) -> Result<RunningSandbox, SandboxError> {
        Err(SandboxError::CapabilityInsufficient {
            code: codes::ISOLATION_FAILED.to_string(),
            message: "Windows provider cannot spawn: no isolation".into(),
        })
    }

    async fn terminate(&self, _running: &RunningSandbox) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn collect_usage(
        &self,
        _running: &RunningSandbox,
    ) -> Result<ResourceUsage, SandboxError> {
        Ok(ResourceUsage::default())
    }

    async fn cleanup(
        &self,
        _resources: Option<Arc<dyn ProviderResources>>,
    ) -> Result<Vec<Diagnostic>, SandboxError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_is_honest() {
        let caps = WindowsProvider::new().probe().await.unwrap();
        assert_eq!(caps.platform, Platform::Windows);
        assert_eq!(caps.resources.rlimits, CapabilityStatus::Unsupported);
        assert_eq!(caps.diagnostics.len(), 1);
    }
}
