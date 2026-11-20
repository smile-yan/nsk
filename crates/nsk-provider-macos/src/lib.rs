//! # nsk-provider-macos
//!
//! macOS provider — **fail-closed stub** (design document §12).
//!
//! macOS is explicitly out of scope for phase 1 development. This crate
//! exists so the workspace builds on macOS hosts and so the factory, CLI
//! and diagnostics can report honest capability data instead of pretending.
//!
//! * `probe` reports what is factually known (no namespace mechanisms, no
//!   phase-1 isolation launcher; rlimits exist, process-group kills work).
//! * `prepare` always fails closed: never run an isolation-requesting
//!   policy as a plain host process (§2.4).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;

use async_trait::async_trait;
use nsk_core::capability::{
    CapabilityStatus, IsolationCapabilities, Platform, PlatformCapabilities, ResourceCapabilities,
    SecurityCapabilities, ToolInfo,
};
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::result::ResourceUsage;
use nsk_provider::traits::{
    PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox, SandboxProvider,
    SpawnContext,
};

/// macOS provider stub.
#[derive(Debug, Default, Clone)]
pub struct MacOSProvider;

impl MacOSProvider {
    pub fn new() -> Self {
        Self
    }
}

/// No provider resources are ever created by this stub.
#[derive(Debug)]
pub struct MacOSResources;

impl ProviderResources for MacOSResources {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait]
impl SandboxProvider for MacOSProvider {
    fn name(&self) -> &'static str {
        "macos"
    }

    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError> {
        Ok(PlatformCapabilities {
            platform: Platform::MacOS,
            isolation: IsolationCapabilities {
                user_namespace: CapabilityStatus::Unsupported,
                mount_namespace: CapabilityStatus::Unsupported,
                pid_namespace: CapabilityStatus::Unsupported,
                network_namespace: CapabilityStatus::Unsupported,
                ipc_namespace: CapabilityStatus::Unsupported,
                uts_namespace: CapabilityStatus::Unsupported,
                launcher: ToolInfo {
                    name: "none".into(),
                    status: CapabilityStatus::Unsupported,
                    ..Default::default()
                },
            },
            resources: ResourceCapabilities {
                cgroup_v2: CapabilityStatus::Unsupported,
                controllers: nsk_core::capability::CgroupControllers::unsupported(),
                rlimits: CapabilityStatus::Available,
                process_tree_kill: CapabilityStatus::Available,
                disk_quota: CapabilityStatus::Unsupported,
            },
            security: SecurityCapabilities {
                seccomp: CapabilityStatus::Unsupported,
                no_new_privileges: CapabilityStatus::Unsupported,
                privilege_dropping: CapabilityStatus::Unsupported,
            },
            diagnostics: vec![
                Diagnostic::info(
                    codes::CAPABILITY_UNAVAILABLE,
                    "macOS provider is a fail-closed stub in phase 1; no isolation is provided",
                ),
                Diagnostic::info(
                    codes::CAPABILITY_UNVERIFIED,
                    "Seatbelt (sandbox-exec) is deprecated by Apple and unverified; see docs/macos-provider.md",
                ),
            ],
        })
    }

    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError> {
        Err(SandboxError::CapabilityInsufficient {
            code: codes::ISOLATION_FAILED.to_string(),
            message: format!(
                "macOS provider cannot satisfy the requested isolation policy (sandbox {}): \
                 no phase-1 isolation mechanism exists; use Linux for isolated execution or \
                 the explicit mock provider for tests",
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
            message: "macOS provider cannot spawn: no isolation".into(),
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
        let caps = MacOSProvider::new().probe().await.unwrap();
        assert_eq!(caps.platform, Platform::MacOS);
        assert_eq!(
            caps.isolation.mount_namespace,
            CapabilityStatus::Unsupported
        );
        assert_eq!(caps.resources.rlimits, CapabilityStatus::Available);
        assert_eq!(caps.diagnostics.len(), 2);
    }

    #[tokio::test]
    async fn prepare_fails_closed() {
        use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
        use std::sync::Arc as StdArc;
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        spec.workspace = WorkspaceSpec::ephemeral();
        let caps = MacOSProvider::new().probe().await.unwrap();

        // The Policy Engine already refuses isolation-requesting policies on
        // this platform (defense in depth happens before the provider).
        let resolve_err = nsk_policy::effective::resolve(&spec, &caps)
            .expect_err("resolve must fail closed on macOS");
        assert!(matches!(
            resolve_err,
            SandboxError::CapabilityInsufficient { .. }
        ));

        // Even if a policy slipped through, prepare() must still refuse.
        let eff = {
            let mut policy = nsk_core::policy::SandboxPolicy::minimal();
            policy.isolation = nsk_core::policy::IsolationPolicy {
                isolate_process: false,
                isolate_filesystem: false,
                isolate_network: false,
                isolate_ipc: false,
                isolate_uts: false,
            };
            policy.filesystem.isolate_root = false;
            policy.filesystem.deny_host_paths = false;
            policy.security.no_new_privileges = false;
            policy.security.drop_privileges = false;
            spec.policy = policy;
            nsk_policy::effective::resolve(&spec, &caps).unwrap()
        };

        let ws = nsk_workspace::manager::WorkspaceManager::with_defaults()
            .prepare(&spec.workspace, &spec.id)
            .unwrap();
        let ctx = PrepareContext {
            id: spec.id,
            spec,
            policy: StdArc::new(eff),
            workspace: StdArc::new(ws),
        };
        let err = MacOSProvider::new()
            .prepare(ctx)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }
}
