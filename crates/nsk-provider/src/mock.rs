//! Mock provider (§ Phase 3: Mock Provider).
//!
//! **Not a security boundary.** The mock provider executes the requested
//! program directly on the host with supervisor-level enforcement only
//! (wall time, output limits, rlimits, process-group termination). Its
//! capability report honestly advertises `Unsupported` for every isolation
//! mechanism, so the Policy Engine refuses any policy that requests
//! isolation.
//!
//! Use cases: unit/integration tests of the kernel lifecycle, and kernel
//! development on platforms whose real providers are not implemented yet.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

#[cfg(target_os = "macos")]
use std::sync::Arc as StdArc;

use nsk_core::capability::{
    CapabilityStatus, IsolationCapabilities, Platform, PlatformCapabilities, ResourceCapabilities,
    SecurityCapabilities, ToolInfo,
};
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::id::SandboxId;
use nsk_core::result::ResourceUsage;
use nsk_policy::validate::validate_spec;
use nsk_resource::limits::RlimitSpec;

use crate::traits::{
    ExecutionPlan, PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox,
    SandboxProvider, SpawnContext,
};

/// Test/dev provider without isolation.
#[derive(Debug, Default, Clone)]
pub struct MockProvider;

impl MockProvider {
    pub fn new() -> Self {
        Self
    }
}

/// Resources held by a mock sandbox (watchdog evidence on macOS; the
/// supervisor owns everything else).
#[derive(Debug)]
pub struct MockResources {
    pub id: SandboxId,
    #[cfg(target_os = "macos")]
    pub evidence: StdArc<nsk_supervisor::watchdog::WatchdogEvidence>,
}

impl ProviderResources for MockResources {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn observe_usage(&self) -> Result<ResourceUsage, SandboxError> {
        #[cfg(target_os = "macos")]
        let usage = {
            let (oom, pids, peak) = self.evidence.snapshot();
            Ok(ResourceUsage {
                oom_events: oom,
                pids_limit_hits: pids,
                memory_peak_bytes: peak,
                ..Default::default()
            })
        };
        #[cfg(not(target_os = "macos"))]
        let usage = Ok(ResourceUsage::default());
        usage
    }
}

/// Arm the supervisor watchdogs when the applied policy selected them as
/// the enforcing mechanism (macOS: no preventive rung exists).
#[cfg(target_os = "macos")]
fn arm_watchdogs(
    policy: &nsk_policy::EffectivePolicy,
    process: &nsk_supervisor::process::SupervisedProcess,
    evidence: StdArc<nsk_supervisor::watchdog::WatchdogEvidence>,
) {
    use nsk_supervisor::watchdog::{WatchdogConfig, WatchdogLimits, spawn_watchdog};
    let r = &policy.requested.resources;
    let memory = policy
        .applied
        .resources
        .iter()
        .any(|l| {
            l.kind == nsk_policy::effective::LimitKind::Memory
                && l.status.is_available()
                && l.mechanism
                    .as_deref()
                    .is_some_and(|m| m.contains("watchdog"))
        })
        .then_some(r.memory_bytes);
    let processes = (policy.applied.process.enforced_by.contains("watchdog"))
        .then_some(policy.requested.process.max_processes.max(1));
    let limits = WatchdogLimits {
        memory_bytes: memory,
        max_processes: processes,
    };
    if limits.is_armed() {
        spawn_watchdog(
            process.pid(),
            process.clone(),
            limits,
            evidence,
            WatchdogConfig::default(),
        );
    }
}

#[async_trait]
impl SandboxProvider for MockProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError> {
        let capabilities = PlatformCapabilities {
            platform: Platform::current(),
            isolation: IsolationCapabilities {
                user_namespace: CapabilityStatus::Unsupported,
                mount_namespace: CapabilityStatus::Unsupported,
                pid_namespace: CapabilityStatus::Unsupported,
                network_namespace: CapabilityStatus::Unsupported,
                ipc_namespace: CapabilityStatus::Unsupported,
                uts_namespace: CapabilityStatus::Unsupported,
                filesystem_isolation: CapabilityStatus::Unsupported,
                network_isolation: CapabilityStatus::Unsupported,
                launcher: ToolInfo {
                    name: "none (mock provider)".into(),
                    status: CapabilityStatus::Unsupported,
                    ..Default::default()
                },
            },
            resources: ResourceCapabilities {
                cgroup_v2: CapabilityStatus::Unsupported,
                controllers: nsk_core::capability::CgroupControllers::unsupported(),
                rlimits: CapabilityStatus::Available,
                // RLIMIT_AS is unusable on macOS (setrlimit EINVAL, not
                // enforced by XNU); RLIMIT_NPROC is per-user there.
                rlimit_address_space: if cfg!(target_os = "macos") {
                    CapabilityStatus::Unsupported
                } else {
                    CapabilityStatus::Available
                },
                rlimit_processes: if cfg!(target_os = "macos") {
                    CapabilityStatus::Unsupported
                } else {
                    CapabilityStatus::Available
                },
                job_objects: CapabilityStatus::Unsupported,
                // On macOS the mock enforces memory/process limits through
                // the supervisor watchdogs (no rlimit mechanism exists).
                memory_watchdog: if cfg!(target_os = "macos") {
                    CapabilityStatus::Available
                } else {
                    CapabilityStatus::Unsupported
                },
                process_watchdog: if cfg!(target_os = "macos") {
                    CapabilityStatus::Available
                } else {
                    CapabilityStatus::Unsupported
                },
                process_tree_kill: CapabilityStatus::Available,
                disk_quota: CapabilityStatus::Unsupported,
            },
            security: SecurityCapabilities {
                seccomp: CapabilityStatus::Unsupported,
                no_new_privileges: CapabilityStatus::Unsupported,
                privilege_dropping: CapabilityStatus::Unsupported,
            },
            diagnostics: vec![Diagnostic::warning(
                codes::CAPABILITY_UNAVAILABLE,
                "mock provider performs NO isolation; for tests and kernel development only",
            )],
        };
        Ok(capabilities)
    }

    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError> {
        // Full validation runs again (defense in depth); the Policy Engine
        // already ran during `create`, and capability matching will have
        // refused isolation-requesting policies.
        validate_spec(&ctx.spec)?;

        warn!(
            id = %ctx.id,
            "mock provider: spawning WITHOUT isolation on the host"
        );

        let spec = &ctx.spec;
        let plan = ExecutionPlan {
            argv: {
                let mut v = vec![spec.command.executable.display().to_string()];
                v.extend(
                    spec.command
                        .args
                        .iter()
                        .map(|a| a.to_string_lossy().to_string()),
                );
                v
            },
            cwd: Some(spec.working_directory(&ctx.workspace.root).to_path_buf()),
            env: spec
                .environment
                .variables
                .iter()
                .map(|v| (v.key.clone(), v.value.clone()))
                .collect(),
            stdin: spec.command.stdin.clone(),
            process_group: true,
            rlimits: mock_rlimits(&spec.policy),
        };

        Ok(PreparedSandbox {
            id: ctx.id,
            provider_name: self.name(),
            plan,
            resources: Some(Arc::new(MockResources {
                id: ctx.id,
                #[cfg(target_os = "macos")]
                evidence: StdArc::new(nsk_supervisor::watchdog::WatchdogEvidence::default()),
            })),
        })
    }

    async fn spawn(
        &self,
        prepared: PreparedSandbox,
        ctx: SpawnContext,
    ) -> Result<RunningSandbox, SandboxError> {
        let process = nsk_supervisor::monitor::spawn(
            prepared.plan.clone().into_process_spec(),
            crate::traits::supervisor_config(&ctx.policy, ctx.events),
        )?;
        #[cfg(target_os = "macos")]
        if let Some(res) = &prepared.resources {
            if let Some(mock_res) = res.as_ref().as_any().downcast_ref::<MockResources>() {
                arm_watchdogs(&ctx.policy, &process, mock_res.evidence.clone());
            }
        }
        Ok(RunningSandbox {
            id: prepared.id,
            provider_name: prepared.provider_name,
            process: Arc::new(process),
            resources: prepared.resources,
            started_at: std::time::Instant::now(),
        })
    }

    async fn terminate(&self, running: &RunningSandbox) -> Result<(), SandboxError> {
        // Supervisor escalation (SIGTERM → SIGKILL group) — mock has no
        // stronger mechanism; do not fake one.
        running
            .process
            .terminate(nsk_supervisor::terminate::TerminateKind::External);
        Ok(())
    }

    async fn collect_usage(
        &self,
        _running: &RunningSandbox,
    ) -> Result<ResourceUsage, SandboxError> {
        // No provider mechanisms: honest empty usage (supervisor numbers are
        // merged by the runtime).
        Ok(ResourceUsage::default())
    }

    async fn cleanup(
        &self,
        _resources: Option<Arc<dyn ProviderResources>>,
    ) -> Result<Vec<Diagnostic>, SandboxError> {
        Ok(Vec::new())
    }
}

/// rlimits the mock can honestly enforce via the supervisor.
fn mock_rlimits(policy: &nsk_core::policy::SandboxPolicy) -> Vec<RlimitSpec> {
    let r = &policy.resources;
    let mut specs = vec![
        RlimitSpec::OpenFiles(r.max_open_files),
        RlimitSpec::FileSize(r.max_file_size_bytes),
    ];
    // RLIMIT_AS/NPROC are unusable on macOS (see capability report).
    if !cfg!(target_os = "macos") {
        specs.push(RlimitSpec::AddressSpace(r.memory_bytes));
        specs.push(RlimitSpec::Processes(u64::from(r.max_processes)));
    }
    specs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_reports_no_isolation_honestly() {
        let caps = MockProvider::new().probe().await.expect("probe");
        assert_eq!(caps.isolation.pid_namespace, CapabilityStatus::Unsupported);
        assert_eq!(caps.resources.rlimits, CapabilityStatus::Available);
        assert!(!caps.diagnostics.is_empty());
        assert!(caps.diagnostics[0].message.contains("NO isolation"));
    }

    #[tokio::test]
    async fn isolation_requesting_policy_is_refused_before_prepare() {
        // The provider itself doesn't check capabilities (the Policy Engine
        // does), but prepare re-validates the spec. The runtime's resolve()
        // is the fail-closed gate; here we assert the resolve step.
        use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = nsk_core::policy::SandboxPolicy::minimal();

        let caps = MockProvider::new().probe().await.unwrap();
        let err = nsk_policy::effective::resolve(&spec, &caps).expect_err("must refuse");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }
}
