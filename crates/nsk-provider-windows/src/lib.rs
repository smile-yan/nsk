//! # nsk-provider-windows
//!
//! Windows provider — **Job Objects MVP** (design document §11, phase 15).
//!
//! Windows has no namespaces, cgroups or POSIX rlimits; §11 prescribes an
//! independent security design instead of copying Linux semantics. This
//! MVP implements the pieces whose boundaries are well-defined and
//! verifiable, and reports everything else honestly:
//!
//! * **Job Objects** ([`job`], §11.3): process-set containment, preventive
//!   per-tree limits (memory commit, active process count, CPU rate hard
//!   limit), UI restrictions, and whole-tree termination
//!   (`TerminateJobObject`, `KILL_ON_JOB_CLOSE` backstop). The child is
//!   created `CREATE_SUSPENDED` and resumed only *after* job assignment —
//!   no escape window for grandchildren.
//! * **Restricted Token** ([`token`], §11.4): the token machinery
//!   (duplicate → `DISABLE_MAX_PRIVILEGE`) is implemented and verified by
//!   the probe; creating processes *with* the token is not wired into the
//!   spawn path in the MVP, so `privilege_dropping` reports
//!   `NotConfigured` — the child keeps the caller's privileges.
//! * **AppContainer** ([`appcontainer`], §11.5): detection facts only;
//!   profile-creation machinery stays out until real security validation
//!   confirms the isolation boundary (§11.5 requirement).
//!
//! Fail-closed rules (§2.4):
//! * filesystem/network isolation requested → refused by the Policy Engine
//!   (Job Objects provide neither, §11.3);
//! * Job Objects unavailable/broken → refused by the Policy Engine
//!   (memory/process limits have no fallback mechanism on Windows);
//! * probed on a non-Windows host → everything `Unsupported`, `prepare`
//!   refuses.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod limits;
pub mod probe;

#[cfg(windows)]
pub mod appcontainer;
#[cfg(windows)]
pub mod job;
#[cfg(windows)]
pub mod token;

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use nsk_core::capability::PlatformCapabilities;
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::result::ResourceUsage;
use nsk_provider::traits::{
    ExecutionPlan, PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox,
    SandboxProvider, SpawnContext,
};

/// `CREATE_SUSPENDED`: the supervisor spawns the child suspended so the
/// provider can place it under the Job Object before its first instruction.
#[cfg(windows)]
pub const CREATE_SUSPENDED: u32 = 0x0000_0004;

/// Windows provider (Job Objects MVP).
#[derive(Debug, Default, Clone)]
pub struct WindowsProvider {
    probe_cache: Arc<tokio::sync::OnceCell<PlatformCapabilities>>,
}

impl WindowsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Capabilities, probed once per provider instance.
    pub async fn capabilities(&self) -> Result<PlatformCapabilities, SandboxError> {
        let caps = self
            .probe_cache
            .get_or_init(|| async move {
                if cfg!(windows) {
                    crate::probe::probe_capabilities().await
                } else {
                    crate::probe::probe_capabilities_off_host()
                }
            })
            .await
            .clone();
        Ok(caps)
    }

    /// Build the execution plan + job limits (unit-testable core).
    fn build_execution_plan(
        &self,
        ctx: &PrepareContext,
    ) -> Result<(ExecutionPlan, limits::JobLimits), SandboxError> {
        let spec = &ctx.spec;
        let policy = &ctx.policy;
        let r = &policy.requested.resources;

        // Host paths are used verbatim (Job Objects do not remap paths);
        // canonicalize the workspace + working directory for determinism.
        let workspace_root = ctx.workspace.root.clone();
        let cwd = spec.working_directory(&workspace_root).to_path_buf();

        // Explicit environment whitelist (never the host env, §5.4).
        // SystemRoot/COMSPEC are required by cmd.exe and the loader.
        let mut env: Vec<(String, String)> = vec![
            ("SystemRoot".into(), "C:\\Windows".into()),
            ("windir".into(), "C:\\Windows".into()),
            ("PATH".into(), "C:\\Windows\\System32;C:\\Windows".into()),
            ("COMSPEC".into(), "C:\\Windows\\system32\\cmd.exe".into()),
        ];
        let tmp = workspace_root.join("tmp");
        if std::fs::create_dir_all(&tmp).is_ok() {
            env.push(("TEMP".into(), tmp.display().to_string()));
            env.push(("TMP".into(), tmp.display().to_string()));
        }
        for var in &spec.environment.variables {
            env.retain(|(k, _)| k != &var.key);
            env.push((var.key.clone(), var.value.clone()));
        }

        // The executable may be bare (cmd resolves via PATH); record it as
        // given. Args are passed through (no shell interpretation).
        let mut argv = vec![spec.command.executable.display().to_string()];
        for a in &spec.command.args {
            argv.push(a.to_string_lossy().to_string());
        }

        // No rlimits on Windows; NOFILE/FSIZE have no mechanism and the
        // resolver records them Unsupported (never claimed as enforced).

        let cpu_quota = policy
            .applied
            .resources
            .iter()
            .find(|l| l.kind == nsk_policy::effective::LimitKind::CpuQuota)
            .and_then(|l| l.effective.as_ref())
            .and_then(|s| s.split(' ').next()?.parse::<f64>().ok());

        let job_limits = limits::JobLimits::from_policy(
            r.memory_bytes,
            r.max_processes,
            cpu_quota,
            true, // UI restrictions: clipboard/handles/global atoms/exit
        );

        let plan = ExecutionPlan {
            argv,
            cwd: Some(cwd),
            env,
            stdin: spec.command.stdin.clone(),
            process_group: false,
            rlimits: Vec::new(),
        };
        Ok((plan, job_limits))
    }
}

/// Resources owned by a running Windows sandbox.
#[derive(Debug)]
pub struct WindowsResources {
    pub id: nsk_core::id::SandboxId,
    /// Present on Windows hosts: the managed job object.
    #[cfg(windows)]
    pub job: Option<job::JobObject>,
    /// Idempotency for the non-Windows path (which never creates resources).
    #[cfg(not(windows))]
    pub _unused: (),
}

impl ProviderResources for WindowsResources {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn attach(&self, pid: u32) -> Result<(), SandboxError> {
        #[cfg(windows)]
        {
            if let Some(job) = &self.job {
                // SAFETY: OpenProcess handle is closed on all paths below.
                unsafe {
                    let proc_handle = crate::job::open_process_for_job(pid)?;
                    let result = job.assign(proc_handle);
                    crate::job::close_process_handle(proc_handle);
                    result?;
                }
                // Resume the suspended child now that it is contained.
                let resumed = crate::job::resume_process_threads(pid)?;
                debug!(pid, resumed, "process assigned to job object and resumed");
            }
        }
        let _ = pid;
        Ok(())
    }

    fn kill_all(&self) -> Result<(), SandboxError> {
        #[cfg(windows)]
        {
            if let Some(job) = &self.job {
                // Empty jobs may fail to terminate; treat as success.
                let _ = job.terminate();
            }
        }
        Ok(())
    }

    fn observe_usage(&self) -> Result<ResourceUsage, SandboxError> {
        #[cfg(windows)]
        {
            if let Some(job) = &self.job {
                return job.observe_usage();
            }
        }
        Ok(ResourceUsage::default())
    }

    fn cleanup(&self) -> Result<Vec<Diagnostic>, SandboxError> {
        #[cfg(windows)]
        {
            if let Some(job) = &self.job {
                // Kill first, then close (KILL_ON_JOB_CLOSE is the backstop
                // for crashes; explicit close makes cleanup deterministic).
                let _ = job.terminate();
                job.close();
            }
        }
        Ok(Vec::new())
    }
}

#[async_trait]
impl SandboxProvider for WindowsProvider {
    fn name(&self) -> &'static str {
        "windows"
    }

    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError> {
        self.capabilities().await
    }

    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError> {
        let caps = self.capabilities().await?;
        let mut diagnostics: Vec<Diagnostic> = Vec::new();

        if !caps.resources.job_objects.is_available() {
            // Fail closed: memory/process limits have no other mechanism.
            return Err(SandboxError::CapabilityInsufficient {
                code: codes::RESOURCE_LIMIT_UNAVAILABLE.to_string(),
                message: "Job Objects are not verified functional on this host; refusing to \
                          spawn (memory/process limits would be unenforced)"
                    .into(),
            });
        }
        if caps.resources.job_objects.is_available() && std::env::consts::OS != "windows" {
            // Defensive: provider selected off-host.
            return Err(SandboxError::Provider {
                provider: "windows".into(),
                message: "the Windows provider only runs on Windows hosts".into(),
            });
        }

        let (plan, job_limits) = self.build_execution_plan(&ctx)?;
        debug!(sandbox = %ctx.id, limits = %job_limits.describe(), "windows sandbox prepared");

        #[cfg(windows)]
        let job = Some(crate::job::JobObject::create(job_limits)?);
        #[cfg(not(windows))]
        let _ = job_limits;

        for d in &caps.diagnostics {
            if d.code == codes::CAPABILITY_UNVERIFIED {
                diagnostics.push(d.clone());
            }
        }
        if diagnostics.is_empty() {
            diagnostics.push(Diagnostic::info(
                codes::CAPABILITY_UNVERIFIED,
                "MVP scope: Job Object limits + whole-tree termination only; \
                 no filesystem/network isolation (§11.3) and no privilege reduction yet (§11.4)",
            ));
        }

        Ok(PreparedSandbox {
            id: ctx.id,
            provider_name: self.name(),
            plan,
            resources: Some(Arc::new(WindowsResources {
                id: ctx.id,
                #[cfg(windows)]
                job,
                #[cfg(not(windows))]
                _unused: (),
            })),
        })
    }

    async fn spawn(
        &self,
        prepared: PreparedSandbox,
        ctx: SpawnContext,
    ) -> Result<RunningSandbox, SandboxError> {
        #[cfg(not(windows))]
        {
            let _ = (prepared, ctx);
            return Err(SandboxError::Provider {
                provider: "windows".into(),
                message: "the Windows provider cannot spawn on non-Windows hosts".into(),
            });
        }

        #[cfg(windows)]
        {
            let mut process_spec = prepared.plan.clone().into_process_spec();
            // Child starts suspended: it is placed under the Job Object
            // (attach) before its first instruction runs.
            process_spec.creation_flags = CREATE_SUSPENDED;

            let process = nsk_supervisor::monitor::spawn(
                process_spec,
                nsk_provider::traits::supervisor_config(&ctx.policy, ctx.events),
            )?;

            // Attach to the job object (assign + resume); fail closed on
            // error (kill + cancel first).
            if let Some(res) = &prepared.resources {
                if let Err(e) = res.attach(process.pid()) {
                    let _ = res.kill_all();
                    process.cancel();
                    return Err(e);
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
    }

    async fn terminate(&self, running: &RunningSandbox) -> Result<(), SandboxError> {
        // Job kill first (whole tree, strongest), supervisor escalation as
        // backup.
        if let Some(res) = &running.resources {
            let _ = res.kill_all();
        }
        running
            .process
            .terminate(nsk_supervisor::terminate::TerminateKind::External);
        Ok(())
    }

    async fn collect_usage(&self, running: &RunningSandbox) -> Result<ResourceUsage, SandboxError> {
        if let Some(res) = &running.resources {
            res.observe_usage()
        } else {
            Ok(ResourceUsage::default())
        }
    }

    async fn cleanup(
        &self,
        resources: Option<Arc<dyn ProviderResources>>,
    ) -> Result<Vec<Diagnostic>, SandboxError> {
        match resources {
            Some(res) => res.cleanup(),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use nsk_core::capability::CapabilityStatus;
    use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};

    fn provider() -> WindowsProvider {
        WindowsProvider::new()
    }

    /// Windows-compatible policy: no fs/network isolation, limits intact.
    fn windows_policy() -> nsk_core::policy::SandboxPolicy {
        let mut p = nsk_core::policy::SandboxPolicy::minimal();
        p.isolation = nsk_core::policy::IsolationPolicy {
            isolate_process: false,
            isolate_filesystem: false,
            isolate_network: false,
            isolate_ipc: false,
            isolate_uts: false,
        };
        p.filesystem.isolate_root = false;
        p.filesystem.deny_host_paths = false;
        p.security.no_new_privileges = false;
        p
    }

    fn spec_with(policy: nsk_core::policy::SandboxPolicy) -> SandboxSpec {
        let mut s = SandboxSpec::new(CommandSpec::new("cmd.exe"));
        s.workspace = WorkspaceSpec::ephemeral();
        s.policy = policy;
        s
    }

    #[tokio::test]
    async fn probe_is_cached() {
        let p = provider();
        let a = p.probe().await.unwrap();
        let b = p.probe().await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn probe_is_honest() {
        let caps = provider().probe().await.unwrap();
        assert_eq!(caps.platform, nsk_core::capability::Platform::Windows);
        if cfg!(windows) {
            assert_eq!(caps.resources.job_objects, CapabilityStatus::Available);
            assert_eq!(
                caps.isolation.filesystem_isolation,
                CapabilityStatus::Unsupported
            );
            assert_eq!(
                caps.isolation.network_isolation,
                CapabilityStatus::Unsupported
            );
            assert_eq!(
                caps.security.privilege_dropping,
                CapabilityStatus::NotConfigured
            );
        } else {
            assert_eq!(caps.resources.job_objects, CapabilityStatus::Unsupported);
        }
    }

    #[tokio::test]
    async fn isolation_requesting_policy_is_refused_by_resolver() {
        let caps = provider().probe().await.unwrap();
        let err = nsk_policy::effective::resolve(
            &spec_with(nsk_core::policy::SandboxPolicy::minimal()),
            &caps,
        )
        .expect_err("minimal requests fs/network isolation — must be refused");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }

    #[tokio::test]
    async fn prepare_builds_plan_and_job_limits() {
        if !cfg!(windows) {
            return;
        }
        let caps = provider().probe().await.unwrap();
        let spec = spec_with(windows_policy());
        let eff = nsk_policy::effective::resolve(&spec, &caps).unwrap();
        let ws = nsk_workspace::manager::WorkspaceManager::with_defaults()
            .prepare(&spec.workspace, &spec.id)
            .unwrap();
        let prepared = provider()
            .prepare(PrepareContext {
                id: spec.id,
                spec,
                policy: Arc::new(eff),
                workspace: Arc::new(ws),
            })
            .await
            .expect("prepare must succeed on Windows");

        let argv0 = prepared.plan.argv[0].to_lowercase();
        assert!(argv0.contains("cmd"));
        assert!(prepared.plan.env.iter().any(|(k, _)| k == "SystemRoot"));
        // Resources carry a live job object.
        let res = prepared.resources.expect("resources");
        assert!(res.as_any().downcast_ref::<WindowsResources>().is_some());
    }

    #[tokio::test]
    async fn prepare_refuses_off_host() {
        if cfg!(windows) {
            return;
        }
        let caps = provider().probe().await.unwrap();
        let spec = spec_with(windows_policy());
        let err = nsk_policy::effective::resolve(&spec, &caps)
            .expect_err("no mechanism at all — resolver must refuse");
        assert!(matches!(err, SandboxError::ResourceLimit(_)));
    }
}
