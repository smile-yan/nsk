//! Provider trait and typed lifecycle handles (§9.1, §9.2).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use nsk_core::capability::PlatformCapabilities;
use nsk_core::error::SandboxError;
use nsk_core::id::SandboxId;
use nsk_core::result::ResourceUsage;
use nsk_core::spec::SandboxSpec;
use nsk_policy::EffectivePolicy;
use nsk_supervisor::process::{ProcessSpec, SupervisedProcess};
use nsk_workspace::manager::PreparedWorkspace;

/// The concrete command plan the supervisor will execute.
///
/// Providers translate the effective policy into this plan (§9.1:
/// "Effective Policy → OS Execution"). For the Linux provider the argv is a
/// bubblewrap command line; for the mock provider it is the raw command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Full argv, including any launcher prefix.
    pub argv: Vec<String>,
    /// Host-side working directory (usually the workspace root).
    pub cwd: Option<PathBuf>,
    /// Explicit environment whitelist for the launcher/child.
    pub env: Vec<(String, String)>,
    pub stdin: nsk_core::spec::StdinSpec,
    /// Run as process-group leader (required for tree termination).
    pub process_group: bool,
    /// rlimits applied pre-exec.
    pub rlimits: Vec<nsk_resource::limits::RlimitSpec>,
}

impl ExecutionPlan {
    /// Convert into a supervisor `ProcessSpec`.
    pub fn into_process_spec(self) -> ProcessSpec {
        let mut spec = ProcessSpec::new(OsString::from(&self.argv[0]));
        for a in &self.argv[1..] {
            spec = spec.arg(a);
        }
        if let Some(cwd) = &self.cwd {
            spec = spec.cwd(cwd);
        }
        for (k, v) in &self.env {
            spec = spec.env(k, v);
        }
        spec.stdin(self.stdin.clone()).rlimits(self.rlimits.clone())
        // process_group stays at its default (true) for tree kills.
    }
}

/// Inputs a provider receives during preparation (§9.2 `prepare`).
#[derive(Debug, Clone)]
pub struct PrepareContext {
    pub id: SandboxId,
    pub spec: SandboxSpec,
    pub policy: Arc<EffectivePolicy>,
    pub workspace: Arc<PreparedWorkspace>,
}

/// Inputs for spawning a prepared sandbox.
#[derive(Debug, Clone)]
pub struct SpawnContext {
    /// Effective policy: the source of supervisor enforcement values
    /// (wall-time deadline, output caps, termination rules).
    pub policy: Arc<EffectivePolicy>,
    /// Event tap bridging supervisor output into the sandbox event stream.
    pub events: Option<tokio::sync::broadcast::Sender<nsk_supervisor::output::SupervisorEvent>>,
}

/// A prepared sandbox: isolation resources exist, process not started.
#[derive(Debug, Clone)]
pub struct PreparedSandbox {
    pub id: SandboxId,
    pub provider_name: &'static str,
    pub plan: ExecutionPlan,
    /// Provider-owned resources (cgroup handle, seccomp fd, …).
    pub resources: Option<Arc<dyn ProviderResources>>,
}

/// A running sandbox: the supervised process plus provider resources.
#[derive(Debug, Clone)]
pub struct RunningSandbox {
    pub id: SandboxId,
    pub provider_name: &'static str,
    pub process: Arc<SupervisedProcess>,
    pub resources: Option<Arc<dyn ProviderResources>>,
    pub started_at: std::time::Instant,
}

/// Provider-owned resources needing deterministic teardown (§9.2).
///
/// Implementations must make `cleanup` idempotent and never panic.
pub trait ProviderResources: Send + Sync + std::fmt::Debug {
    /// Downcast support for crate-local resource types.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Attach the process to provider resources (e.g. write cgroup.procs).
    fn attach(&self, pid: u32) -> Result<(), SandboxError> {
        let _ = pid;
        Ok(())
    }

    /// Kill all processes under provider control (e.g. cgroup.kill).
    /// Must be idempotent.
    fn kill_all(&self) -> Result<(), SandboxError> {
        Ok(())
    }

    /// Observe current usage from provider mechanisms (may be empty).
    fn observe_usage(&self) -> Result<ResourceUsage, SandboxError> {
        Ok(ResourceUsage::default())
    }

    /// Release provider resources; returns diagnostics for anything that
    /// could not be freed. Must be idempotent.
    fn cleanup(&self) -> Result<Vec<nsk_core::diagnostic::Diagnostic>, SandboxError> {
        Ok(Vec::new())
    }
}

/// Build the supervisor configuration from an effective policy (§8.2).
///
/// Single translation point from policy values to supervisor enforcement so
/// every provider applies identical wall-time, output and termination rules.
pub fn supervisor_config(
    policy: &EffectivePolicy,
    tap: Option<tokio::sync::broadcast::Sender<nsk_supervisor::output::SupervisorEvent>>,
) -> nsk_supervisor::monitor::SupervisorConfig {
    let output = &policy.requested.output;
    let resources = &policy.requested.resources;
    let retain_per_stream = output
        .max_stdout_bytes
        .min(output.max_stderr_bytes)
        .min(1024 * 1024) as usize;
    nsk_supervisor::monitor::SupervisorConfig {
        deadline: Some(nsk_supervisor::timer::Deadline::after(resources.wall_time)),
        max_stdout: output.max_stdout_bytes,
        max_stderr: output.max_stderr_bytes,
        max_combined: output.combined_limit_bytes,
        terminate_on_limit: output.terminate_on_limit,
        retain_per_stream,
        tap,
        ..Default::default()
    }
}

/// Platform provider trait (§9.2).
///
/// The lifecycle is: `probe` → `prepare` → `spawn` → (`terminate`) →
/// `collect` → `cleanup`. Providers must be fail-closed: when a required
/// isolation mechanism cannot be established, `prepare` or `spawn` must
/// return an error — never degrade silently.
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    /// Provider name for diagnostics ("linux", "mock", …).
    fn name(&self) -> &'static str;

    /// Detect platform capabilities. May be cached by the caller.
    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError>;

    /// Build the isolation environment and the execution plan.
    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError>;

    /// Spawn the process described by the plan.
    async fn spawn(
        &self,
        prepared: PreparedSandbox,
        ctx: SpawnContext,
    ) -> Result<RunningSandbox, SandboxError>;

    /// Terminate the whole sandbox (process tree + provider resources).
    async fn terminate(&self, running: &RunningSandbox) -> Result<(), SandboxError>;

    /// Collect current resource usage (provider mechanisms only).
    async fn collect_usage(&self, running: &RunningSandbox) -> Result<ResourceUsage, SandboxError>;

    /// Release all provider resources; must be idempotent.
    async fn cleanup(
        &self,
        resources: Option<Arc<dyn ProviderResources>>,
    ) -> Result<Vec<nsk_core::diagnostic::Diagnostic>, SandboxError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_to_process_spec() {
        let plan = ExecutionPlan {
            argv: vec!["/bin/sh".into(), "-c".into(), "echo hi".into()],
            cwd: Some(PathBuf::from("/tmp")),
            env: vec![("A".into(), "1".into())],
            stdin: nsk_core::spec::StdinSpec::Closed,
            process_group: true,
            rlimits: vec![nsk_resource::limits::RlimitSpec::OpenFiles(64)],
        };
        let spec = plan.into_process_spec();
        assert_eq!(spec.argv.len(), 3);
        assert_eq!(spec.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(spec.rlimits.len(), 1);
        assert!(spec.process_group);
    }

    #[test]
    fn default_resources_are_noop() {
        let r: Box<dyn ProviderResources> = Box::new(NoopRes);
        assert!(r.attach(1).is_ok());
        assert!(r.kill_all().is_ok());
        assert!(r.observe_usage().is_ok());
        assert!(r.cleanup().unwrap().is_empty());
    }

    #[derive(Debug)]
    struct NoopRes;

    impl ProviderResources for NoopRes {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
}
