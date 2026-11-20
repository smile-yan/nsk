//! `run` subcommand implementation (§ Phase 13).

use std::io::Read;
use std::sync::Arc;

use nsk_core::error::SandboxError;
use nsk_core::result::SandboxStatus;
use nsk_core::spec::{CommandSpec, SandboxSpec, StdinSpec, WorkspaceSpec};
use nsk_provider::traits::SandboxProvider;
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder};

/// Execution outcome classification for the process exit code.
pub fn exit_code_for(status: SandboxStatus) -> i32 {
    match status {
        SandboxStatus::Success => 0,
        SandboxStatus::NonZeroExit => 2,
        SandboxStatus::TimeLimitExceeded
        | SandboxStatus::CpuLimitExceeded
        | SandboxStatus::MemoryLimitExceeded
        | SandboxStatus::ProcessLimitExceeded
        | SandboxStatus::OutputLimitExceeded
        | SandboxStatus::DiskLimitExceeded => 3,
        SandboxStatus::Cancelled => 130,
        SandboxStatus::SpawnFailed
        | SandboxStatus::IsolationFailed
        | SandboxStatus::ResourceLimitUnavailable
        | SandboxStatus::InternalError => 4,
    }
}

/// Build the runtime for a chosen provider.
pub async fn build_runtime(
    provider: Arc<dyn SandboxProvider>,
) -> Result<Arc<dyn SandboxRuntime>, SandboxError> {
    Ok(Arc::new(
        SandboxRuntimeBuilder::new()
            .with_provider(provider)
            .build()
            .await?,
    ))
}

/// Build a spec from CLI options.
#[allow(clippy::too_many_arguments)]
pub fn build_spec(
    executable: String,
    args: Vec<String>,
    profile: &str,
    wall_time_override: Option<u64>,
    memory_mb_override: Option<u64>,
    pids_override: Option<u32>,
    stdin_file: Option<String>,
    stdin_str: Option<String>,
    keep_workspace: bool,
    env: Vec<(String, String)>,
) -> Result<SandboxSpec, SandboxError> {
    let mut policy = match profile {
        "strict" => nsk_core::policy::SandboxPolicy::strict(),
        "extended" => nsk_core::policy::SandboxPolicy::extended(),
        _ => nsk_core::policy::SandboxPolicy::minimal(),
    };
    if let Some(secs) = wall_time_override {
        policy.resources.wall_time = std::time::Duration::from_secs(secs);
    }
    if let Some(mb) = memory_mb_override {
        policy.resources.memory_bytes = mb * 1024 * 1024;
    }
    if let Some(pids) = pids_override {
        policy.resources.max_processes = pids;
        policy.process.max_processes = pids;
    }

    let stdin = if let Some(file) = stdin_file {
        let bytes = std::fs::read(&file)
            .map_err(|e| SandboxError::Internal(format!("cannot read stdin file {file}: {e}")))?;
        StdinSpec::Bytes(bytes)
    } else if let Some(s) = stdin_str {
        StdinSpec::Bytes(s.into_bytes())
    } else {
        StdinSpec::Closed
    };

    let mut spec = SandboxSpec::new(CommandSpec::new(executable).args(args).stdin_bytes(
        match stdin {
            StdinSpec::Bytes(b) => b,
            StdinSpec::Closed => Vec::new(),
        },
    ));
    spec.workspace = WorkspaceSpec {
        root: Default::default(),
        writable_paths: Default::default(),
        readonly_paths: Default::default(),
        cleanup_on_exit: !keep_workspace,
    };
    for (k, v) in env {
        spec.environment = spec.environment.with(k, v);
    }
    spec.policy = policy;
    Ok(spec)
}

/// Relax the isolation policy for providers that cannot provide it
/// (explicit `--no-isolation` / mock provider path; loudly warned by main).
pub fn relax_isolation(spec: &mut SandboxSpec) {
    spec.policy.isolation = nsk_core::policy::IsolationPolicy {
        isolate_process: false,
        isolate_filesystem: false,
        isolate_network: false,
        isolate_ipc: false,
        isolate_uts: false,
    };
    spec.policy.filesystem.isolate_root = false;
    spec.policy.filesystem.deny_host_paths = false;
    spec.policy.security.no_new_privileges = false;
    spec.policy.security.drop_privileges = false;
    spec.policy.security.require_user_namespace = false;
    spec.policy.security.require_cgroup = false;
}

/// Run a program inside the sandbox; returns the CLI exit code.
pub async fn run(
    runtime: Arc<dyn SandboxRuntime>,
    spec: SandboxSpec,
    json: bool,
) -> Result<i32, SandboxError> {
    // SIGINT → sandbox cancel.
    let cancel_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("[nsk] SIGINT received — cancelling sandbox");
        }
    });
    let result = tokio::select! {
        r = runtime.execute(spec) => r,
        _ = cancel_task => {
            return Ok(130);
        }
    }?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&*result).unwrap_or_default()
        );
    } else {
        crate::report::print_result_summary(&result);
    }
    Ok(exit_code_for(result.status))
}

/// Read stdin passthrough bytes from the actual process stdin when requested.
#[allow(dead_code)]
pub fn read_stdin_bytes() -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    match std::io::stdin().read_to_end(&mut buf) {
        Ok(0) => None,
        Ok(_) => Some(buf),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn exit_code_classification() {
        assert_eq!(exit_code_for(SandboxStatus::Success), 0);
        assert_eq!(exit_code_for(SandboxStatus::NonZeroExit), 2);
        assert_eq!(exit_code_for(SandboxStatus::TimeLimitExceeded), 3);
        assert_eq!(exit_code_for(SandboxStatus::MemoryLimitExceeded), 3);
        assert_eq!(exit_code_for(SandboxStatus::Cancelled), 130);
        assert_eq!(exit_code_for(SandboxStatus::IsolationFailed), 4);
    }

    #[test]
    fn spec_building() {
        let spec = build_spec(
            "/bin/echo".into(),
            vec!["hi".into()],
            "strict",
            Some(3),
            Some(64),
            Some(4),
            None,
            None,
            false,
            vec![("A".into(), "B".into())],
        )
        .expect("spec");
        assert_eq!(
            spec.policy.resources.wall_time,
            std::time::Duration::from_secs(3)
        );
        assert_eq!(spec.policy.resources.memory_bytes, 64 * 1024 * 1024);
        assert_eq!(spec.policy.process.max_processes, 4);
        assert_eq!(spec.command.args.len(), 1);
        assert_eq!(spec.environment.variables.len(), 1);
        assert!(spec.workspace.cleanup_on_exit);
    }

    #[tokio::test]
    async fn run_end_to_end_mock() {
        let provider = nsk_provider::create_mock_provider();
        // Relax isolation like the CLI's --no-isolation would.
        let mut spec = build_spec(
            "/bin/echo".into(),
            vec!["cli-test".into()],
            "minimal",
            None,
            None,
            None,
            None,
            None,
            false,
            vec![],
        )
        .unwrap();
        relax_isolation(&mut spec);
        let runtime = build_runtime(provider).await.unwrap();
        let code = run(runtime, spec, false).await.unwrap();
        assert_eq!(code, 0);
    }
}
