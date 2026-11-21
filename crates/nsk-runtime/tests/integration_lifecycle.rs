//! End-to-end lifecycle integration tests over the mock provider
//! (§16.3 Integration Tests, runnable on any Unix host).
//!
//! All tests share ONE multi-thread tokio runtime: a SIGCHLD handler is
//! process-global, and per-test runtimes contend for it under parallel load,
//! which can make `Child::wait()` lose exit notifications and hang.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use nsk_core::policy::IsolationPolicy;
use nsk_core::result::SandboxStatus;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_core::state::SandboxState;
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("global test runtime")
    })
    .block_on(fut)
}

/// Policy compatible with the mock provider (no isolation requested).
fn relaxed_policy() -> nsk_core::policy::SandboxPolicy {
    let mut p = nsk_core::policy::SandboxPolicy::minimal();
    p.isolation = IsolationPolicy {
        isolate_process: false,
        isolate_filesystem: false,
        isolate_network: false,
        isolate_ipc: false,
        isolate_uts: false,
    };
    p.filesystem.isolate_root = false;
    p.filesystem.deny_host_paths = false;
    p.security.no_new_privileges = false;
    p.security.drop_privileges = false;
    // The mock provider applies policy rlimits to real spawns, and
    // RLIMIT_NPROC counts *all* processes of the uid — CI runner job users
    // already exceed minimal()'s default of 16, making any fork inside the
    // sandboxed shell fail (EAGAIN). These tests do not exercise process
    // limits, so grant a generous budget.
    p.resources.max_processes = 1024;
    p.process.max_processes = 1024;
    p
}

fn echo_spec(args: &[&str]) -> SandboxSpec {
    let mut spec =
        SandboxSpec::new(CommandSpec::new("/bin/echo").args(args.iter().map(|s| s.to_string())));
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = relaxed_policy();
    spec
}

async fn build_runtime() -> Arc<dyn SandboxRuntime> {
    Arc::new(
        SandboxRuntimeBuilder::new()
            .with_provider(nsk_provider::create_mock_provider())
            .build()
            .await
            .expect("runtime"),
    )
}

#[test]
fn execute_echo_success() {
    block_on(async {
        let rt = build_runtime().await;
        let result = rt
            .execute(echo_spec(&["hello world"]))
            .await
            .expect("execute");
        assert_eq!(result.status, SandboxStatus::Success);
        assert_eq!(result.exit_info.as_ref().unwrap().exit_code, Some(0));
        assert_eq!(result.output.stdout.retained, b"hello world\n");
        assert_eq!(result.output.stdout.total_bytes, 12);
    });
}

#[test]
fn execute_nonzero_exit() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sh").arg("-c").arg("exit 7"));
        spec.policy = relaxed_policy();
        let result = rt.execute(spec).await.expect("execute");
        assert_eq!(result.status, SandboxStatus::NonZeroExit);
        assert_eq!(result.exit_info.as_ref().unwrap().exit_code, Some(7));
    });
}

#[test]
fn stdin_bytes_flow_to_cat() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec =
            SandboxSpec::new(CommandSpec::new("/bin/cat").stdin_bytes(b"stdin-payload".to_vec()));
        spec.policy = relaxed_policy();
        let result = rt.execute(spec).await.expect("execute");
        assert_eq!(result.status, SandboxStatus::Success);
        assert_eq!(result.output.stdout.retained, b"stdin-payload");
    });
}

#[test]
fn environment_whitelist_only() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec =
            SandboxSpec::new(CommandSpec::new("/usr/bin/env")).with_env("NSK_INT_TEST", "42");
        spec.policy = relaxed_policy();
        let result = rt.execute(spec).await.expect("execute");
        let text = result.output.stdout.text();
        assert!(
            text.contains("NSK_INT_TEST=42"),
            "env var must pass: {text}"
        );
        assert!(!text.contains("PATH="), "host env must not leak: {text}");
    });
}

#[test]
fn wall_time_limit_terminates() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(
            CommandSpec::new("/bin/sh")
                .arg("-c")
                .arg("while true; do sleep 1; done"),
        );
        spec.policy = relaxed_policy();
        spec.policy.resources.wall_time = Duration::from_millis(400);
        let result = rt.execute(spec).await.expect("execute");
        assert_eq!(result.status, SandboxStatus::TimeLimitExceeded);
        assert!(result.resource_usage.wall_time >= Duration::from_millis(350));
        assert!(result.resource_usage.wall_time < Duration::from_secs(10));
    });
}

#[test]
fn cancel_running_sandbox() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("30"));
        spec.policy = relaxed_policy();
        let id = rt.create(spec).await.expect("create");
        rt.start(id).await.expect("start");

        tokio::time::sleep(Duration::from_millis(150)).await;
        rt.cancel(id).await.expect("cancel");

        let result = rt.wait(id).await.expect("wait");
        assert_eq!(result.status, SandboxStatus::Cancelled);
    });
}

#[test]
fn output_limit_terminates_yes() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(CommandSpec::new("/usr/bin/yes"));
        spec.policy = relaxed_policy();
        spec.policy.output.max_stdout_bytes = 512 * 1024;
        spec.policy.output.max_stderr_bytes = 512 * 1024;
        spec.policy.output.combined_limit_bytes = 512 * 1024;
        spec.policy.resources.max_output_bytes = 512 * 1024;
        let result = rt.execute(spec).await.expect("execute");
        assert_eq!(result.status, SandboxStatus::OutputLimitExceeded);
        assert!(result.resource_usage.stdout_bytes > 512 * 1024);
        // Retained buffer stays bounded.
        assert!(result.output.stdout.retained.len() <= 512 * 1024);
    });
}

#[test]
fn inspect_reports_states() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("1"));
        spec.policy = relaxed_policy();
        let id = rt.create(spec).await.expect("create");
        let info = rt.inspect(id).await.expect("inspect");
        assert_eq!(info.state, SandboxState::Ready);

        rt.start(id).await.expect("start");
        let info = rt.inspect(id).await.expect("inspect");
        assert!(matches!(
            info.state,
            SandboxState::Starting | SandboxState::Running
        ));

        let result = rt.wait(id).await.expect("wait");
        assert_eq!(result.status, SandboxStatus::Success);

        let info = rt.inspect(id).await.expect("inspect");
        assert_eq!(info.state, SandboxState::Completed);
        assert_eq!(info.status, Some(SandboxStatus::Success));
    });
}

#[test]
fn events_flow_through_lifecycle() {
    block_on(async {
        let rt = build_runtime().await;
        let spec = echo_spec(&["events"]);
        let id = rt.create(spec).await.expect("create");
        let mut rx = rt.subscribe(Some(id));
        rt.start(id).await.expect("start");
        let _ = rt.wait(id).await.expect("wait");

        let mut kinds = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if ev.id == id {
                kinds.push(ev.event.kind().to_string());
            }
        }
        // "created"/"ready" are emitted during create(), i.e. before this
        // test subscribed to the per-entry channel; everything from `start`
        // onward must be observable.
        assert!(kinds.contains(&"started".to_string()), "kinds: {kinds:?}");
        assert!(kinds.contains(&"stdout".to_string()), "kinds: {kinds:?}");
        assert!(kinds.contains(&"exited".to_string()), "kinds: {kinds:?}");
        assert!(
            kinds.contains(&"cleanup_completed".to_string()),
            "kinds: {kinds:?}"
        );
    });
}

#[test]
fn invalid_policy_refused_fail_closed() {
    block_on(async {
        let rt = build_runtime().await;
        // Default minimal policy requests isolation — the mock cannot
        // provide it, so create() must refuse (§2.4 fail-closed).
        let spec = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        let err = rt.create(spec).await.expect_err("must refuse");
        assert!(matches!(
            err,
            nsk_core::error::SandboxError::CapabilityInsufficient { .. }
        ));
    });
}

#[test]
fn unknown_sandbox_errors() {
    block_on(async {
        let rt = build_runtime().await;
        let id = nsk_core::id::SandboxId::new();
        assert!(matches!(
            rt.inspect(id).await.unwrap_err(),
            nsk_core::error::SandboxError::NotFound(_)
        ));
        assert!(matches!(
            rt.cancel(id).await.unwrap_err(),
            nsk_core::error::SandboxError::NotFound(_)
        ));
    });
}

#[test]
fn workspace_artifacts_and_cleanup() {
    block_on(async {
        let rt = Arc::new(
            SandboxRuntimeBuilder::new()
                .with_provider(nsk_provider::create_mock_provider())
                .with_workspace_config(nsk_workspace::manager::WorkspaceManagerConfig {
                    base_dir: Some(std::env::temp_dir().join("nsk-it-workspaces")),
                    ..Default::default()
                })
                .build()
                .await
                .expect("runtime"),
        );
        // Program writes a file into the workspace cwd.
        let mut spec = SandboxSpec::new(
            CommandSpec::new("/bin/sh")
                .arg("-c")
                .arg("echo artifact-content > out.txt; ls"),
        );
        spec.policy = relaxed_policy();
        let result = rt.execute(spec).await.expect("execute");
        assert_eq!(result.status, SandboxStatus::Success);
        // Kernel-managed workspace is removed after execution; stdout shows
        // the artifact listing produced inside the sandbox.
        assert_eq!(result.resource_usage.stdout_bytes, 8); // "out.txt\n"
    });
}

#[test]
fn concurrent_executions() {
    block_on(async {
        let rt = build_runtime().await;
        let mut handles = Vec::new();
        for i in 0..8 {
            let rt = rt.clone();
            handles.push(tokio::spawn(async move {
                let result = rt
                    .execute(echo_spec(&[&format!("task-{i}")]))
                    .await
                    .expect("execute");
                assert_eq!(result.status, SandboxStatus::Success);
                assert!(result.output.stdout.text().contains(&format!("task-{i}")));
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
    });
}
