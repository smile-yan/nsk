//! Windows Job Object integration tests (§16.3/§16.4 applied to Windows).
//!
//! These run **only on Windows** (the windows CI job) and verify the real
//! mechanism stack: suspended spawn + job assignment, resource limits,
//! whole-tree termination, accounting and cleanup.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::result::SandboxStatus;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_provider_windows::WindowsProvider;
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder};

async fn build_runtime() -> Option<Arc<dyn SandboxRuntime>> {
    if !cfg!(windows) {
        eprintln!("skipping: not a Windows host");
        return None;
    }
    let provider: Arc<dyn nsk_provider::traits::SandboxProvider> = Arc::new(WindowsProvider::new());
    let caps = provider.probe().await.unwrap();
    if !caps.resources.job_objects.is_available() {
        eprintln!("skipping: Job Objects not verified functional on this host");
        return None;
    }
    Some(Arc::new(
        SandboxRuntimeBuilder::new()
            .with_provider(provider)
            .build()
            .await
            .unwrap(),
    ))
}

/// Policy compatible with what the Windows provider can actually provide:
/// Job Object limits; no fs/network isolation.
fn windows_policy() -> SandboxPolicy {
    let mut p = SandboxPolicy::minimal();
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
    p
}

fn spec(cmd: CommandSpec) -> SandboxSpec {
    let mut spec = SandboxSpec::new(cmd);
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = windows_policy();
    spec
}

#[tokio::test]
async fn job_limited_echo_runs() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let result = rt
        .execute(spec(
            CommandSpec::new("cmd.exe").args(["/C", "echo", "jobbed"]),
        ))
        .await
        .unwrap();
    assert_eq!(result.status, SandboxStatus::Success);
    assert!(result.output.stdout.text().contains("jobbed"));
}

#[tokio::test]
async fn whole_tree_termination_on_wall_time() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let mut s = spec(CommandSpec::new("cmd.exe").args(["/C", "ping", "-n", "30", "127.0.0.1"]));
    s.policy.resources.wall_time = Duration::from_millis(700);
    let started = std::time::Instant::now();
    let result = rt.execute(s).await.unwrap();
    assert_eq!(result.status, SandboxStatus::TimeLimitExceeded);
    // The supervisor + job must have stopped the tree promptly.
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "termination took too long: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn memory_limit_stops_hungry_child() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    // PowerShell allocates well above the commit limit; the job memory
    // limit makes the allocation fail (exit != 0) and peak usage stays
    // bounded.
    let mut s = spec(CommandSpec::new("powershell.exe").args([
        "-NoProfile",
        "-Command",
        "$b = New-Object byte[] (600MB); Start-Sleep -Seconds 30",
    ]));
    s.policy.resources.wall_time = Duration::from_secs(30);
    s.policy.resources.memory_bytes = 128 * 1024 * 1024;
    let result = rt.execute(s).await.unwrap();
    assert_ne!(
        result.status,
        SandboxStatus::Success,
        "a 600MB allocation under a 128MB commit limit must fail"
    );
    let peak = result.resource_usage.memory_peak_bytes.unwrap_or(0);
    assert!(
        peak <= 512 * 1024 * 1024,
        "job peak memory must stay bounded near the limit (observed {peak})"
    );
}

#[tokio::test]
async fn active_process_limit_blocks_children() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    // start /WAIT propagates the child's result; under ActiveProcessLimit
    // = 1 the child cannot join the job, `start` fails, and cmd reports a
    // non-zero exit. (A trailing `& exit 0` would mask the failure.)
    let mut s = spec(CommandSpec::new("cmd.exe").args(["/C", "start /WAIT /B cmd /C exit 0"]));
    s.policy.resources.wall_time = Duration::from_secs(20);
    s.policy.resources.max_processes = 1;
    s.policy.process.max_processes = 1;
    let result = rt.execute(s).await.unwrap();
    assert_ne!(
        result.status,
        SandboxStatus::Success,
        "spawning a child beyond the active-process limit must fail"
    );
}

#[tokio::test]
async fn usage_accounting_is_collected() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let result = rt
        .execute(spec(CommandSpec::new("cmd.exe").args(["/C", "echo", "hi"])))
        .await
        .unwrap();
    assert_eq!(result.status, SandboxStatus::Success);
    // CPU time and IO accounting come from the Job Object.
    assert!(
        result.resource_usage.cpu_time.is_some(),
        "job accounting must provide cpu_time"
    );
    assert!(
        result.resource_usage.disk_usage_bytes.is_some(),
        "job accounting must provide io counters"
    );
}

#[tokio::test]
async fn strict_profile_is_refused_on_windows() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let mut s = spec(CommandSpec::new("cmd.exe").args(["/C", "echo", "hi"]));
    s.policy = SandboxPolicy::strict();
    let err = rt.execute(s).await.expect_err("strict must be refused");
    assert!(matches!(
        err,
        nsk_core::error::SandboxError::CapabilityInsufficient { .. }
    ));
}
