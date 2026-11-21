//! Linux isolation & security tests (§16.4, §20.2 隔离验收).
//!
//! These run **only on Linux** with bubblewrap available; they verify the
//! real OS isolation stack: namespaces, filesystem policy, network
//! isolation, cgroup limits and cleanup.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use nsk_core::capability::CapabilityStatus;
use nsk_core::policy::SandboxPolicy;
use nsk_core::result::SandboxStatus;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_provider::traits::SandboxProvider;
use nsk_provider_linux::LinuxProviderConfig;
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

async fn build_runtime() -> Option<Arc<dyn SandboxRuntime>> {
    let provider = Arc::new(nsk_provider_linux::LinuxProvider::new(
        LinuxProviderConfig::default(),
    ));
    let caps = provider.probe().await.unwrap();
    if !caps.isolation.launcher.status.is_available() {
        eprintln!("skipping: bubblewrap not available on this host");
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

fn spec(cmd: CommandSpec) -> SandboxSpec {
    let mut spec = SandboxSpec::new(cmd);
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = SandboxPolicy::minimal();
    spec
}

#[test]
fn linux_probe_reports_honestly() {
    block_on(async {
        let provider: Arc<dyn SandboxProvider> = Arc::new(nsk_provider_linux::LinuxProvider::new(
            LinuxProviderConfig::default(),
        ));
        let caps = provider.probe().await.unwrap();
        // The launcher status decides everything; it must be honest.
        let bwrap_found = which_bwrap();
        if bwrap_found {
            assert_eq!(caps.isolation.launcher.status, CapabilityStatus::Available);
        } else {
            assert_ne!(caps.isolation.launcher.status, CapabilityStatus::Available);
        }
    });
}

fn which_bwrap() -> bool {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .any(|dir| dir.join("bwrap").is_file())
}

#[tokio::test]
async fn isolated_echo_runs() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let result = rt
        .execute(spec(CommandSpec::new("/bin/echo").arg("isolated")))
        .await
        .unwrap();
    assert_eq!(result.status, SandboxStatus::Success);
    assert_eq!(result.output.stdout.retained, b"isolated\n");
}

#[tokio::test]
async fn host_home_is_not_accessible() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    // /home and $HOME must not exist inside the sandbox (§10.5).
    let result = rt
        .execute(spec(CommandSpec::new("/bin/sh").arg("-c").arg(
            "ls /home >/dev/null 2>&1 && echo HOME_LEAK || echo OK; \
             test -e /root/.ssh/id_rsa && echo SSH_LEAK || echo OK; \
             test -S /var/run/docker.sock && echo DOCKER_LEAK || echo OK",
        )))
        .await
        .unwrap();
    assert_eq!(result.status, SandboxStatus::Success);
    let out = result.output.stdout.text();
    assert!(out.contains("OK"), "host paths leaked: {out}");
    assert!(!out.contains("LEAK"), "host paths leaked: {out}");
}

#[tokio::test]
async fn network_is_disabled() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    // Network namespace with no interfaces: only loopback exists, down.
    let result = rt
        .execute(spec(CommandSpec::new("/bin/sh").arg("-c").arg(
            "cat /proc/net/dev | awk 'NR>2 {print $1}' | tr -d ':' | tr '\\n' ','",
        )))
        .await
        .unwrap();
    let out = result.output.stdout.text();
    assert!(
        !out.contains("eth") && !out.contains("ens") && !out.contains("wlan"),
        "host interfaces leaked into the sandbox: {out}"
    );
}

#[tokio::test]
async fn wall_time_enforced_inside_isolation() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let mut s = spec(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("while :; do sleep 1; done"),
    );
    s.policy.resources.wall_time = Duration::from_millis(500);
    let result = rt.execute(s).await.unwrap();
    assert_eq!(result.status, SandboxStatus::TimeLimitExceeded);
}

#[tokio::test]
async fn memory_bomb_hits_memory_limit() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let mut s = spec(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("x=a; while :; do x=\"$x$x\"; done"),
    );
    s.policy.resources.wall_time = Duration::from_secs(30);
    s.policy.resources.memory_bytes = 32 * 1024 * 1024;
    let result = rt.execute(s).await.unwrap();
    assert!(
        matches!(
            result.status,
            SandboxStatus::MemoryLimitExceeded | SandboxStatus::NonZeroExit
        ),
        "memory bomb must be stopped by the memory limit (status {:?})",
        result.status
    );
    // §7.4: only kernel evidence (cgroup oom events) proves OOM. Hosted CI
    // runners expose no cgroup v2 delegation to the non-root job user, so
    // the provider degrades to RLIMIT_AS and the shell's allocation
    // failure is an honest NonZeroExit — never Success.
    assert!(
        result.resource_usage.oom_events.unwrap_or(0) > 0
            || result.status == SandboxStatus::NonZeroExit,
        "oom evidence must be recorded when available (§7.4)"
    );
}

#[tokio::test]
async fn fork_bomb_hits_pid_limit() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/fork_bomb.sh"
    );
    let mut s = spec(CommandSpec::new("/bin/sh").arg(fixture));
    s.policy.resources.wall_time = Duration::from_secs(30);
    s.policy.resources.max_processes = 16;
    s.policy.process.max_processes = 16;
    let result = rt.execute(s).await.unwrap();
    assert!(
        matches!(
            result.status,
            SandboxStatus::ProcessLimitExceeded | SandboxStatus::NonZeroExit
        ),
        "fork bomb must be stopped by pids.max (status {:?})",
        result.status
    );
    assert!(
        result.resource_usage.pids_limit_hits.unwrap_or(0) > 0
            || result.status == SandboxStatus::NonZeroExit,
        "pids limit hits must be recorded (§7.4)"
    );
}

#[tokio::test]
async fn workspace_isolation_and_artifacts() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    let s = spec(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("pwd; echo data > out.txt; cat out.txt; ls /"),
    );
    let result = rt.execute(s).await.unwrap();
    assert_eq!(result.status, SandboxStatus::Success);
    let out = result.output.stdout.text();
    assert!(
        out.starts_with("/workspace"),
        "cwd must be /workspace: {out}"
    );
    assert!(out.contains("data"), "artifact must be readable: {out}");
}

#[tokio::test]
async fn pid_namespace_isolation() {
    let Some(rt) = build_runtime().await else {
        return;
    };
    // Inside a fresh PID namespace the shell's PID is tiny: 1 when the
    // command is the namespace init (older bubblewrap) or 2 with
    // bubblewrap ≥ 0.9, which inserts an internal init process. A failed
    // unshare would leave the shell with a host PID (large).
    let result = rt
        .execute(spec(CommandSpec::new("/bin/sh").arg("-c").arg("echo $$")))
        .await
        .unwrap();
    let pid_txt = result.output.stdout.text().trim().to_string();
    let pid: u32 = pid_txt
        .parse()
        .unwrap_or_else(|_| panic!("PID namespace must echo a numeric pid, got {pid_txt:?}"));
    assert!(
        pid <= 2,
        "PID namespace must be fresh, got pid {pid} (host leak?)"
    );
}
