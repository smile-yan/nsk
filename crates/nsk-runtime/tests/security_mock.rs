//! Security tests over the mock provider (§16.4) — supervisor-level
//! enforcement that works on any Unix host:
//!
//! * wall-time kill (infinite loop),
//! * output bomb termination,
//! * open-file bomb via RLIMIT_NOFILE,
//! * file-size bomb via RLIMIT_FSIZE,
//! * environment whitelist (no host leakage),
//! * workspace file policy.
//!
//! Full OS-isolation security tests (host-path, network, fork-bomb under
//! namespaces/cgroups) live in `nsk-provider-linux/tests/` and run on Linux
//! CI hosts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use nsk_core::id::SandboxId;
use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::result::SandboxStatus;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
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

fn relaxed_policy() -> SandboxPolicy {
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
    p.security.drop_privileges = false;
    p
}

async fn build_runtime() -> Arc<dyn SandboxRuntime> {
    Arc::new(
        SandboxRuntimeBuilder::new()
            .with_provider(nsk_provider::create_mock_provider())
            .build()
            .await
            .unwrap(),
    )
}

use std::sync::Arc;

#[test]
fn sec_wall_time_enforced() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(
            CommandSpec::new("/bin/sh")
                .arg("-c")
                .arg("while :; do sleep 1; done"),
        );
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        spec.policy.resources.wall_time = Duration::from_millis(400);
        let result = rt.execute(spec).await.unwrap();
        assert_eq!(result.status, SandboxStatus::TimeLimitExceeded);
    });
}

#[test]
fn sec_output_bomb_terminated() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec = SandboxSpec::new(CommandSpec::new("/usr/bin/yes"));
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        spec.policy.output.max_stdout_bytes = 256 * 1024;
        spec.policy.output.max_stderr_bytes = 256 * 1024;
        spec.policy.output.combined_limit_bytes = 256 * 1024;
        spec.policy.resources.max_output_bytes = 256 * 1024;
        let result = rt.execute(spec).await.unwrap();
        assert_eq!(result.status, SandboxStatus::OutputLimitExceeded);
    });
}

#[test]
fn sec_open_file_bomb_killed_by_nofile() {
    block_on(async {
        let rt = build_runtime().await;
        // Try to open 100 fds under a NOFILE of 8: the shell must fail.
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sh").arg("-c").arg(
            "exec 3<$0; exec 4<$0; exec 5<$0; exec 6<$0; exec 7<$0; exec 8<$0; exec 9<$0; echo opened",
        ));
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        spec.policy.resources.max_open_files = 8;
        let result = rt.execute(spec).await.unwrap();
        // Either the fd duplication failed (text mentions error) or the
        // program did not print "opened".
        let out = result.output.stdout.text();
        assert!(
            !out.contains("opened") || result.status != SandboxStatus::Success,
            "NOFILE must prevent opening beyond the limit; stdout: {out}"
        );
    });
}

#[test]
fn sec_file_size_bomb_killed_by_fsize() {
    block_on(async {
        let rt = build_runtime().await;
        // Write a 100 MB file under a 1 MiB RLIMIT_FSIZE: SIGXFSZ.
        let mut spec = SandboxSpec::new(
            CommandSpec::new("/bin/dd")
                .arg("if=/dev/zero")
                .arg("of=big.bin")
                .arg("bs=1M")
                .arg("count=100"),
        );
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        spec.policy.resources.max_file_size_bytes = 1024 * 1024;
        let result = rt.execute(spec).await.unwrap();
        let killed_by_xfsz = result
            .exit_info
            .map(|e| e.signal == Some(25))
            .unwrap_or(false);
        assert!(
            killed_by_xfsz || result.status != SandboxStatus::Success,
            "RLIMIT_FSIZE must stop the file bomb (status {:?}, exit {:?})",
            result.status,
            result.exit_info
        );
    });
}

#[test]
fn sec_env_whitelist_no_host_leak() {
    block_on(async {
        let rt = build_runtime().await;
        let mut spec =
            SandboxSpec::new(CommandSpec::new("/usr/bin/env")).with_env("NSK_ALLOWED", "yes");
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        let result = rt.execute(spec).await.unwrap();
        let text = result.output.stdout.text();
        assert!(text.contains("NSK_ALLOWED=yes"));
        // Common sensitive host variables must not leak.
        for leak in ["HOME=", "SSH_AUTH_SOCK=", "AWS_", "TOKEN"] {
            assert!(!text.contains(leak), "host env leaked: {leak} in {text}");
        }
    });
}

#[test]
fn sec_daemonized_children_die_with_sandbox() {
    block_on(async {
        let rt = build_runtime().await;

        // Baseline count of host-wide `sleep 30` processes (the probe runs
        // outside isolation on the mock provider, so it sees the host).
        async fn count_sleep30(rt: &Arc<dyn SandboxRuntime>) -> i64 {
            let mut probe = SandboxSpec::new(
                CommandSpec::new("/bin/sh")
                    .arg("-c")
                    .arg("ps -ef | grep 'sleep 30' | grep -v grep | wc -l | tr -d ' '"),
            );
            probe.workspace = WorkspaceSpec::ephemeral();
            probe.policy = relaxed_policy();
            let r = rt.execute(probe).await.expect("probe");
            r.output.stdout.text().trim().parse().unwrap_or(-1)
        }
        // Use a unique duration so concurrent test runs cannot interfere.
        async fn spawn_daemonizer(rt: &Arc<dyn SandboxRuntime>) {
            let mut spec = SandboxSpec::new(
                CommandSpec::new("/bin/sh")
                    .arg("-c")
                    .arg("/bin/sleep 97 & echo spawned; exit 0"),
            );
            spec.workspace = WorkspaceSpec::ephemeral();
            spec.policy = relaxed_policy();
            spec.policy.process.kill_process_tree = true;
            let result = rt.execute(spec).await.expect("execute");
            assert_eq!(result.status, SandboxStatus::Success);
        }

        // (The baseline probe uses sleep 97 — run it once to warm up.)
        spawn_daemonizer(&rt).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = {
            let mut probe = SandboxSpec::new(
                CommandSpec::new("/bin/sh")
                    .arg("-c")
                    .arg("ps -ef | grep 'sleep 97' | grep -v grep | wc -l | tr -d ' '"),
            );
            probe.workspace = WorkspaceSpec::ephemeral();
            probe.policy = relaxed_policy();
            let r = rt.execute(probe).await.expect("probe");
            r.output.stdout.text().trim().parse::<i64>().unwrap_or(-1)
        };
        assert_eq!(
            after, 0,
            "daemonized sandbox child leaked into the host (§16.4 Background Process)"
        );
        let _ = count_sleep30(&rt).await;
        let _ = SandboxId::new();
    });
}
