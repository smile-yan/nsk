//! Stress tests (§16.5).
//!
//! Heavy cases are `#[ignore]`d and run explicitly via
//! `cargo test -p nsk-runtime --test stress -- --ignored`.
//! Scale factors come from the environment (`NSK_STRESS_ITERS`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

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

fn echo_spec(tag: &str) -> SandboxSpec {
    let mut spec = SandboxSpec::new(CommandSpec::new("/bin/echo").args([tag.to_string()]));
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = relaxed_policy();
    spec
}

fn iterations(default: u64) -> u64 {
    std::env::var("NSK_STRESS_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn stress_short_burst_concurrent() {
    // Always-on smoke: 20 concurrent quick executions.
    block_on(async {
        let rt = build_runtime().await;
        let mut handles = Vec::new();
        for i in 0..20 {
            let rt = rt.clone();
            handles.push(tokio::spawn(async move {
                let r = rt
                    .execute(echo_spec(&format!("burst-{i}")))
                    .await
                    .expect("execute");
                assert_eq!(r.status, SandboxStatus::Success);
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
    });
}

#[test]
#[ignore = "long-running: run with --ignored (§16.5 连续执行压力)"]
fn stress_1000_sequential_executions() {
    let iters = iterations(200);
    block_on(async {
        let rt = build_runtime().await;
        let start = Instant::now();
        for i in 0..iters {
            let r = rt
                .execute(echo_spec(&format!("seq-{i}")))
                .await
                .expect("execute");
            assert_eq!(r.status, SandboxStatus::Success);
        }
        println!(
            "{iters} sequential executions in {:.2}s",
            start.elapsed().as_secs_f64()
        );
    });
}

#[test]
#[ignore = "long-running: run with --ignored (§16.5 并发压力)"]
fn stress_100_concurrent_executions() {
    block_on(async {
        let rt = build_runtime().await;
        let mut handles = Vec::new();
        for i in 0..100 {
            let rt = rt.clone();
            handles.push(tokio::spawn(async move {
                let r = rt
                    .execute(echo_spec(&format!("par-{i}")))
                    .await
                    .expect("execute");
                assert_eq!(r.status, SandboxStatus::Success);
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
    });
}

#[test]
#[ignore = "long-running: run with --ignored (§16.5 高频输出)"]
fn stress_high_volume_output() {
    block_on(async {
        let rt = build_runtime().await;
        // 64 MiB of stdout under an 8 MiB limit → terminated, bounded memory.
        let mut spec = SandboxSpec::new(
            CommandSpec::new("/bin/dd")
                .arg("if=/dev/zero")
                .arg("bs=1M")
                .arg("count=64"),
        );
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        spec.policy.output.max_stdout_bytes = 8 * 1024 * 1024;
        spec.policy.output.max_stderr_bytes = 8 * 1024 * 1024;
        spec.policy.output.combined_limit_bytes = 8 * 1024 * 1024;
        spec.policy.resources.max_output_bytes = 8 * 1024 * 1024;
        let r = rt.execute(spec).await.expect("execute");
        assert_eq!(r.status, SandboxStatus::OutputLimitExceeded);
        assert!(r.output.stdout.retained.len() <= 8 * 1024 * 1024 + 8192);
    });
}

#[test]
#[ignore = "long-running: run with --ignored (§16.5 超时风暴/取消竞态)"]
fn stress_timeout_and_cancel_storm() {
    block_on(async {
        let rt = build_runtime().await;
        let mut handles = Vec::new();
        for i in 0..30 {
            let rt = rt.clone();
            let timed_out = i % 2 == 0;
            handles.push(tokio::spawn(async move {
                let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("60"));
                spec.workspace = WorkspaceSpec::ephemeral();
                spec.policy = relaxed_policy();
                if timed_out {
                    spec.policy.resources.wall_time = Duration::from_millis(200);
                }
                let id = rt.create(spec).await.expect("create");
                rt.start(id).await.expect("start");
                if !timed_out {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    rt.cancel(id).await.expect("cancel");
                }
                let r = rt.wait(id).await.expect("wait");
                if timed_out {
                    assert_eq!(r.status, SandboxStatus::TimeLimitExceeded);
                } else {
                    assert_eq!(r.status, SandboxStatus::Cancelled);
                }
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
    });
}
