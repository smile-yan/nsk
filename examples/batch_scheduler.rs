//! Example: bounded-concurrency batch execution (§3.1 Scheduler).
//!
//! Run with: `cargo run -p nsk-examples --example batch_scheduler`
//!
//! Four jobs are submitted to the FIFO scheduler with a global budget of
//! two concurrent sandboxes. Handles are collected up front and awaited
//! afterwards; the scheduler decides *when* each job reaches the runtime
//! and never touches OS resources itself (§13.2).

use std::sync::Arc;
use std::time::Duration;

use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntimeBuilder, create_mock_provider};
use nsk_scheduler::{Scheduler, SchedulerConfig};

/// Build one batch job: run, report, take a nap, report again.
fn job_spec(n: usize) -> SandboxSpec {
    let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sh").arg("-c").arg(format!(
        "echo job-{n} started; sleep 0.5; echo job-{n} done"
    )));
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = SandboxPolicy::minimal();
    // Mock provider = no OS isolation; relaxed explicitly (see
    // hello_sandbox for the probed, per-domain variant).
    spec.policy.isolation = IsolationPolicy {
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
    spec.policy.resources.wall_time = Duration::from_secs(30);
    spec
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Arc::new(
        SandboxRuntimeBuilder::new()
            .with_provider(create_mock_provider())
            .build()
            .await?,
    );
    let scheduler = Scheduler::new(
        SchedulerConfig {
            max_concurrency: 2,
            ..SchedulerConfig::default()
        },
        runtime,
    );
    println!(
        "scheduler: max_concurrency={} max_queue={}",
        scheduler.config().max_concurrency,
        scheduler.config().max_queue
    );

    // Submit everything; the FIFO queue holds the excess.
    let mut handles = Vec::new();
    for n in 1..=4 {
        let handle = scheduler.submit(job_spec(n)).await?;
        println!("submitted job-{n} (task id {})", handle.task_id);
        handles.push(handle);
    }

    // Await the results in submission order.
    for (n, handle) in handles.into_iter().enumerate() {
        let result = handle.result().await;
        println!(
            "job-{} → status={:?} wall={:.2}s stdout={}",
            n + 1,
            result.status,
            result.resource_usage.wall_time.as_secs_f64(),
            result.output.stdout.text().trim().replace('\n', " | ")
        );
    }

    let stats = scheduler.stats();
    println!(
        "stats: submitted={} started={} completed={} rejected={} cancelled={}",
        stats.submitted, stats.started, stats.completed, stats.rejected, stats.cancelled
    );

    Ok(())
}
