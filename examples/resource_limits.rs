//! Example: resource limits — a memory cap in action (§5.7, §7.2, §7.4).
//!
//! Run with: `cargo run -p nsk-examples --example resource_limits`
//!
//! A tiny allocator bomb (doubling a shell variable) runs under a 32 MiB
//! memory limit. The outcome is platform-honest, and this example shows
//! how to read it:
//!
//! * Linux (cgroup v2)     → `MemoryLimitExceeded`, confirmed by
//!   `oom_events` from `memory.events` — a hard kill;
//! * macOS (watchdog)      → reactive termination with overshoot, loudly
//!   recorded in diagnostics (no silent pretend-enforcement);
//! * mock provider         → no enforcement at all; only the wall-time
//!   backstop remains → `TimeLimitExceeded` (degradation is explicit).
//!
//! An exit code alone is never treated as proof of an OOM (§7.4): the
//! status is derived from provider-confirmed evidence only.

use std::time::Duration;

use nsk_core::capability::CapabilityStatus;
use nsk_core::policy::SandboxPolicy;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder, create_default_provider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = create_default_provider()?;
    let caps = provider.probe().await?;
    println!("provider: {}", provider.name());
    println!(
        "hard memory enforcement available: {}",
        caps.resources.cgroup_v2.is_available() || caps.resources.job_objects.is_available()
    );

    let mut spec = SandboxSpec::new(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("x=a; while :; do x=\"$x$x\"; done"),
    );
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = SandboxPolicy::minimal();

    // Keep the policy honest: drop the isolation domains this provider
    // cannot honor (see hello_sandbox for the fully annotated variant).
    let iso = &caps.isolation;
    spec.policy.isolation.isolate_process &=
        iso.pid_namespace.is_available() || caps.resources.job_objects.is_available();
    spec.policy.isolation.isolate_filesystem &= iso.filesystem_isolation.is_available();
    spec.policy.isolation.isolate_network &= iso.network_isolation.is_available();
    spec.policy.isolation.isolate_ipc &= iso.ipc_namespace.is_available();
    spec.policy.isolation.isolate_uts &= iso.uts_namespace.is_available();
    spec.policy.security.no_new_privileges &= caps.security.no_new_privileges.is_available();
    if !iso.user_namespace.is_available() {
        spec.policy.security.require_user_namespace = false;
    }
    if caps.resources.cgroup_v2 != CapabilityStatus::Available {
        spec.policy.security.require_cgroup = false;
    }
    if !iso.mount_namespace.is_available() {
        spec.policy.filesystem.deny_host_paths = false;
        spec.policy.filesystem.isolate_root = false;
    }

    // The scenario: 32 MiB memory cap; wall time is only a backstop.
    spec.policy.resources.memory_bytes = 32 * 1024 * 1024;
    spec.policy.resources.wall_time = Duration::from_secs(15);

    let runtime = SandboxRuntimeBuilder::new()
        .with_provider(provider)
        .build()
        .await?;
    let result = runtime.execute(spec).await?;

    let usage = &result.resource_usage;
    println!("status:      {:?}", result.status);
    println!("wall time:   {:.2}s", usage.wall_time.as_secs_f64());
    println!("memory peak: {:?} B", usage.memory_peak_bytes);
    println!("oom events:  {:?}", usage.oom_events);
    for d in &result.diagnostics {
        println!("diagnostic:  [{:?}] {}", d.severity, d.message);
    }

    println!();
    match result.status {
        nsk_core::result::SandboxStatus::MemoryLimitExceeded => {
            println!("→ the memory cap was enforced and confirmed by kernel/provider evidence");
        }
        nsk_core::result::SandboxStatus::TimeLimitExceeded => {
            println!("→ no memory enforcement on this platform; the wall-time backstop fired");
        }
        other => println!("→ unexpected status {other:?} — inspect the diagnostics above"),
    }

    Ok(())
}
