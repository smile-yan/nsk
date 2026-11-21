//! Example: hello, sandbox — the portable "first run" (§14.3, §17 profiles).
//!
//! Run with: `cargo run -p nsk-examples --example hello_sandbox`
//!
//! Starts from the `strict` profile, probes the host, drops exactly the
//! isolation domains the platform provider cannot honor (the API-level
//! equivalent of the CLI's `--relax-unsupported`), and executes. On Linux
//! this runs fully isolated (namespaces + cgroups); on macOS the Seatbelt
//! PoC covers what it can; every drop is announced here and recorded in
//! the result diagnostics — never silent.

use nsk_core::capability::CapabilityStatus;
use nsk_core::policy::SandboxPolicy;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder, create_default_provider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Platform default provider: Linux bubblewrap/cgroups, macOS
    //    Seatbelt PoC, Windows Job Objects MVP.
    let provider = create_default_provider()?;
    let caps = provider.probe().await?;
    println!("provider: {}", provider.name());

    // 2. Describe the execution request, starting from the strict profile.
    let mut spec = SandboxSpec::new(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("echo hello from the sandbox; pwd"),
    );
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = SandboxPolicy::strict();

    // 3. Drop exactly the isolation domains this provider cannot honor.
    //    The CLI does the same under `--relax-unsupported`; every drop is
    //    also recorded in the result diagnostics by the policy resolver.
    let mut dropped: Vec<&'static str> = Vec::new();
    let iso = &caps.isolation;

    drop_unavailable(
        iso.pid_namespace.is_available() || caps.resources.job_objects.is_available(),
        "process",
        &mut spec.policy.isolation.isolate_process,
        &mut dropped,
    );
    drop_unavailable(
        iso.filesystem_isolation.is_available(),
        "filesystem",
        &mut spec.policy.isolation.isolate_filesystem,
        &mut dropped,
    );
    drop_unavailable(
        iso.network_isolation.is_available(),
        "network",
        &mut spec.policy.isolation.isolate_network,
        &mut dropped,
    );
    drop_unavailable(
        iso.ipc_namespace.is_available(),
        "ipc",
        &mut spec.policy.isolation.isolate_ipc,
        &mut dropped,
    );
    drop_unavailable(
        iso.uts_namespace.is_available(),
        "uts",
        &mut spec.policy.isolation.isolate_uts,
        &mut dropped,
    );
    drop_unavailable(
        caps.security.no_new_privileges.is_available(),
        "no_new_privileges",
        &mut spec.policy.security.no_new_privileges,
        &mut dropped,
    );
    if spec.policy.security.require_user_namespace && !iso.user_namespace.is_available() {
        spec.policy.security.require_user_namespace = false;
        dropped.push("user_namespace");
    }
    if spec.policy.security.require_cgroup
        && caps.resources.cgroup_v2 != CapabilityStatus::Available
    {
        spec.policy.security.require_cgroup = false;
        dropped.push("require_cgroup");
    }
    if !iso.mount_namespace.is_available() {
        // Host-path hiding and root remapping are namespace-only mechanisms;
        // providers with a different filesystem mechanism (Seatbelt) would
        // fail-closed on them, so drop them explicitly here.
        spec.policy.filesystem.deny_host_paths = false;
        spec.policy.filesystem.isolate_root = false;
        dropped.push("deny_host_paths");
        dropped.push("isolate_root");
    }

    if dropped.is_empty() {
        println!("strict profile accepted as-is — nothing to relax");
    } else {
        println!(
            "WARNING: relaxed unavailable domains: {}",
            dropped.join(", ")
        );
    }

    // 4. Execute end-to-end: create → start → wait (+ cleanup).
    let runtime = SandboxRuntimeBuilder::new()
        .with_provider(provider)
        .build()
        .await?;
    let result = runtime.execute(spec).await?;

    println!("status:    {:?}", result.status);
    println!(
        "exit code: {:?}",
        result.exit_info.and_then(|e| e.exit_code)
    );
    println!(
        "wall time: {:.3}s",
        result.resource_usage.wall_time.as_secs_f64()
    );
    println!("stdout:    {}", result.output.stdout.text().trim());
    for d in &result.diagnostics {
        println!("diagnostic: [{:?}] {}", d.severity, d.message);
    }

    Ok(())
}

/// Turn one isolation requirement off when the probed provider cannot
/// honor it, and record the drop for the announcement line.
fn drop_unavailable(
    available: bool,
    name: &'static str,
    requested: &mut bool,
    dropped: &mut Vec<&'static str>,
) {
    if !available {
        *requested = false;
        dropped.push(name);
    }
}
