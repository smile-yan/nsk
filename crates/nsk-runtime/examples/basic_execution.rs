//! Example: basic sandbox execution (§14.3 执行 API).
//!
//! Run with: `cargo run --example basic_execution -p nsk-runtime`
//!
//! This example uses the mock provider (no OS isolation) so it works on
//! every host; on Linux, swap in `nsk_runtime::create_default_provider()`
//! for real namespace/cgroup isolation.

use std::time::Duration;

use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build the runtime with a provider.
    let runtime = SandboxRuntimeBuilder::new()
        .with_provider(nsk_provider::create_mock_provider())
        .build()
        .await?;

    println!("provider: {}", runtime.provider_name());

    // 2. Describe the execution request.
    let mut spec = SandboxSpec::new(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("echo hello from the sandbox; echo err >&2; exit 0")
            .stdin_bytes(b"unused".to_vec()),
    );
    spec.workspace = WorkspaceSpec::ephemeral();

    // The mock provider cannot provide OS isolation; relax the policy
    // (on Linux with the default provider, keep the secure defaults).
    spec.policy = SandboxPolicy::minimal();
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
    spec.policy.resources.wall_time = Duration::from_secs(10);

    // 3. Execute end-to-end: create → start → wait (+ cleanup).
    let result = runtime.execute(spec).await?;

    println!("status:        {:?}", result.status);
    println!("exit code:     {:?}", result.exit_info.map(|e| e.exit_code));
    println!(
        "wall time:     {:.3}s",
        result.resource_usage.wall_time.as_secs_f64()
    );
    println!("stdout:        {}", result.output.stdout.text());
    println!("stderr:        {}", result.output.stderr.text());
    for d in &result.diagnostics {
        println!("diagnostic:    [{:?}] {}", d.severity, d.message);
    }

    Ok(())
}
