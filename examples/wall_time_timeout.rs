//! Example: wall-time deadline (§5.7 `wall_time`, §5.9 `TimeLimitExceeded`).
//!
//! Run with: `cargo run -p nsk-examples --example wall_time_timeout`
//!
//! An infinite ticker runs under a 2-second wall-clock deadline. The
//! supervisor terminates it, the final status is `TimeLimitExceeded`, and
//! the output captured before termination is retained (bounded). This
//! backstop works on every platform — even with the mock provider that
//! offers no OS-level isolation or limits.

use std::time::Duration;

use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder, create_mock_provider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = SandboxRuntimeBuilder::new()
        .with_provider(create_mock_provider())
        .build()
        .await?;

    let mut spec = SandboxSpec::new(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("while :; do echo tick; sleep 0.2; done"),
    );
    spec.workspace = WorkspaceSpec::ephemeral();
    spec.policy = SandboxPolicy::minimal();
    // The mock provider provides NO isolation; relax everything explicitly
    // (the CLI does the same under `--no-isolation`, loudly warned). See
    // hello_sandbox for the probed, per-domain variant.
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
    spec.policy.security.require_user_namespace = false;
    spec.policy.security.require_cgroup = false;

    // The deadline: 2 seconds of wall clock, kernel-side.
    spec.policy.resources.wall_time = Duration::from_secs(2);

    let result = runtime.execute(spec).await?;

    println!("status:    {:?}", result.status);
    println!(
        "wall time: {:.2}s",
        result.resource_usage.wall_time.as_secs_f64()
    );
    println!(
        "stdout:    {} B produced, {} B retained:",
        result.output.stdout.total_bytes,
        result.output.stdout.retained.len()
    );
    println!("{}", result.output.stdout.text());
    println!("→ the wall-time backstop is enforced by the kernel supervisor,");
    println!("  independently of what the platform provider can enforce.");

    Ok(())
}
