//! Example: policy handling (§6 Policy Engine, §17 Profiles).
//!
//! Run with: `cargo run --example policy -p nsk-runtime`

use nsk_core::capability::PlatformCapabilities;
use nsk_core::policy::SandboxPolicy;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_policy::effective::resolve;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = nsk_provider::create_mock_provider();
    let caps: PlatformCapabilities = provider.probe().await?;

    // 1. Profiles (§17) are validated starting points.
    for (name, policy) in [
        ("minimal", SandboxPolicy::minimal()),
        ("strict", SandboxPolicy::strict()),
        ("extended", SandboxPolicy::extended()),
    ] {
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = policy;

        match resolve(&spec, &caps) {
            Ok(effective) => {
                println!("profile {name}:");
                for limit in &effective.applied.resources {
                    println!(
                        "  {:<10} status={:?} requested={} effective={} mechanism={}",
                        limit.kind,
                        limit.status,
                        limit.requested,
                        limit.effective.as_deref().unwrap_or("-"),
                        limit.mechanism.as_deref().unwrap_or("-"),
                    );
                }
                println!(
                    "  limitations: {} recorded (degradations & advisories)",
                    effective.limitations.len()
                );
                println!();
            }
            Err(e) => println!("profile {name}: refused — {e}\n"),
        }
    }

    // 2. Fail-closed: isolation on a provider that cannot provide it.
    let spec = SandboxSpec::new(CommandSpec::new("/bin/echo")); // minimal policy requests isolation
    match resolve(&spec, &caps) {
        Ok(_) => println!("minimal policy accepted"),
        Err(e) => println!("minimal policy on mock provider → refused (fail-closed):\n  {e}"),
    }

    Ok(())
}
