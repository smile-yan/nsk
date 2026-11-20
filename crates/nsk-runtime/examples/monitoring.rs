//! Example: monitoring a running sandbox (§14.4 Event API, §7.2 usage).
//!
//! Run with: `cargo run --example monitoring -p nsk-runtime`

use std::time::Duration;

use nsk_core::event::SandboxEvent;
use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = SandboxRuntimeBuilder::new()
        .with_provider(nsk_provider::create_mock_provider())
        .build()
        .await?;

    // A program that produces output steadily for a while.
    let mut spec = SandboxSpec::new(
        CommandSpec::new("/bin/sh")
            .arg("-c")
            .arg("for i in 1 2 3 4 5 6 7 8 9 10; do echo tick-$i; sleep 0.2; done"),
    );
    spec.workspace = WorkspaceSpec::ephemeral();
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
    spec.policy.resources.wall_time = Duration::from_secs(30);

    let id = runtime.create(spec).await?;
    let mut events = runtime.subscribe(Some(id));

    runtime.start(id).await?;

    // Stream lifecycle + output events while the program runs (§14.4).
    let wait_handle = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.wait(id).await }
    });

    let mut wait_handle = Some(wait_handle);
    loop {
        tokio::select! {
            ev = events.recv() => {
                match ev {
                    Ok(e) if e.id == id => match &e.event {
                        SandboxEvent::Stdout(data) => {
                            print!("[stdout] {}", String::from_utf8_lossy(data));
                        }
                        SandboxEvent::Stderr(data) => {
                            print!("[stderr] {}", String::from_utf8_lossy(data));
                        }
                        SandboxEvent::ResourceUsage(u) => {
                            println!(
                                "[usage] wall={:.2}s stdout={}B stderr={}B",
                                u.wall_time.as_secs_f64(),
                                u.stdout_bytes,
                                u.stderr_bytes
                            );
                        }
                        SandboxEvent::LimitExceeded(kind) => {
                            println!("[limit] {kind:?} exceeded");
                        }
                        SandboxEvent::CleanupCompleted => break,
                        _ => {}
                    },
                    Ok(_) => {} // other sandbox
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        println!("[events] lagged by {n} (bounded queue, §14.4)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            result = async {
                match wait_handle.as_mut() {
                    Some(h) => h.await,
                    None => std::future::pending().await,
                }
            } => {
                let result = result??;
                println!("\nfinal status: {:?}", result.status);
                break;
            }
        }
    }

    Ok(())
}
