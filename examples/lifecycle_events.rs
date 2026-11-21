//! Example: event stream + mid-run cancel (§14.4 Event API, §14.3 cancel).
//!
//! Run with: `cargo run -p nsk-examples --example lifecycle_events`
//!
//! A 30-second sleeper is cancelled after one second. Every lifecycle and
//! streaming event is printed as it arrives (`kind()` gives the short
//! name); the final status is `Cancelled`. Events are broadcast through a
//! bounded channel: a slow subscriber observes `Lagged` but can never
//! block the kernel or grow memory unboundedly.

use std::time::Duration;

use nsk_core::event::SandboxEvent;
use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::{SandboxRuntime, SandboxRuntimeBuilder, create_mock_provider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = SandboxRuntimeBuilder::new()
        .with_provider(create_mock_provider())
        .build()
        .await?;

    // Mock provider = no OS isolation; relaxed explicitly (see
    // hello_sandbox for the probed, per-domain variant). Irrelevant here —
    // the scenario is the lifecycle, not isolation.
    let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sh").arg("-c").arg("sleep 30"));
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
    spec.policy.security.require_user_namespace = false;
    spec.policy.security.require_cgroup = false;
    spec.policy.resources.wall_time = Duration::from_secs(60);

    let id = runtime.create(spec).await?;
    let mut events = runtime.subscribe(Some(id));

    // Cancel after 1s (§14.3): cooperative kernel-level cancellation —
    // the process tree is terminated and cleanup still runs.
    tokio::spawn({
        let runtime = runtime.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!("[caller] cancel({id})");
            if let Err(e) = runtime.cancel(id).await {
                eprintln!("cancel failed: {e}");
            }
        }
    });

    runtime.start(id).await?;

    let wait_handle = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.wait(id).await }
    });

    let mut wait_handle = Some(wait_handle);
    loop {
        tokio::select! {
            ev = events.recv() => {
                match ev {
                    Ok(e) if e.id == id => {
                        let detail = match &e.event {
                            SandboxEvent::Stdout(data) => {
                                String::from_utf8_lossy(data).trim_end().to_string()
                            }
                            SandboxEvent::Exited(i) => format!(
                                "exit_code={:?} signal={:?}",
                                i.exit_code, i.signal
                            ),
                            SandboxEvent::LimitExceeded(kind) => format!("{kind:?}"),
                            _ => String::new(),
                        };
                        if detail.is_empty() {
                            println!("[{:>12}]", e.event.kind());
                        } else {
                            println!("[{:>12}] {detail}", e.event.kind());
                        }
                    }
                    Ok(_) => {} // event of another sandbox
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        println!("[events] lagged by {n} (bounded queue)");
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
