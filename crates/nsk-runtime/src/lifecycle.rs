//! Lifecycle orchestration (§4.2, §4.3).
//!
//! The lifecycle driver owns every state transition of one sandbox and the
//! run-to-completion task that maps the supervisor outcome into a
//! [`SandboxResult`], then cleans up (§10.9 flow, provider-independent).

use std::sync::Arc;
use std::time::Duration;

use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::event::{LimitType, SandboxEvent};
use nsk_core::result::{ExitInfo, OutputResult, ResourceUsage, SandboxResult, SandboxStatus};
use nsk_core::spec::SandboxSpec;
use nsk_core::state::SandboxState;
use nsk_policy::effective::resolve;
use nsk_provider::traits::{PrepareContext, SandboxProvider, SpawnContext};
use nsk_supervisor::monitor::{ExecOutcome, OutcomeReason};
use nsk_supervisor::output::SupervisorEvent;
use nsk_workspace::manager::WorkspaceManager;
use tracing::{debug, info, warn};

use crate::cleanup::CleanupManager;
use crate::registry::SandboxEntry;

/// Signals with deterministic limit semantics (§7.4).
const SIGXCPU: i32 = 24; // CPU-time rlimit exceeded
const SIGXFSZ: i32 = 25; // file-size rlimit exceeded

/// Prepare a sandbox: validate → prepare workspace → provider prepare.
pub(crate) async fn prepare(
    entry: &Arc<SandboxEntry>,
    spec: SandboxSpec,
    provider: &Arc<dyn SandboxProvider>,
    workspace_manager: &WorkspaceManager,
) -> Result<(), SandboxError> {
    entry.emit(SandboxEvent::Created);
    entry.transition(SandboxState::Validating)?;
    *entry.spec.lock().unwrap_or_else(|p| p.into_inner()) = Some(spec.clone());

    // Policy Engine pipeline (§6.2): validate + capability match.
    let capabilities = provider.probe().await?;
    let effective = match resolve(&spec, &capabilities) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            if let SandboxError::PolicyValidation(diags) = &e {
                entry.push_diagnostics(diags.clone());
            }
            let _ = entry.transition(SandboxState::Failed);
            return Err(e);
        }
    };
    entry.push_diagnostics(effective.limitations.clone());
    *entry.effective.lock().unwrap_or_else(|p| p.into_inner()) = Some(effective.clone());
    debug!(id = %entry.id, "policy resolved");

    // Preparing: workspace + provider isolation.
    entry.transition(SandboxState::Preparing)?;
    entry.emit(SandboxEvent::Preparing);

    let workspace = match workspace_manager.prepare(&spec.workspace, &entry.id) {
        Ok(ws) => Arc::new(ws),
        Err(e) => {
            let _ = entry.transition(SandboxState::Failed);
            return Err(SandboxError::Isolation(format!(
                "workspace prepare failed: {e}"
            )));
        }
    };
    entry.push_diagnostics(workspace.diagnostics.clone());
    *entry.workspace.lock().unwrap_or_else(|p| p.into_inner()) = Some(workspace.clone());

    let ctx = PrepareContext {
        id: entry.id,
        spec,
        policy: effective,
        workspace,
    };
    match provider.prepare(ctx).await {
        Ok(prepared) => {
            *entry.prepared.lock().unwrap_or_else(|p| p.into_inner()) = Some(prepared);
            entry.transition(SandboxState::Ready)?;
            entry.emit(SandboxEvent::Ready);
            Ok(())
        }
        Err(e) => {
            let _ = entry.transition(SandboxState::Failed);
            Err(e)
        }
    }
}

/// Start a prepared sandbox (Ready → Starting → Running) and spawn the
/// run-to-completion driver.
pub(crate) async fn start(
    entry: &Arc<SandboxEntry>,
    provider: &Arc<dyn SandboxProvider>,
) -> Result<(), SandboxError> {
    if entry.state() != SandboxState::Ready {
        return Err(SandboxError::InvalidOperation {
            id: entry.id,
            state: entry.state(),
            required: "Ready",
        });
    }
    entry.transition(SandboxState::Starting)?;

    let prepared = entry
        .prepared
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .ok_or_else(|| SandboxError::Internal("prepared sandbox missing".into()))?;

    // Enforcement values (deadline, output caps) derive from the effective
    // policy; providers translate them via nsk_provider::supervisor_config.
    let policy = entry
        .effective
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .ok_or_else(|| SandboxError::Internal("effective policy missing at start".into()))?;

    let (tap_tx, tap_rx) = tokio::sync::broadcast::channel::<SupervisorEvent>(256);
    // Bridge supervisor events into the sandbox event stream (§14.4).
    let bridge_entry = entry.clone();
    tokio::spawn(async move {
        let mut rx = tap_rx;
        loop {
            match rx.recv().await {
                Ok(SupervisorEvent::OutputChunk(kind, data)) => {
                    let ev = match kind {
                        nsk_supervisor::output::OutputStream::Stdout => SandboxEvent::Stdout(data),
                        nsk_supervisor::output::OutputStream::Stderr => SandboxEvent::Stderr(data),
                    };
                    bridge_entry.emit(ev);
                }
                Ok(SupervisorEvent::LimitCrossed(crossed)) => {
                    bridge_entry.emit(SandboxEvent::LimitExceeded(LimitType::Output));
                    let _ = crossed;
                }
                Ok(SupervisorEvent::Terminating(kind)) => {
                    debug!(kind = kind.as_str(), "supervisor terminating");
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // Bounded queue: lagging is acceptable (§14.4).
                    debug!(lagged = n, "event bridge lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let running = match provider
        .spawn(
            prepared,
            SpawnContext {
                policy,
                events: Some(tap_tx),
            },
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let _ = entry.transition(SandboxState::Failed);
            entry.emit(SandboxEvent::Terminating);
            return Err(e);
        }
    };
    info!(id = %entry.id, pid = running.process.pid(), provider = running.provider_name, "sandbox started");
    entry.emit(SandboxEvent::Started);

    // Store the running handle, flip to Running, and spawn the driver.
    *entry.running.lock().unwrap_or_else(|p| p.into_inner()) = Some(running.clone());
    entry.transition(SandboxState::Running)?;

    let driver_entry = entry.clone();
    let driver_provider = provider.clone();
    tokio::spawn(async move {
        drive_to_completion(driver_entry, driver_provider, running).await;
    });
    Ok(())
}

/// The run-to-completion driver (§8.2 Exit Collection + §4.2 tail states).
async fn drive_to_completion(
    entry: Arc<SandboxEntry>,
    provider: Arc<dyn SandboxProvider>,
    running: nsk_provider::traits::RunningSandbox,
) {
    // Wait for the outcome.
    let outcome: Arc<ExecOutcome> = running.process.wait().await;
    entry.emit(SandboxEvent::Exited(outcome.exit));

    // Collecting: merge supervisor + provider usage.
    let _ = entry.transition(SandboxState::Collecting);
    let provider_usage = provider.collect_usage(&running).await.unwrap_or_else(|e| {
        debug!(id = %entry.id, error = %e, "provider usage collection failed");
        ResourceUsage::default()
    });

    let mut usage = ResourceUsage {
        wall_time: outcome.wall_time,
        ..provider_usage.clone()
    };
    let (stdout_bytes, stderr_bytes) = running.process.output_totals();
    usage.stdout_bytes = stdout_bytes;
    usage.stderr_bytes = stderr_bytes;
    usage.cpu_time = provider_usage.cpu_time.or(None);
    *entry.last_usage.lock().unwrap_or_else(|p| p.into_inner()) = Some(usage.clone());
    entry.emit(SandboxEvent::ResourceUsage(usage.clone()));

    // Status derivation (§5.9): reliable evidence only.
    let status = derive_status(&outcome, &usage, entry.cancel.is_cancelled());
    let mut result = SandboxResult::new(entry.id, status);
    result.exit_info = Some(outcome.exit);
    result.resource_usage = usage.clone();
    result.output = OutputResult {
        stdout: outcome.output.stdout.clone(),
        stderr: outcome.output.stderr.clone(),
    };

    // Terminating (when the exit was not a clean exit).
    if status != SandboxStatus::Success && status != SandboxStatus::NonZeroExit {
        entry.emit(SandboxEvent::Terminating);
        let _ = entry.transition(SandboxState::Terminating);
        // Ensure the whole tree is gone (idempotent).
        let _ = provider.terminate(&running).await;
    }

    // Cleaning.
    let cleaning = entry.transition(SandboxState::Cleaning);
    let cleanup_manager = CleanupManager::new(provider.name());
    let cleanup_diags = match cleaning {
        Ok(_) => match cleanup_manager.cleanup(&entry, &provider).await {
            Ok(d) => d,
            Err(SandboxError::Cleanup(mut d)) => {
                // Hard cleanup failure: record and complete with diagnostics
                // so results are never lost (§4.3 rule 8).
                d.push(Diagnostic::error(
                    codes::CLEANUP_INCOMPLETE,
                    "cleanup failed; resources may remain (retry with cleanup())",
                ));
                d
            }
            Err(e) => vec![Diagnostic::error(
                codes::CLEANUP_FAILED,
                format!("cleanup error: {e}"),
            )],
        },
        Err(e) => {
            warn!(id = %entry.id, error = %e, "unexpected state during cleanup");
            vec![Diagnostic::error(
                codes::CLEANUP_FAILED,
                format!("state machine error during cleanup: {e}"),
            )]
        }
    };
    result.diagnostics = entry.snapshot_diagnostics();
    result.diagnostics.extend(cleanup_diags.iter().cloned());

    // Completed.
    let _ = entry.transition(SandboxState::Completed);
    let result = Arc::new(result);
    entry.set_result(result.clone());
    // CleanupCompleted is emitted by the CleanupManager itself.
    info!(id = %entry.id, status = ?result.status, wall_ms = result.resource_usage.wall_time.as_millis(), "sandbox completed");
}

/// Map an outcome + usage evidence to the final status (§7.4: exit codes
/// never prove OOM by themselves).
fn derive_status(outcome: &ExecOutcome, usage: &ResourceUsage, cancelled: bool) -> SandboxStatus {
    match &outcome.reason {
        OutcomeReason::CancelRequested => SandboxStatus::Cancelled,
        OutcomeReason::WallTimeExceeded => SandboxStatus::TimeLimitExceeded,
        OutcomeReason::OutputLimitExceeded(_) => SandboxStatus::OutputLimitExceeded,
        OutcomeReason::Terminated(kind) => match kind {
            nsk_supervisor::terminate::TerminateKind::Timeout => SandboxStatus::TimeLimitExceeded,
            nsk_supervisor::terminate::TerminateKind::Cancel => SandboxStatus::Cancelled,
            nsk_supervisor::terminate::TerminateKind::Limit => SandboxStatus::OutputLimitExceeded,
            nsk_supervisor::terminate::TerminateKind::External => {
                if cancelled {
                    SandboxStatus::Cancelled
                } else {
                    // Provider-confirmed limit kills (watchdogs, Job
                    // Objects) are deterministic evidence — the provider
                    // terminated the tree itself because a limit was
                    // exceeded (§7.4).
                    if usage.oom_events.unwrap_or(0) > 0 {
                        SandboxStatus::MemoryLimitExceeded
                    } else if usage.pids_limit_hits.unwrap_or(0) > 0 {
                        SandboxStatus::ProcessLimitExceeded
                    } else {
                        SandboxStatus::NonZeroExit
                    }
                }
            }
        },
        OutcomeReason::Internal(msg) => {
            let _ = msg;
            SandboxStatus::InternalError
        }
        OutcomeReason::Exit => {
            // Signal-based deterministic limits.
            if let Some(signal) = outcome.exit.signal {
                if signal == SIGXCPU {
                    return SandboxStatus::CpuLimitExceeded;
                }
                if signal == SIGXFSZ {
                    return SandboxStatus::DiskLimitExceeded;
                }
            }
            // Kernel-confirmed events (§7.4): cgroup oom/pids counters.
            if usage.oom_events.unwrap_or(0) > 0 {
                return SandboxStatus::MemoryLimitExceeded;
            }
            if usage.pids_limit_hits.unwrap_or(0) > 0 {
                return SandboxStatus::ProcessLimitExceeded;
            }
            match outcome.exit.exit_code {
                Some(0) => SandboxStatus::Success,
                Some(_) => SandboxStatus::NonZeroExit,
                None => SandboxStatus::NonZeroExit,
            }
        }
    }
}

/// Cancel a running sandbox (idempotent).
pub(crate) fn cancel(entry: &Arc<SandboxEntry>) {
    entry.cancel.cancel();
    if let Some(running) = entry
        .running
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
    {
        if !running.process.is_finished() {
            running.process.cancel();
        }
    }
}

/// Public cleanup entry point (retryable after failure).
pub(crate) async fn cleanup_entry(
    entry: &Arc<SandboxEntry>,
    provider: &Arc<dyn SandboxProvider>,
) -> Result<Vec<Diagnostic>, SandboxError> {
    let state = entry.state();
    if !matches!(state, SandboxState::Completed | SandboxState::Failed) {
        return Err(SandboxError::InvalidOperation {
            id: entry.id,
            state,
            required: "Completed or Failed",
        });
    }
    let manager = CleanupManager::new(provider.name());
    let diags = manager.cleanup(entry, provider).await?;
    if !entry.cleanup_done.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(SandboxError::Cleanup(diags));
    }
    // Retry path: Failed → Cleaning → Completed.
    if entry.state() == SandboxState::Failed {
        let _ = entry.transition(SandboxState::Cleaning);
        let _ = entry.transition(SandboxState::Completed);
    }
    Ok(diags)
}

/// Small helper: duration formatting for logs.
#[allow(dead_code)]
fn fmt_duration(d: Duration) -> String {
    format!("{}ms", d.as_millis())
}

// Silence unused ExitInfo import in some cfgs.
#[allow(unused_imports)]
use ExitInfo as _ExitInfo;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn status_mapping_is_evidence_based() {
        let exit_ok = ExecOutcome {
            pid: 1,
            exit: ExitInfo::from_exit_code(0),
            wall_time: Duration::from_millis(10),
            reason: OutcomeReason::Exit,
            output: Default::default(),
        };
        assert_eq!(
            derive_status(&exit_ok, &ResourceUsage::default(), false),
            SandboxStatus::Success
        );

        let exit_err = ExecOutcome {
            exit: ExitInfo::from_exit_code(2),
            ..exit_ok.clone()
        };
        assert_eq!(
            derive_status(&exit_err, &ResourceUsage::default(), false),
            SandboxStatus::NonZeroExit
        );

        // SIGXCPU → CpuLimitExceeded (deterministic).
        let cpu_kill = ExecOutcome {
            exit: ExitInfo::from_signal(SIGXCPU, false),
            ..exit_ok.clone()
        };
        assert_eq!(
            derive_status(&cpu_kill, &ResourceUsage::default(), false),
            SandboxStatus::CpuLimitExceeded
        );

        // SIGKILL alone is NOT proof of OOM (§7.4): stays NonZeroExit.
        let sigkill = ExecOutcome {
            exit: ExitInfo::from_signal(9, false),
            ..exit_ok.clone()
        };
        assert_eq!(
            derive_status(&sigkill, &ResourceUsage::default(), false),
            SandboxStatus::NonZeroExit
        );

        // But a kernel-confirmed OOM event is.
        let oom_usage = ResourceUsage {
            oom_events: Some(1),
            ..Default::default()
        };
        assert_eq!(
            derive_status(&sigkill, &oom_usage, false),
            SandboxStatus::MemoryLimitExceeded
        );

        // Kernel-confirmed pid-limit hits are.
        let pids_usage = ResourceUsage {
            pids_limit_hits: Some(3),
            ..Default::default()
        };
        assert_eq!(
            derive_status(&sigkill, &pids_usage, false),
            SandboxStatus::ProcessLimitExceeded
        );

        // Cancellation.
        let cancelled = ExecOutcome {
            reason: OutcomeReason::CancelRequested,
            ..exit_ok.clone()
        };
        assert_eq!(
            derive_status(&cancelled, &ResourceUsage::default(), true),
            SandboxStatus::Cancelled
        );
    }

    #[test]
    fn provider_confirmed_kills_classify_by_evidence() {
        let external_kill = ExecOutcome {
            exit: ExitInfo::from_exit_code(1),
            reason: OutcomeReason::Terminated(nsk_supervisor::terminate::TerminateKind::External),
            ..ExecOutcome {
                pid: 1,
                exit: ExitInfo::from_exit_code(0),
                wall_time: Duration::from_millis(10),
                reason: OutcomeReason::Exit,
                output: Default::default(),
            }
        };

        // Watchdog-confirmed memory kill → deterministic memory status.
        let mem_usage = ResourceUsage {
            oom_events: Some(1),
            ..Default::default()
        };
        assert_eq!(
            derive_status(&external_kill, &mem_usage, false),
            SandboxStatus::MemoryLimitExceeded
        );

        // Watchdog-confirmed process kill → deterministic process status.
        let pid_usage = ResourceUsage {
            pids_limit_hits: Some(1),
            ..Default::default()
        };
        assert_eq!(
            derive_status(&external_kill, &pid_usage, false),
            SandboxStatus::ProcessLimitExceeded
        );

        // Without evidence the kill stays NonZeroExit (no guessing, §7.4).
        assert_eq!(
            derive_status(&external_kill, &ResourceUsage::default(), false),
            SandboxStatus::NonZeroExit
        );

        // Cancellation wins over evidence (user asked for it).
        assert_eq!(
            derive_status(&external_kill, &mem_usage, true),
            SandboxStatus::Cancelled
        );
    }
}
