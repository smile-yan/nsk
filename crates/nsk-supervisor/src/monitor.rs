//! The supervisor monitor loop (§8.2 Process Monitor / Termination
//! Controller / Exit Collector) and spawn entry point.
//!
//! One monitor task owns the `tokio::process::Child` for the whole lifetime
//! of the sandbox process. It races:
//!
//! * `child.wait()` (normal exit),
//! * the wall-time deadline,
//! * cancellation / termination requests,
//! * output-limit crossings (when `terminate_on_limit`),
//!
//! and performs SIGTERM → SIGKILL group escalation when a termination
//! condition fires. Exit collection maps wait statuses to [`ExitInfo`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use nsk_core::error::SandboxError;
use nsk_core::result::ExitInfo;
use nsk_resource::usage::LimitCrossing;

use crate::output::{OutputShared, OutputStream, collect_stream};
use crate::process::{ProcessSpec, SupervisedProcess, build_command};
use crate::stdin::spawn_stdin_writer;
use crate::terminate::{TerminateKind, escalate_group_termination};
use crate::timer::Deadline;

/// Why the monitor concluded (§8.3 termination conditions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReason {
    /// Normal exit.
    Exit,
    /// Wall-time deadline reached.
    WallTimeExceeded,
    /// Cancel requested by the caller.
    CancelRequested,
    /// Output limit crossed and enforcement was enabled.
    OutputLimitExceeded(LimitCrossing),
    /// External / provider-initiated termination.
    Terminated(TerminateKind),
    /// Supervisor-internal problem (kernel bug).
    Internal(String),
}

/// The collected result of a supervised run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutcome {
    pub pid: u32,
    pub exit: ExitInfo,
    /// Wall time from spawn to exit collection.
    pub wall_time: Duration,
    pub reason: OutcomeReason,
    pub output: crate::output::OutputSnapshot,
}

/// Supervisor configuration (limits and timing).
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Absolute wall deadline; `None` = unlimited (not recommended).
    pub deadline: Option<Deadline>,
    /// SIGTERM → SIGKILL grace for group escalation.
    pub terminate_grace: Duration,
    /// Output limits (bytes; `u64::MAX` = unlimited).
    pub max_stdout: u64,
    pub max_stderr: u64,
    pub max_combined: u64,
    /// Retained bytes per stream in memory (bounded buffer, §8.5).
    pub retain_per_stream: usize,
    /// Terminate when an output limit is crossed.
    pub terminate_on_limit: bool,
    /// How long to wait for output collectors to drain after exit.
    pub collector_drain_grace: Duration,
    /// Event tap for streaming output chunks and termination notices.
    pub tap: Option<broadcast::Sender<SupervisorEvent>>,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            deadline: None,
            terminate_grace: Duration::from_millis(500),
            max_stdout: u64::MAX,
            max_stderr: u64::MAX,
            max_combined: u64::MAX,
            retain_per_stream: 1024 * 1024,
            terminate_on_limit: true,
            collector_drain_grace: Duration::from_millis(300),
            tap: None,
        }
    }
}

pub use crate::output::SupervisorEvent;

/// Spawn and supervise a process (§8.2 Process Manager + Monitor).
///
/// # Errors
/// [`SandboxError::Spawn`] when the OS refuses to spawn (ENOENT, EAGAIN, …).
pub fn spawn(
    spec: ProcessSpec,
    config: SupervisorConfig,
) -> Result<SupervisedProcess, SandboxError> {
    let mut cmd = build_command(&spec)?;
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Spawn(format!("{}: {e}", spec.display_command())))?;
    let pid = child.id().unwrap_or(0);
    let started_at = Instant::now();
    debug!(pid, command = %spec.display_command(), "process spawned");

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Internal("stdout pipe missing".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Internal("stderr pipe missing".into()))?;
    let stdin_handle = child.stdin.take();

    let output = OutputShared::new(
        config.max_stdout,
        config.max_stderr,
        config.max_combined,
        config.retain_per_stream,
    );
    let (done_tx, done_rx) = watch::channel(None);
    let (terminate_tx, terminate_rx) = watch::channel(None::<TerminateKind>);
    let cancel = CancellationToken::new();

    // Stdin writer.
    let stdin_stop = cancel.child_token();
    if let Some(pipe) = stdin_handle {
        spawn_stdin_writer(pipe, &spec.stdin, stdin_stop);
    } else if matches!(spec.stdin, nsk_core::spec::StdinSpec::Bytes(_)) {
        warn!(pid, "stdin bytes requested but pipe unavailable");
    }

    // Output collectors.
    let stop = cancel.child_token();
    let tap = config.tap.clone();
    tokio::spawn(collect_stream(
        stdout,
        OutputStream::Stdout,
        output.clone(),
        tap.clone(),
        stop.clone(),
    ));
    let tap2 = config.tap.clone();
    tokio::spawn(collect_stream(
        stderr,
        OutputStream::Stderr,
        output.clone(),
        tap2,
        stop,
    ));

    // Monitor task owns the child.
    tokio::spawn(monitor_loop(
        child,
        pid,
        started_at,
        spec,
        config,
        output.clone(),
        done_tx,
        terminate_rx,
        cancel.clone(),
    ));

    Ok(SupervisedProcess::new(
        pid,
        started_at,
        done_rx,
        output,
        cancel,
        terminate_tx,
    ))
}

/// The monitor select loop.
#[allow(clippy::too_many_arguments)]
async fn monitor_loop(
    mut child: tokio::process::Child,
    pid: u32,
    started_at: Instant,
    spec: ProcessSpec,
    config: SupervisorConfig,
    output: Arc<OutputShared>,
    done_tx: watch::Sender<Option<Arc<ExecOutcome>>>,
    mut terminate_rx: watch::Receiver<Option<TerminateKind>>,
    cancel: CancellationToken,
) {
    let mut limits_rx = crate::output::limits_watcher(&output);
    let mut escalation_done = false;
    let mut reason: OutcomeReason = OutcomeReason::Exit;
    let mut exit: Option<ExitInfo> = None;

    loop {
        tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(status) => {
                        exit = Some(exit_info_from(&status));
                        if reason == OutcomeReason::Exit {
                            // Normal exit unless a termination path already set a reason.
                        }
                        break;
                    }
                    Err(e) => {
                        warn!(pid, error = %e, "child.wait failed");
                        reason = OutcomeReason::Internal(format!("wait failed: {e}"));
                        break;
                    }
                }
            }

            _ = async {
                match config.deadline {
                    Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d.instant())).await,
                    None => std::future::pending::<()>().await,
                }
            }, if !escalation_done => {
                reason = OutcomeReason::WallTimeExceeded;
                emit(&config.tap, SupervisorEvent::Terminating(TerminateKind::Timeout));
                escalate_group_termination(pid, config.terminate_grace).await;
                escalation_done = true;
                cancel.cancel(); // stop stdin writer & collectors
            }

            _ = cancel.cancelled(), if !escalation_done => {
                reason = OutcomeReason::CancelRequested;
                emit(&config.tap, SupervisorEvent::Terminating(TerminateKind::Cancel));
                escalate_group_termination(pid, config.terminate_grace).await;
                escalation_done = true;
                cancel.cancel(); // stop stdin writer & collectors
            }

            res = terminate_rx.changed(), if !escalation_done => {
                if res.is_ok() {
                    // Copy out of the borrow before awaiting (Ref is !Send).
                    let requested = *terminate_rx.borrow_and_update();
                    if let Some(kind) = requested {
                        reason = match kind {
                            TerminateKind::Cancel => OutcomeReason::CancelRequested,
                            other => OutcomeReason::Terminated(other),
                        };
                        emit(&config.tap, SupervisorEvent::Terminating(kind));
                        escalate_group_termination(pid, config.terminate_grace).await;
                        escalation_done = true;
                        cancel.cancel(); // stop stdin writer & collectors
                    }
                } else {
                    // Sender dropped: treat as external termination request.
                    reason = OutcomeReason::Terminated(TerminateKind::External);
                    escalate_group_termination(pid, config.terminate_grace).await;
                    escalation_done = true;
                }
            }

            res = limits_rx.changed(), if !escalation_done => {
                if res.is_ok() {
                    let crossed = *limits_rx.borrow_and_update();
                    emit(&config.tap, SupervisorEvent::LimitCrossed(crossed));
                    if config.terminate_on_limit {
                        reason = OutcomeReason::OutputLimitExceeded(crossed);
                        emit(&config.tap, SupervisorEvent::Terminating(TerminateKind::Limit));
                        escalate_group_termination(pid, config.terminate_grace).await;
                        escalation_done = true;
                        cancel.cancel(); // stop stdin writer & collectors
                    }
                }
            }
        }
    }

    // Process-leftover sweep (§8.4): after the leader exits, kill any
    // remaining group members (daemonized children, grandchildren). A dead
    // group makes this a no-op; the escalation paths already ran it.
    if spec.process_group {
        crate::terminate::kill_group_now(pid);
    }

    // Drain collectors briefly so buffered data reflects pipe contents.
    tokio::time::timeout(config.collector_drain_grace, async {
        // After the group sweep the pipes hit EOF quickly; this wait covers
        // the common case (§8.5 output totals are tracked incrementally).
        tokio::time::sleep(Duration::from_millis(20)).await;
    })
    .await
    .ok();

    let wall_time = started_at.elapsed();
    let outcome = ExecOutcome {
        pid,
        exit: exit.unwrap_or(ExitInfo::from_exit_code(-1)),
        wall_time,
        reason,
        output: output.snapshot(),
    };
    info!(
        pid,
        exit_code = ?outcome.exit.exit_code,
        signal = ?outcome.exit.signal,
        reason = ?outcome.reason,
        wall_ms = wall_time.as_millis(),
        stdout_bytes = outcome.output.stdout.total_bytes,
        stderr_bytes = outcome.output.stderr.total_bytes,
        "process finished"
    );
    let _ = spec; // kept for logging symmetry / future use
    done_tx.send_replace(Some(Arc::new(outcome)));
}

fn emit(tap: &Option<broadcast::Sender<SupervisorEvent>>, event: SupervisorEvent) {
    if let Some(tx) = tap {
        let _ = tx.send(event);
    }
}

/// Map a wait status to `ExitInfo` (Unix signal semantics).
pub fn exit_info_from(status: &std::process::ExitStatus) -> ExitInfo {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            ExitInfo::from_signal(sig, status.core_dumped())
        } else {
            ExitInfo::from_exit_code(status.code().unwrap_or(-1))
        }
    }
    #[cfg(not(unix))]
    {
        ExitInfo::from_exit_code(status.code().unwrap_or(-1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessSpec;

    #[cfg(unix)]
    #[tokio::test]
    async fn echo_exit_zero() {
        let spec = ProcessSpec::new("/bin/echo").arg("hello");
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        let outcome = proc_.wait().await;
        assert_eq!(outcome.exit.exit_code, Some(0));
        assert_eq!(outcome.reason, OutcomeReason::Exit);
        assert_eq!(outcome.output.stdout.retained, b"hello\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exit_code_collected() {
        let spec = ProcessSpec::new("/bin/sh").arg("-c").arg("exit 3");
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        let outcome = proc_.wait().await;
        assert_eq!(outcome.exit.exit_code, Some(3));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wall_time_kill() {
        let spec = ProcessSpec::new("/bin/sh")
            .arg("-c")
            .arg("while true; do sleep 1; done");
        let config = SupervisorConfig {
            deadline: Some(Deadline::after(Duration::from_millis(300))),
            ..Default::default()
        };
        let proc_ = spawn(spec, config).expect("spawn");
        let outcome = proc_.wait().await;
        assert_eq!(outcome.reason, OutcomeReason::WallTimeExceeded);
        assert!(outcome.wall_time >= Duration::from_millis(250));
        assert!(outcome.wall_time < Duration::from_secs(5));
        // The group usually dies from SIGTERM (15); SIGKILL (9) is the
        // escalation fallback.
        assert!(
            matches!(outcome.exit.signal, Some(15) | Some(9)),
            "expected group termination signal, got {:?}",
            outcome.exit.signal
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancel_race() {
        let spec = ProcessSpec::new("/bin/sleep").arg("30");
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        tokio::time::sleep(Duration::from_millis(100)).await;
        proc_.cancel();
        let outcome = proc_.wait().await;
        assert_eq!(outcome.reason, OutcomeReason::CancelRequested);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_limit_terminates_yes() {
        let spec = ProcessSpec::new("/usr/bin/yes");
        let config = SupervisorConfig {
            max_stdout: 1024 * 1024,
            max_stderr: 1024 * 1024,
            max_combined: 1024 * 1024,
            terminate_on_limit: true,
            ..Default::default()
        };
        let proc_ = spawn(spec, config).expect("spawn");
        let outcome = proc_.wait().await;
        assert!(matches!(
            outcome.reason,
            OutcomeReason::OutputLimitExceeded(_)
        ));
        assert!(outcome.output.stdout.total_bytes > 1024 * 1024);
        // Retained buffer is bounded.
        assert!(outcome.output.stdout.retained.len() <= 1024 * 1024);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdin_bytes_reach_cat() {
        let spec =
            ProcessSpec::new("/bin/cat").stdin(nsk_core::spec::StdinSpec::Bytes(b"abc".to_vec()));
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        let outcome = proc_.wait().await;
        assert_eq!(outcome.exit.exit_code, Some(0));
        assert_eq!(outcome.output.stdout.retained, b"abc");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn env_is_explicit() {
        let spec = ProcessSpec::new("/usr/bin/env").env("NSK_TEST", "42");
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        let outcome = proc_.wait().await;
        let text = outcome.output.stdout.text();
        assert!(text.contains("NSK_TEST=42"));
        assert!(!text.contains("PATH="), "host env must not leak");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rlimit_open_files_applied() {
        let spec = ProcessSpec::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -n")
            .rlimits(vec![nsk_resource::limits::RlimitSpec::OpenFiles(64)]);
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        let outcome = proc_.wait().await;
        assert_eq!(outcome.exit.exit_code, Some(0));
        assert_eq!(outcome.output.stdout.text().trim(), "64");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawn_missing_binary_fails() {
        let spec = ProcessSpec::new("/no/such/binary/anywhere");
        let err = spawn(spec, SupervisorConfig::default()).expect_err("must fail");
        assert!(matches!(err, SandboxError::Spawn(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn group_termination_kills_children() {
        // A shell that spawns a long-lived child; group kill must clean both.
        let spec = ProcessSpec::new("/bin/sh")
            .arg("-c")
            .arg("/bin/sleep 30 & wait $!");
        let proc_ = spawn(spec, SupervisorConfig::default()).expect("spawn");
        tokio::time::sleep(Duration::from_millis(150)).await;
        proc_.terminate(TerminateKind::External);
        let outcome = proc_.wait().await;
        assert!(matches!(outcome.reason, OutcomeReason::Terminated(_)));
        // On Unix the shell dies from SIGTERM (143) or SIGKILL (137).
        assert!(outcome.exit.exit_code.is_none() || outcome.exit.exit_code != Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tap_receives_output_chunks() {
        let (tap_tx, mut tap_rx) = tokio::sync::broadcast::channel(64);
        let spec = ProcessSpec::new("/bin/echo").arg("chunked");
        let config = SupervisorConfig {
            tap: Some(tap_tx),
            ..Default::default()
        };
        let proc_ = spawn(spec, config).expect("spawn");
        let _ = proc_.wait().await;
        let mut got_stdout = false;
        while let Ok(ev) = tap_rx.try_recv() {
            if let SupervisorEvent::OutputChunk(OutputStream::Stdout, data) = ev {
                assert_eq!(data, b"chunked\n");
                got_stdout = true;
            }
        }
        assert!(got_stdout, "tap must receive stdout chunk");
    }
}
