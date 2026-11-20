//! Execution result types (design document §5.8, §5.9 and §7.2).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::diagnostic::Diagnostic;
use crate::id::SandboxId;

/// Final status of a sandbox execution (§5.9).
///
/// The status is derived from reliable evidence only: exit codes, termination
/// signals, and provider-reported limit events. An exit code alone is never
/// treated as proof of an OOM (§7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStatus {
    /// Program exited with code 0.
    Success,
    /// Program exited with a non-zero code or a signal.
    NonZeroExit,
    /// Wall-time deadline exceeded.
    TimeLimitExceeded,
    /// CPU-time budget exceeded (SIGXCPU / cgroup accounting).
    CpuLimitExceeded,
    /// Memory limit enforced (confirmed OOM event or provider report).
    MemoryLimitExceeded,
    /// Process/PID limit enforced.
    ProcessLimitExceeded,
    /// Output limit enforced.
    OutputLimitExceeded,
    /// File-size or disk limit enforced.
    DiskLimitExceeded,
    /// Cancelled by the caller.
    Cancelled,
    /// The program could not be started.
    SpawnFailed,
    /// Required isolation could not be established (fail-closed).
    IsolationFailed,
    /// A mandatory resource limit could not be applied (fail-closed).
    ResourceLimitUnavailable,
    /// Unexpected kernel error.
    InternalError,
}

impl SandboxStatus {
    /// True when the status means the kernel itself refused or failed.
    pub fn is_kernel_failure(self) -> bool {
        matches!(
            self,
            SandboxStatus::SpawnFailed
                | SandboxStatus::IsolationFailed
                | SandboxStatus::ResourceLimitUnavailable
                | SandboxStatus::InternalError
        )
    }
}

/// How the child process terminated (§5.8 ExitInfo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitInfo {
    /// Exit code, when the process exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal number (Unix), `None` on normal exit or Windows.
    pub signal: Option<i32>,
    /// True when a core dump was produced.
    pub core_dumped: bool,
}

impl ExitInfo {
    pub fn from_exit_code(code: i32) -> Self {
        Self {
            exit_code: Some(code),
            signal: None,
            core_dumped: false,
        }
    }

    pub fn from_signal(signal: i32, core_dumped: bool) -> Self {
        Self {
            exit_code: None,
            signal: Some(signal),
            core_dumped,
        }
    }
}

/// Observed resource usage (§7.2).
///
/// Fields are `Option` because every provider can only observe what its
/// platform exposes; absence is information, not zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub wall_time: Duration,
    pub cpu_time: Option<Duration>,
    pub memory_current_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub process_count: Option<u32>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub disk_usage_bytes: Option<u64>,
    /// Confirmed OOM kill events observed by the provider (cgroup memory.events).
    pub oom_events: Option<u64>,
    /// Confirmed PID-limit hits (cgroup pids.events `max` counter).
    pub pids_limit_hits: Option<u64>,
}

impl ResourceUsage {
    /// Combined output byte count.
    pub fn output_bytes(&self) -> u64 {
        self.stdout_bytes + self.stderr_bytes
    }
}

/// Retained output of one stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputData {
    /// Total bytes produced by the program (may exceed `retained.len()`).
    pub total_bytes: u64,
    /// Bounded retained prefix of the stream.
    pub retained: Vec<u8>,
    /// True when the stream was truncated (limit hit or retention cap).
    pub truncated: bool,
}

impl OutputData {
    /// Interpret retained bytes as UTF-8 (lossy) for display.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.retained).into_owned()
    }
}

/// Collected stdout/stderr result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputResult {
    pub stdout: OutputData,
    pub stderr: OutputData,
}

/// The complete result of one sandbox execution (§5.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub id: SandboxId,
    pub status: SandboxStatus,
    pub exit_info: Option<ExitInfo>,
    pub resource_usage: ResourceUsage,
    pub output: OutputResult,
    pub diagnostics: Vec<Diagnostic>,
}

impl SandboxResult {
    /// Create an empty result scaffold for `id`.
    pub fn new(id: SandboxId, status: SandboxStatus) -> Self {
        Self {
            id,
            status,
            exit_info: None,
            resource_usage: ResourceUsage::default(),
            output: OutputResult::default(),
            diagnostics: Vec::new(),
        }
    }

    /// Push a diagnostic and return the mutated result.
    pub fn with_diagnostic(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn status_classification() {
        assert!(!SandboxStatus::Success.is_kernel_failure());
        assert!(SandboxStatus::IsolationFailed.is_kernel_failure());
        assert!(SandboxStatus::InternalError.is_kernel_failure());
    }

    #[test]
    fn exit_info_builders() {
        let e = ExitInfo::from_exit_code(0);
        assert_eq!(e.exit_code, Some(0));
        let e = ExitInfo::from_signal(9, false);
        assert_eq!(e.signal, Some(9));
        assert!(!e.core_dumped);
    }

    #[test]
    fn usage_output_totals() {
        let u = ResourceUsage {
            stdout_bytes: 10,
            stderr_bytes: 5,
            ..Default::default()
        };
        assert_eq!(u.output_bytes(), 15);
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = SandboxResult::new(SandboxId::new(), SandboxStatus::TimeLimitExceeded)
            .with_diagnostic(Diagnostic::warning(
                crate::diagnostic::codes::CANCEL_REQUESTED,
                "wall time exceeded",
            ));
        let json = serde_json::to_string(&r).unwrap();
        let back: SandboxResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, SandboxStatus::TimeLimitExceeded);
        assert_eq!(back.diagnostics.len(), 1);
    }
}
