//! Policy → Job Object limit translation (§11.3).
//!
//! Portable (compiles everywhere, unit-tested everywhere); the Windows-only
//! application lives in [`crate::job`]. Job Objects enforce:
//!
//! * memory — commit-charge based, per-process and job-wide,
//! * active process count — preventive per-tree limit,
//! * CPU rate — hard limit, 1% granularity (CpuRate = percent × 100),
//! * whole-tree termination (KILL_ON_JOB_CLOSE + TerminateJobObject).
//!
//! Job Objects provide **no** filesystem or network isolation (§11.3) —
//! the capability report and resolver encode that honestly.

use serde::{Deserialize, Serialize};

/// Job Object limits derived from the effective policy (§5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobLimits {
    /// Per-process + job-wide commit limit (bytes); `None` = unlimited.
    pub memory_bytes: Option<u64>,
    /// Max processes assigned to the job (including the leader).
    pub max_processes: Option<u32>,
    /// Hard CPU rate limit in percent × 100 (10000 = all cores); `None` =
    /// no rate control.
    pub cpu_rate: Option<u32>,
    /// UI restrictions (clipboard / handles / global atoms / exit windows).
    pub ui_restrictions: bool,
}

impl JobLimits {
    /// Translate the effective policy limits into Job Object values.
    ///
    /// The caller (provider `prepare`) resolved the mechanism ladder: limits
    /// are only translated when the resolver recorded the Job Object as the
    /// enforcing mechanism — this function is pure translation, not policy.
    pub fn from_policy(
        memory_bytes: u64,
        max_processes: u32,
        cpu_quota_cores: Option<f64>,
        ui_restrictions: bool,
    ) -> Self {
        Self {
            memory_bytes: Some(memory_bytes),
            max_processes: Some(max_processes.max(1)),
            cpu_rate: cpu_quota_cores.map(cpu_rate_from_cores),
            ui_restrictions,
        }
    }

    /// Human-readable summary for diagnostics (honest reporting, §15).
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        match self.memory_bytes {
            Some(b) => parts.push(format!("memory={b}B")),
            None => parts.push("memory=unlimited".into()),
        }
        match self.max_processes {
            Some(n) => parts.push(format!("max_processes={n}")),
            None => parts.push("max_processes=unlimited".into()),
        }
        match self.cpu_rate {
            Some(rate) => parts.push(format!("cpu_rate={}%", rate / 100)),
            None => parts.push("cpu_rate=unlimited".into()),
        }
        if self.ui_restrictions {
            parts.push("ui=restricted".into());
        }
        parts.join(", ")
    }
}

/// Convert a CPU quota (cores, possibly fractional) into the Job Object
/// `CpuRate` encoding (percent × 100; minimum 1% = 100).
pub fn cpu_rate_from_cores(cores: f64) -> u32 {
    if cores <= 0.0 {
        return 100; // 1% floor: a non-positive quota is meaningless.
    }
    // Percent = cores × 100; CpuRate = percent × 100 → cores × 10000.
    let rate = (cores * 10_000.0).round() as i64;
    rate.clamp(100, 10_000) as u32
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn cpu_rate_encoding() {
        assert_eq!(cpu_rate_from_cores(1.0), 10_000);
        assert_eq!(cpu_rate_from_cores(0.5), 5_000);
        assert_eq!(cpu_rate_from_cores(0.05), 500);
        assert_eq!(cpu_rate_from_cores(0.0001), 100); // 1% floor
        assert_eq!(cpu_rate_from_cores(0.0), 100);
        assert_eq!(cpu_rate_from_cores(-1.0), 100);
        assert_eq!(cpu_rate_from_cores(2.0), 10_000); // capped at 100%
        assert_eq!(cpu_rate_from_cores(8.0), 10_000);
    }

    #[test]
    fn job_limits_from_policy() {
        let l = JobLimits::from_policy(256 * 1024 * 1024, 16, Some(1.0), true);
        assert_eq!(l.memory_bytes, Some(256 * 1024 * 1024));
        assert_eq!(l.max_processes, Some(16));
        assert_eq!(l.cpu_rate, Some(10_000));
        assert!(l.ui_restrictions);
        assert!(l.describe().contains("memory=268435456B"));
        assert!(l.describe().contains("cpu_rate=100%"));
    }
}
