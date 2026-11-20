//! Limit conversions between policy values and kernel encodings.
//!
//! Design document §5.7 / §10.7: the same logical limit has different
//! encodings per mechanism (cgroups v2 files, rlimits). Conversions live in
//! one place so providers stay consistent.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// rlimit kinds applied pre-exec by the supervisor (Unix).
///
/// Values are clamped to the platform's `rlim_t`; conversions are explicit
/// so the report can say exactly which rlimit was set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RlimitSpec {
    /// RLIMIT_NOFILE — max open file descriptors.
    OpenFiles(u64),
    /// RLIMIT_FSIZE — max single-file size in bytes.
    FileSize(u64),
    /// RLIMIT_CPU — CPU seconds.
    CpuTime(u64),
    /// RLIMIT_AS — address-space bytes (degraded memory enforcement).
    AddressSpace(u64),
    /// RLIMIT_NPROC — max processes for the user (degraded PID enforcement).
    Processes(u64),
}

impl RlimitSpec {
    pub fn name(&self) -> &'static str {
        match self {
            RlimitSpec::OpenFiles(_) => "RLIMIT_NOFILE",
            RlimitSpec::FileSize(_) => "RLIMIT_FSIZE",
            RlimitSpec::CpuTime(_) => "RLIMIT_CPU",
            RlimitSpec::AddressSpace(_) => "RLIMIT_AS",
            RlimitSpec::Processes(_) => "RLIMIT_NPROC",
        }
    }

    pub fn value(&self) -> u64 {
        match *self {
            RlimitSpec::OpenFiles(v)
            | RlimitSpec::FileSize(v)
            | RlimitSpec::CpuTime(v)
            | RlimitSpec::AddressSpace(v)
            | RlimitSpec::Processes(v) => v,
        }
    }
}

/// cgroup v2 `cpu.max` encoding: "$MAX $PERIOD", both in microseconds.
///
/// A quota of `cores` cores maps to `quota_us = cores * period_us`.
/// Standard period: 100 ms (100000 us) — same default used by systemd.
pub fn cpu_quota_to_cgroup_max(cores: f64, period_us: u64) -> String {
    const DEFAULT_PERIOD_US: u64 = 100_000;
    let period = if period_us == 0 {
        DEFAULT_PERIOD_US
    } else {
        period_us
    };
    if cores <= 0.0 {
        return "max".to_string();
    }
    let quota_us = (cores * period as f64).round() as i64;
    if quota_us < 1000 {
        // Request below one millisecond: still enforce a minimal slice.
        return format!("1000 {period}");
    }
    format!("{quota_us} {period}")
}

/// cgroup v2 `cpu.max` for an unlimited quota.
pub const CPU_MAX_UNLIMITED: &str = "max 100000";

/// Convert a CPU-time budget into cgroup-friendly / rlimit seconds.
pub fn duration_to_cgroup_cpu(d: Duration) -> u64 {
    d.as_secs()
}

/// cgroup v2 limit files a sandbox cgroup uses (§10.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupLimitFiles;

impl CgroupLimitFiles {
    pub const MEMORY_MAX: &'static str = "memory.max";
    pub const MEMORY_CURRENT: &'static str = "memory.current";
    pub const MEMORY_EVENTS: &'static str = "memory.events";
    pub const MEMORY_PEAK: &'static str = "memory.peak";
    pub const MEMORY_SWAP_MAX: &'static str = "memory.swap.max";
    pub const CPU_MAX: &'static str = "cpu.max";
    pub const CPU_STAT: &'static str = "cpu.stat";
    pub const PIDS_MAX: &'static str = "pids.max";
    pub const PIDS_CURRENT: &'static str = "pids.current";
    pub const PIDS_EVENTS: &'static str = "pids.events";
    pub const CGROUP_PROCS: &'static str = "cgroup.procs";
    pub const CGROUP_KILL: &'static str = "cgroup.kill";
    pub const CGROUP_SUBTREE_CONTROL: &'static str = "cgroup.subtree_control";
    pub const CGROUP_CONTROLLERS: &'static str = "cgroup.controllers";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_encoding() {
        assert_eq!(cpu_quota_to_cgroup_max(1.0, 100_000), "100000 100000");
        assert_eq!(cpu_quota_to_cgroup_max(2.0, 100_000), "200000 100000");
        assert_eq!(cpu_quota_to_cgroup_max(0.5, 100_000), "50000 100000");
        assert_eq!(cpu_quota_to_cgroup_max(0.0, 100_000), "max");
        assert_eq!(cpu_quota_to_cgroup_max(-1.0, 100_000), "max");
        // Sub-tick quota still enforced.
        let s = cpu_quota_to_cgroup_max(0.001, 100_000);
        assert!(s.starts_with("1000 "), "got {s}");
        // Period 0 falls back to default.
        assert_eq!(cpu_quota_to_cgroup_max(1.0, 0), "100000 100000");
    }

    #[test]
    fn rlimit_names() {
        let r = RlimitSpec::OpenFiles(64);
        assert_eq!(r.name(), "RLIMIT_NOFILE");
        assert_eq!(r.value(), 64);
        assert_eq!(RlimitSpec::CpuTime(5).name(), "RLIMIT_CPU");
        assert_eq!(RlimitSpec::AddressSpace(1).name(), "RLIMIT_AS");
        assert_eq!(RlimitSpec::Processes(16).name(), "RLIMIT_NPROC");
        assert_eq!(RlimitSpec::FileSize(1024).name(), "RLIMIT_FSIZE");
    }

    #[test]
    fn cpu_duration() {
        assert_eq!(duration_to_cgroup_cpu(Duration::from_millis(1500)), 1);
    }
}
