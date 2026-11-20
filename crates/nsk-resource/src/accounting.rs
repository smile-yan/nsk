//! Usage accounting: aggregate snapshots into peak statistics (§7.2).

use std::time::Duration;

use nsk_core::result::ResourceUsage;

/// Accumulates usage snapshots, keeping observed peaks (§7.4).
#[derive(Debug, Default, Clone)]
pub struct UsageAccountant {
    wall_time: Duration,
    cpu_time: Option<Duration>,
    memory_peak: Option<u64>,
    memory_current: Option<u64>,
    process_count: Option<u32>,
    process_peak: Option<u32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    disk_usage: Option<u64>,
    oom_events: u64,
    pids_limit_hits: u64,
}

impl UsageAccountant {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge one snapshot. Monotonic fields (bytes written) are maxed;
    /// peaks are updated; OOM / pids counters accumulate the max.
    pub fn observe(&mut self, usage: &ResourceUsage) {
        if usage.wall_time > self.wall_time {
            self.wall_time = usage.wall_time;
        }
        if let Some(cpu) = usage.cpu_time {
            self.cpu_time = Some(self.cpu_time.map_or(cpu, |prev| prev.max(cpu)));
        }
        if let Some(cur) = usage.memory_current_bytes {
            self.memory_current = Some(cur);
        }
        if let Some(peak) = usage.memory_peak_bytes {
            self.memory_peak = Some(self.memory_peak.map_or(peak, |prev| prev.max(peak)));
        } else if let Some(cur) = usage.memory_current_bytes {
            self.memory_peak = Some(self.memory_peak.map_or(cur, |prev| prev.max(cur)));
        }
        if let Some(count) = usage.process_count {
            self.process_count = Some(count);
            self.process_peak = Some(self.process_peak.unwrap_or(0).max(count));
        }
        self.stdout_bytes = self.stdout_bytes.max(usage.stdout_bytes);
        self.stderr_bytes = self.stderr_bytes.max(usage.stderr_bytes);
        if let Some(disk) = usage.disk_usage_bytes {
            self.disk_usage = Some(self.disk_usage.map_or(disk, |prev| prev.max(disk)));
        }
        if let Some(oom) = usage.oom_events {
            self.oom_events = self.oom_events.max(oom);
        }
        if let Some(hits) = usage.pids_limit_hits {
            self.pids_limit_hits = self.pids_limit_hits.max(hits);
        }
    }

    /// Current aggregated view.
    pub fn snapshot(&self) -> ResourceUsage {
        ResourceUsage {
            wall_time: self.wall_time,
            cpu_time: self.cpu_time,
            memory_current_bytes: self.memory_current,
            memory_peak_bytes: self.memory_peak,
            process_count: self.process_count,
            stdout_bytes: self.stdout_bytes,
            stderr_bytes: self.stderr_bytes,
            disk_usage_bytes: self.disk_usage,
            oom_events: if self.oom_events > 0 {
                Some(self.oom_events)
            } else {
                None
            },
            pids_limit_hits: if self.pids_limit_hits > 0 {
                Some(self.pids_limit_hits)
            } else {
                None
            },
        }
    }

    pub fn memory_peak(&self) -> Option<u64> {
        self.memory_peak
    }

    pub fn process_peak(&self) -> Option<u32> {
        self.process_peak
    }

    pub fn oom_events(&self) -> u64 {
        self.oom_events
    }

    pub fn pids_limit_hits(&self) -> u64 {
        self.pids_limit_hits
    }
}

/// Alias kept for naming clarity at call sites (§7.3 Usage Accounting).
pub type UsageSnapshotAccumulator = UsageAccountant;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(wall_ms: u64, mem: Option<u64>, pids: Option<u32>) -> ResourceUsage {
        ResourceUsage {
            wall_time: Duration::from_millis(wall_ms),
            cpu_time: None,
            memory_current_bytes: mem,
            memory_peak_bytes: None,
            process_count: pids,
            stdout_bytes: 0,
            stderr_bytes: 0,
            disk_usage_bytes: None,
            oom_events: None,
            pids_limit_hits: None,
        }
    }

    #[test]
    fn keeps_peaks() {
        let mut acc = UsageAccountant::new();
        acc.observe(&sample(100, Some(1024), Some(3)));
        acc.observe(&sample(200, Some(512), Some(9)));
        acc.observe(&sample(150, Some(2048), Some(1)));
        let snap = acc.snapshot();
        assert_eq!(snap.wall_time, Duration::from_millis(200));
        assert_eq!(snap.memory_peak_bytes, Some(2048));
        assert_eq!(snap.memory_current_bytes, Some(2048));
        assert_eq!(snap.process_count, Some(1));
        assert_eq!(acc.process_peak(), Some(9));
    }

    #[test]
    fn accumulates_oom_and_pids_events() {
        let mut acc = UsageAccountant::new();
        let mut u1 = sample(10, None, None);
        u1.oom_events = Some(1);
        u1.pids_limit_hits = Some(4);
        acc.observe(&u1);
        let mut u2 = sample(20, None, None);
        u2.oom_events = Some(0);
        u2.pids_limit_hits = Some(2);
        acc.observe(&u2);
        assert_eq!(acc.oom_events(), 1);
        assert_eq!(acc.pids_limit_hits(), 4);
        let snap = acc.snapshot();
        assert_eq!(snap.oom_events, Some(1));
    }

    #[test]
    fn oom_absent_when_zero() {
        let mut acc = UsageAccountant::new();
        let mut u = sample(10, None, None);
        u.oom_events = Some(0);
        acc.observe(&u);
        assert_eq!(acc.snapshot().oom_events, None);
    }

    #[test]
    fn output_bytes_maxed() {
        let mut acc = UsageAccountant::new();
        let mut u1 = sample(10, None, None);
        u1.stdout_bytes = 500;
        u1.stderr_bytes = 100;
        acc.observe(&u1);
        let mut u2 = sample(10, None, None);
        u2.stdout_bytes = 300;
        u2.stderr_bytes = 200;
        acc.observe(&u2);
        let snap = acc.snapshot();
        assert_eq!(snap.stdout_bytes, 500);
        assert_eq!(snap.stderr_bytes, 200);
    }
}
