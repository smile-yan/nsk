//! Pure enforcement decisions: usage + limits → exceeded kinds (§7.3).
//!
//! Note (§7.4): these are *decisions*, not mechanisms. The supervisor and
//! providers own the actual termination paths.

use std::time::Duration;

use nsk_core::event::LimitType;
use nsk_core::result::ResourceUsage;
use serde::{Deserialize, Serialize};

/// A decision derived from observed usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitDecision {
    pub limit: LimitType,
    /// Human-readable evidence (never includes user output content).
    pub evidence: String,
}

/// Evaluate observed usage against limits.
///
/// `wall_deadline` is the exact deadline instant duration (elapsed wall time
/// compared against `wall_time`); `wall_time_limit` is the policy value.
pub fn evaluate_limit_crossings(
    usage: &ResourceUsage,
    wall_time_limit: Duration,
    memory_limit: Option<u64>,
    process_limit: Option<u32>,
    output_combined_limit: Option<u64>,
) -> Vec<LimitDecision> {
    let mut out = Vec::new();

    if usage.wall_time >= wall_time_limit {
        out.push(LimitDecision {
            limit: LimitType::WallTime,
            evidence: format!(
                "wall time {}s >= limit {}s",
                usage.wall_time.as_secs_f64(),
                wall_time_limit.as_secs_f64()
            ),
        });
    }

    if let (Some(limit), Some(peak)) = (memory_limit, usage.memory_peak_bytes) {
        if peak > limit {
            out.push(LimitDecision {
                limit: LimitType::Memory,
                evidence: format!("memory peak {peak} > limit {limit}"),
            });
        }
    }

    if let (Some(limit), Some(count)) = (process_limit, usage.process_count) {
        if count > limit {
            out.push(LimitDecision {
                limit: LimitType::Process,
                evidence: format!("process count {count} > limit {limit}"),
            });
        }
    }

    if let Some(limit) = output_combined_limit {
        let total = usage.output_bytes();
        if total > limit {
            out.push(LimitDecision {
                limit: LimitType::Output,
                evidence: format!("combined output {total} > limit {limit}"),
            });
        }
    }

    // Confirmed OOM events (cgroup memory.events) are always reported.
    if usage.oom_events.unwrap_or(0) > 0 {
        out.push(LimitDecision {
            limit: LimitType::Memory,
            evidence: format!(
                "{} oom kill event(s) recorded by kernel",
                usage.oom_events.unwrap_or(0)
            ),
        });
    }

    // Confirmed PID-limit hits (cgroup pids.events).
    if usage.pids_limit_hits.unwrap_or(0) > 0 {
        out.push(LimitDecision {
            limit: LimitType::Process,
            evidence: format!(
                "pids.events max counter = {}",
                usage.pids_limit_hits.unwrap_or(0)
            ),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(wall_ms: u64) -> ResourceUsage {
        ResourceUsage {
            wall_time: Duration::from_millis(wall_ms),
            ..Default::default()
        }
    }

    #[test]
    fn no_crossings_when_under_limits() {
        let mut u = usage(100);
        u.memory_peak_bytes = Some(1024);
        u.process_count = Some(2);
        u.stdout_bytes = 10;
        u.stderr_bytes = 10;
        let decisions =
            evaluate_limit_crossings(&u, Duration::from_secs(5), Some(4096), Some(16), Some(1000));
        assert!(decisions.is_empty());
    }

    #[test]
    fn wall_time_crossing() {
        let decisions =
            evaluate_limit_crossings(&usage(5000), Duration::from_secs(5), None, None, None);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].limit, LimitType::WallTime);
    }

    #[test]
    fn memory_and_process_and_output() {
        let mut u = usage(100);
        u.memory_peak_bytes = Some(8192);
        u.process_count = Some(32);
        u.stdout_bytes = 900;
        u.stderr_bytes = 200;
        let decisions =
            evaluate_limit_crossings(&u, Duration::from_secs(5), Some(4096), Some(16), Some(1000));
        let kinds: Vec<_> = decisions.iter().map(|d| d.limit).collect();
        assert!(kinds.contains(&LimitType::Memory));
        assert!(kinds.contains(&LimitType::Process));
        assert!(kinds.contains(&LimitType::Output));
        assert_eq!(kinds.len(), 3);
    }

    #[test]
    fn kernel_events_are_confirmed_evidence() {
        let mut u = usage(100);
        u.oom_events = Some(1);
        u.pids_limit_hits = Some(3);
        let decisions = evaluate_limit_crossings(&u, Duration::from_secs(5), None, None, None);
        let kinds: Vec<_> = decisions.iter().map(|d| d.limit).collect();
        assert!(kinds.contains(&LimitType::Memory));
        assert!(kinds.contains(&LimitType::Process));
    }
}
