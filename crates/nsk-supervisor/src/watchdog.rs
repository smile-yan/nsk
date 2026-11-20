//! Reactive enforcement watchdogs for the macOS provider (§7.2/§7.4).
//!
//! macOS has no preventive per-process-tree memory or process-count
//! mechanism (no cgroups, no Job Objects; `RLIMIT_AS`/`RLIMIT_NPROC` are
//! unusable — see `docs/macos-provider.md`). The provider therefore offers
//! *reactive* enforcement: a poll loop observes the sandbox tree and kills
//! it when a limit is exceeded. This has an enforcement window (overshoot
//! between polls) — it is recorded honestly in the applied policy
//! (`RESOURCE_LIMIT_DEGRADED`) and in the capability report
//! (`memory_watchdog` / `process_watchdog`).
//!
//! Evidence discipline (§7.4): a watchdog kill is only reported as a limit
//! event when the watchdog itself confirmed the exceedance — the counters in
//! [`WatchdogEvidence`] are the single source for `oom_events` /
//! `pids_limit_hits` in the collected usage.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

/// Confirmed watchdog events, merged into `ResourceUsage` on collect.
#[derive(Debug, Default)]
pub struct WatchdogEvidence {
    /// Confirmed memory-limit kills (maps to `oom_events`).
    pub memory_kills: AtomicU64,
    /// Confirmed process-limit kills (maps to `pids_limit_hits`).
    pub process_kills: AtomicU64,
    /// Peak observed memory (bytes; physical footprint), if any.
    pub peak_memory: AtomicU64,
}

impl WatchdogEvidence {
    pub fn snapshot(&self) -> (Option<u64>, Option<u64>, Option<u64>) {
        let mem = self.memory_kills.load(Ordering::SeqCst);
        let pids = self.process_kills.load(Ordering::SeqCst);
        let peak = self.peak_memory.load(Ordering::SeqCst);
        (
            (mem > 0).then_some(mem),
            (pids > 0).then_some(pids),
            (peak > 0).then_some(peak),
        )
    }
}

/// One watchdog configuration; `None` = not armed.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogLimits {
    /// Memory limit in bytes (physical footprint, cgroup `memory.current`
    /// semantics closest available on macOS).
    pub memory_bytes: Option<u64>,
    /// Max processes in the sandbox process group (including the leader).
    pub max_processes: Option<u32>,
}

impl WatchdogLimits {
    pub fn is_armed(&self) -> bool {
        self.memory_bytes.is_some() || self.max_processes.is_some()
    }
}

/// Current physical footprint of a process (bytes), `None` when the pid is
/// gone (or the process is fully reaped).
///
/// SAFETY: `proc_pid_rusage` fills a caller-provided `rusage_info_v0`
/// buffer; no allocation, no retained pointers.
fn resident_footprint(pid: u32) -> Option<u64> {
    use libc::{RUSAGE_INFO_V0, rusage_info_v0};
    // SAFETY: FFI with a valid pid and an aligned, zeroed buffer of the
    // documented flavor size; the call does not retain the pointer.
    unsafe {
        let mut info: rusage_info_v0 = std::mem::zeroed();
        let rc = libc::proc_pid_rusage(
            pid as libc::c_int,
            RUSAGE_INFO_V0,
            &mut info as *mut rusage_info_v0 as *mut libc::rusage_info_t,
        );
        if rc == 0 {
            // Physical footprint is the closest analog to cgroup
            // memory.current (includes compressed pages).
            Some(info.ri_phys_footprint)
        } else {
            None
        }
    }
}

/// The sandbox process group: pids whose pgid equals the sandbox leader's
/// pgid. The group id equals the leader's pid (the supervisor spawns the
/// child as process-group leader).
fn group_members(pgid: u32) -> Option<Vec<u32>> {
    // 20k pids is far above any macOS pid_limit default; sized once.
    const MAX_PIDS: usize = 20_000;
    let mut buf = vec![0 as libc::pid_t; MAX_PIDS];
    // SAFETY: buffer is writable for the returned count; the API never
    // retains the pointer.
    let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr().cast(), MAX_PIDS as libc::c_int) };
    if n <= 0 {
        return None;
    }
    let mut members = Vec::new();
    for pid in buf.iter().take(n as usize) {
        if *pid <= 0 {
            continue;
        }
        // SAFETY: getpgid on a live pid; ESRCH handled via Ok/Err.
        let g = unsafe { libc::getpgid(*pid) };
        if g == pgid as libc::pid_t {
            members.push(*pid as u32);
        }
    }
    Some(members)
}

/// Aggregate physical footprint over a set of pids (cgroup memory.current
/// analog: sum over the tree). Pids that vanished mid-observation count 0.
fn aggregate_footprint(pids: &[u32]) -> u64 {
    pids.iter().filter_map(|pid| resident_footprint(*pid)).sum()
}

/// Configuration for the watchdog task.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Poll interval. Enforcement window ≈ interval + kill latency.
    pub interval: Duration,
    /// Hard lifetime cap for the watchdog task (backstop against leaks).
    pub max_lifetime: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(150),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

/// Spawn the watchdog task for a running sandbox.
///
/// The task exits when the supervised process finishes, when the shared
/// cancellation token fires, when the pid disappears, or at `max_lifetime`.
/// On exceedance it terminates the process (supervisor escalation —
/// SIGTERM → SIGKILL for the group), records evidence, and exits.
pub fn spawn_watchdog(
    pid: u32,
    process: crate::process::SupervisedProcess,
    limits: WatchdogLimits,
    evidence: Arc<WatchdogEvidence>,
    config: WatchdogConfig,
) {
    if !limits.is_armed() {
        return;
    }
    tokio::spawn(async move {
        let started = Instant::now();
        loop {
            if process.is_finished() {
                debug!(pid, "watchdog: sandbox finished; exiting");
                return;
            }
            if started.elapsed() > config.max_lifetime {
                warn!(pid, "watchdog exceeded lifetime cap; exiting");
                return;
            }
            tokio::time::sleep(config.interval).await;

            // One group enumeration serves both watchdogs (cgroup-style
            // tree-wide accounting: sum over members).
            let members = match group_members(pid) {
                Some(m) if !m.is_empty() => m,
                Some(_) => {
                    // Group leader gone and no members: nothing to enforce.
                    debug!(pid, "watchdog: group empty; exiting");
                    return;
                }
                None => {
                    debug!(pid, "watchdog: group enumeration failed; exiting");
                    return;
                }
            };

            if let Some(limit) = limits.memory_bytes {
                let bytes = aggregate_footprint(&members);
                evidence.peak_memory.fetch_max(bytes, Ordering::SeqCst);
                if bytes > limit {
                    info!(
                        pid,
                        bytes,
                        limit,
                        members = members.len(),
                        "watchdog: memory limit exceeded; killing sandbox"
                    );
                    evidence.memory_kills.fetch_add(1, Ordering::SeqCst);
                    process.terminate(crate::terminate::TerminateKind::External);
                    return;
                }
            }

            if let Some(max) = limits.max_processes {
                let count = members.len() as u32;
                if count > max {
                    info!(
                        pid,
                        count, max, "watchdog: process limit exceeded; killing sandbox"
                    );
                    evidence.process_kills.fetch_add(1, Ordering::SeqCst);
                    process.terminate(crate::terminate::TerminateKind::External);
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn footprint_of_self_is_positive() {
        let bytes = resident_footprint(std::process::id());
        assert!(bytes.is_some(), "proc_pid_rusage must observe self");
        assert!(bytes.unwrap() > 0);
    }

    #[test]
    fn group_members_of_self_is_at_least_one() {
        // This test process is its own group leader in most environments;
        // its pgid is discoverable either way.
        let pgid = unsafe { libc::getpgid(0) };
        let members = group_members(pgid as u32);
        assert!(members.is_some());
        assert!(!members.unwrap().is_empty());
    }

    #[test]
    fn evidence_snapshot_semantics() {
        let e = WatchdogEvidence::default();
        let (oom, pids, peak) = e.snapshot();
        assert_eq!((oom, pids, peak), (None, None, None));
        e.memory_kills.store(1, Ordering::SeqCst);
        e.peak_memory.store(42, Ordering::SeqCst);
        let (oom, pids, peak) = e.snapshot();
        assert_eq!(oom, Some(1));
        assert_eq!(pids, None);
        assert_eq!(peak, Some(42));
    }

    #[tokio::test]
    async fn watchdog_exits_when_process_already_finished() {
        // A finished supervised process makes the watchdog exit promptly.
        let spec = crate::process::ProcessSpec::new("/bin/echo");
        let config = crate::monitor::SupervisorConfig::default();
        let process = crate::monitor::spawn(spec, config).unwrap();
        let _ = process.wait().await;
        let evidence = Arc::new(WatchdogEvidence::default());
        let started = Instant::now();
        spawn_watchdog(
            process.pid(),
            process,
            WatchdogLimits {
                memory_bytes: Some(1024),
                max_processes: None,
            },
            evidence.clone(),
            WatchdogConfig::default(),
        );
        // Wait a few poll periods; no kill evidence may appear.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        let (oom, pids, _) = evidence.snapshot();
        assert_eq!((oom, pids), (None, None));
    }
}
