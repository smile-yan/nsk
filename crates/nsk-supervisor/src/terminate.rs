//! Process-tree termination with escalation (§8.4).
//!
//! On Unix the sandbox child is a process-group leader (see
//! [`crate::process::ProcessSpec::process_group`]); the whole group is
//! signalled: SIGTERM → grace → SIGKILL. Providers that own a stronger
//! mechanism (cgroup `cgroup.kill`) run it first and fall back to this.
//!
//! `Child::kill()` alone is *not* process-tree termination (§7.4); every
//! path here targets the group.

use std::time::Duration;

use tokio::time::sleep;

/// Why termination started (observable via the event tap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminateKind {
    /// Deadline reached.
    Timeout,
    /// Caller requested cancellation.
    Cancel,
    /// A resource/output limit was crossed.
    Limit,
    /// External/provider-requested termination.
    External,
}

impl TerminateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TerminateKind::Timeout => "timeout",
            TerminateKind::Cancel => "cancel",
            TerminateKind::Limit => "limit",
            TerminateKind::External => "external",
        }
    }
}

/// Send a signal to a process group (Unix). No-op on other platforms.
#[cfg(unix)]
pub fn signal_group(pgid: u32, sig: i32) -> std::io::Result<()> {
    // SAFETY: raw syscall wrapper; signalling a pgid we own.
    let rc = unsafe { libc::killpg(pgid as libc::pid_t, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn signal_group(_pgid: u32, _sig: i32) -> std::io::Result<()> {
    Ok(())
}

/// Check whether a process group still exists (ESRCH test).
#[cfg(unix)]
pub fn group_exists(pgid: u32) -> bool {
    // SAFETY: signal 0 probes existence without side effects.
    unsafe { libc::killpg(pgid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
pub fn group_exists(_pgid: u32) -> bool {
    false
}

/// Escalating group termination: SIGTERM, wait `grace` (polling for group
/// exit), SIGKILL. Never reaps — the monitor owns `child.wait()`.
pub async fn escalate_group_termination(pgid: u32, grace: Duration) {
    #[cfg(unix)]
    {
        const SIGTERM: i32 = libc::SIGTERM;
        const SIGKILL: i32 = libc::SIGKILL;

        if signal_group(pgid, SIGTERM).is_err() {
            // Group may already be gone.
            if !group_exists(pgid) {
                return;
            }
        }

        let poll = Duration::from_millis(25);
        let mut waited = Duration::ZERO;
        while waited < grace {
            sleep(poll).await;
            waited += poll;
            if !group_exists(pgid) {
                return;
            }
        }
        let _ = signal_group(pgid, SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = (pgid, grace);
    }
}

/// Immediate SIGKILL for the group (used as last-resort cleanup).
pub fn kill_group_now(pgid: u32) {
    #[cfg(unix)]
    {
        let _ = signal_group(pgid, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_group_reports_missing() {
        // PID space near the top is almost never allocated.
        assert!(!group_exists(0xFFFF_FFF0));
    }

    #[tokio::test]
    async fn escalation_on_dead_group_returns_quickly() {
        let start = std::time::Instant::now();
        escalate_group_termination(0xFFFF_FFF0, Duration::from_secs(1)).await;
        assert!(start.elapsed() < Duration::from_millis(300));
    }
}
