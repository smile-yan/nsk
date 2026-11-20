//! cgroups v2 manager (§10.7).
//!
//! One cgroup per sandbox, created under a configurable parent (default:
//! the unified-hierarchy root). Provides:
//!
//! * creation with controller enablement checks,
//! * limit application (`memory.max`, `memory.swap.max`, `cpu.max`,
//!   `pids.max`),
//! * metrics reading (`memory.current`, `memory.peak`, `memory.events`,
//!   `cpu.stat`, `pids.current`, `pids.events`),
//! * reliable whole-group kill (`cgroup.kill` on kernel ≥ 5.14, fallback to
//!   killing every listed pid),
//! * idempotent destruction.
//!
//! Permission rules (§10.7): availability of cgroups v2 does **not** imply
//! the current user may manage groups — every write failure is surfaced as
//! a capability problem, never swallowed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use nsk_core::error::SandboxError;
use nsk_core::result::ResourceUsage;

use crate::probe::{CgroupProbe, cgroup_v2_mount, enabled_controllers};

/// Manager for one sandbox's cgroup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupManager {
    /// Unified hierarchy root (e.g. `/sys/fs/cgroup`).
    pub root: PathBuf,
    /// This sandbox's group directory.
    pub group: PathBuf,
}

impl CgroupManager {
    /// Create the sandbox group under `parent_root`.
    pub fn create(root: &Path, group_name: &str) -> Result<Self, SandboxError> {
        let group = root.join(group_name);
        std::fs::create_dir(&group).map_err(|e| {
            SandboxError::ResourceLimit(format!(
                "cannot create cgroup {}: {e} (delegation missing?)",
                group.display()
            ))
        })?;
        debug!(cgroup = %group.display(), "cgroup created");
        Ok(Self {
            root: root.to_path_buf(),
            group,
        })
    }

    /// Controllers enabled in the parent (available to children).
    pub fn parent_controllers(&self) -> Vec<String> {
        enabled_controllers(&self.root)
    }

    /// Read a cgroup control file.
    fn read_file(&self, name: &str) -> Result<String, SandboxError> {
        std::fs::read_to_string(self.group.join(name))
            .map(|s| s.trim().to_string())
            .map_err(|e| SandboxError::ResourceLimit(format!("read {name}: {e}")))
    }

    /// Write a cgroup control file.
    fn write_file(&self, name: &str, content: &str) -> Result<(), SandboxError> {
        std::fs::write(self.group.join(name), content).map_err(|e| {
            SandboxError::ResourceLimit(format!(
                "write {} = {content:?}: {e} (controller delegated?)",
                self.group.join(name).display()
            ))
        })?;
        debug!(cgroup = %self.group.display(), file = name, value = content, "cgroup limit applied");
        Ok(())
    }

    /// Write a limit only when the controller is enabled; returns whether
    /// the limit was actually applied.
    pub fn write_limit_if_controller(
        &self,
        controller: &str,
        file: &str,
        value: &str,
    ) -> Result<bool, SandboxError> {
        if self.parent_controllers().contains(&controller.to_string()) {
            self.write_file(file, value)?;
            Ok(true)
        } else {
            warn!(
                controller,
                file, "controller not enabled; limit not applied"
            );
            Ok(false)
        }
    }

    /// Attach a pid to this group.
    pub fn attach(&self, pid: u32) -> Result<(), SandboxError> {
        self.write_file("cgroup.procs", &pid.to_string())
    }

    /// Pids currently in the group.
    pub fn current_pids(&self) -> Vec<u32> {
        self.read_file("cgroup.procs")
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    /// Kill every process in the group.
    ///
    /// Prefers `cgroup.kill` (atomic, kernel ≥ 5.14); falls back to SIGKILL
    /// per listed pid with a retry pass for newly forked children.
    pub fn kill_all(&self) -> Result<usize, SandboxError> {
        if self.group.join("cgroup.kill").exists() {
            self.write_file("cgroup.kill", "1")?;
            return Ok(self.current_pids().len());
        }
        // Fallback: repeated SIGKILL over cgroup.procs.
        let mut killed = 0;
        for round in 0..5 {
            let pids = self.current_pids();
            if pids.is_empty() {
                break;
            }
            for pid in &pids {
                // SAFETY: kill(2) wrapper.
                unsafe {
                    libc::kill(*pid as libc::pid_t, libc::SIGKILL);
                }
                killed += 1;
            }
            if round < 4 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(killed)
    }

    /// Observe metrics (§10.7 memory/cpu/pid monitoring).
    ///
    /// All fields are best-effort: files that don't exist (older kernels,
    /// disabled controllers) are reported as `None`, not errors.
    pub fn observe_usage(&self) -> ResourceUsage {
        let mut usage = ResourceUsage::default();

        if let Ok(v) = self.read_file("memory.current") {
            usage.memory_current_bytes = v.parse().ok();
        }
        if let Ok(v) = self.read_file("memory.peak") {
            usage.memory_peak_bytes = v.parse().ok();
        } else if let Some(cur) = usage.memory_current_bytes {
            usage.memory_peak_bytes = Some(cur);
        }
        usage.oom_events = self.read_file("memory.events").ok().and_then(|events| {
            events.lines().find_map(|l| {
                let mut it = l.split_whitespace();
                if it.next() == Some("oom_kill") {
                    it.next().and_then(|v| v.parse().ok())
                } else {
                    None
                }
            })
        });
        usage.pids_limit_hits = self.read_file("pids.events").ok().and_then(|events| {
            events.lines().find_map(|l| {
                let mut it = l.split_whitespace();
                if it.next() == Some("max") {
                    it.next().and_then(|v| v.parse().ok())
                } else {
                    None
                }
            })
        });
        if let Ok(v) = self.read_file("pids.current") {
            usage.process_count = v.parse().ok();
        }
        if let Ok(stat) = self.read_file("cpu.stat") {
            for line in stat.lines() {
                let mut it = line.split_whitespace();
                if it.next() == Some("usage_usec") {
                    if let Some(us) = it.next().and_then(|v| v.parse::<u64>().ok()) {
                        usage.cpu_time = Some(Duration::from_micros(us));
                    }
                }
            }
        }

        usage
    }

    /// Destroy the group: kill, wait for empty, remove. Idempotent.
    ///
    /// Returns diagnostics for leftover state instead of failing silently.
    pub fn destroy(&self) -> Result<Vec<nsk_core::diagnostic::Diagnostic>, SandboxError> {
        use nsk_core::diagnostic::{Diagnostic, codes};
        let mut diags = Vec::new();

        if !self.group.exists() {
            return Ok(diags); // already gone: idempotent
        }

        let _ = self.kill_all();

        // Wait for the group to drain.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if self.current_pids().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        let leftover = self.current_pids();
        if !leftover.is_empty() {
            warn!(pids = ?leftover, "cgroup still has processes after kill");
            diags.push(Diagnostic::error(
                codes::TERMINATION_INCOMPLETE,
                format!("cgroup {} still contains processes", self.group.display()),
            ));
        }

        match std::fs::remove_dir(&self.group) {
            Ok(()) => info!(cgroup = %self.group.display(), "cgroup destroyed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                diags.push(Diagnostic::error(
                    codes::CLEANUP_FAILED,
                    format!("cannot remove cgroup {}: {e}", self.group.display()),
                ));
            }
        }

        Ok(diags)
    }
}

/// Result of checking whether cgroup management is possible at all.
pub type ControllersState = CgroupProbe;

/// Validate cgroup availability for the requested controllers.
pub fn ensure_cgroup_usable(
    root: &Path,
    required_controllers: &[&str],
) -> Result<(), SandboxError> {
    if cgroup_v2_mount().is_none() && !root.join("cgroup.controllers").exists() {
        return Err(SandboxError::ResourceLimit(
            "cgroups v2 unified hierarchy not available".into(),
        ));
    }
    let enabled: Vec<String> = enabled_controllers(root);
    for c in required_controllers {
        if !enabled.iter().any(|e| e == c) {
            return Err(SandboxError::ResourceLimit(format!(
                "cgroup controller '{c}' not enabled on this system"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_rejects_on_unwritable_root() {
        // /proc (procfs) is never writable via cgroup files.
        let result = CgroupManager::create(Path::new("/proc"), "nsk-test-should-fail");
        assert!(result.is_err());
    }

    #[test]
    fn destroy_is_idempotent_for_missing_group() {
        let manager = CgroupManager {
            root: PathBuf::from("/nonexistent-root-nsk"),
            group: PathBuf::from("/nonexistent-root-nsk/nsk-test"),
        };
        // destroy on a missing group must succeed with no diagnostics.
        let diags = manager.destroy().expect("idempotent destroy");
        assert!(diags.is_empty());
    }

    #[test]
    fn usage_defaults_when_no_files() {
        let manager = CgroupManager {
            root: PathBuf::from("/nonexistent-root-nsk"),
            group: PathBuf::from("/nonexistent-root-nsk/nsk-test"),
        };
        let usage = manager.observe_usage();
        assert_eq!(usage.memory_current_bytes, None);
        assert_eq!(usage.oom_events, None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn delegated_root_allows_lifecycle() {
        // Only runs in environments with cgroup delegation (CI linux job).
        let root = match cgroup_v2_mount() {
            Some(r) => r,
            None => return,
        };
        let manager =
            match CgroupManager::create(&root, &format!("nsk-test-{}", std::process::id())) {
                Ok(m) => m,
                Err(_) => return, // no delegation on this host; probe covers it
            };
        let usage = manager.observe_usage();
        assert_eq!(usage.memory_current_bytes, Some(0));
        manager.destroy().expect("destroy");
        assert!(!manager.group.exists());
    }
}
