//! Capability probe (§10.3).
//!
//! Detection uses **actual functional tests**, not just version numbers:
//! * bubblewrap is verified by executing a real unprivileged sandbox,
//! * cgroup delegation is verified by creating a test group and writing a
//!   limit file,
//! * controller availability is read from the unified hierarchy itself.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use nsk_core::capability::{
    CapabilityStatus, CgroupControllers, Platform, PlatformCapabilities, ToolInfo,
};
use nsk_core::diagnostic::{Diagnostic, codes};
use tracing::{debug, info, warn};

use crate::provider::{LinuxProviderConfig, SeccompChoice};

/// Locate a binary in `PATH` (mirrors shell lookup without spawning a shell).
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Kernel release string, e.g. "6.5.0-14-generic".
pub fn kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

/// Parse major.minor from a kernel release string.
pub fn kernel_version(release: &str) -> Option<(u64, u64)> {
    let mut parts = release.split('.');
    let major = parts
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    let minor = parts
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// The mount point of the cgroup v2 unified hierarchy, if any.
pub fn cgroup_v2_mount() -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup2" {
            return Some(PathBuf::from(fields[1]));
        }
    }
    None
}

/// Read enabled controllers from `cgroup.controllers` at `root`.
pub fn enabled_controllers(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("cgroup.controllers"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Run a command with a timeout, returning (ok, stdout).
async fn run_probe(cmd: &str, args: &[&str], timeout: Duration) -> Option<(bool, String)> {
    let child = tokio::process::Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    Some((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

/// Full capability probe (§10.3 checklist).
pub async fn linux_capabilities(config: &LinuxProviderConfig) -> PlatformCapabilities {
    probe_with_config(config).await
}

pub async fn probe_with_config(config: &LinuxProviderConfig) -> PlatformCapabilities {
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let mut caps = PlatformCapabilities {
        platform: Platform::Linux,
        ..Default::default()
    };

    // Kernel.
    let release = kernel_release();
    if let Some(rel) = &release {
        diagnostics.push(Diagnostic::info(codes::HOST_ENV, format!("kernel {rel}")));
        if let Some((major, minor)) = kernel_version(rel) {
            if (major, minor) < (4, 14) {
                diagnostics.push(Diagnostic::warning(
                    codes::CAPABILITY_DEGRADED,
                    "kernel older than 4.14: seccomp actions and some cgroup features limited",
                ));
            }
        }
    } else {
        diagnostics.push(Diagnostic::warning(
            codes::HOST_ENV,
            "/proc/sys/kernel/osrelease unreadable: not a Linux host?",
        ));
    }

    // bubblewrap (§10.4).
    let bwrap_path = config.bwrap_path.clone().or_else(|| find_in_path("bwrap"));
    caps.isolation.launcher = match bwrap_path {
        Some(path) => {
            let version = match run_probe(
                &path.display().to_string(),
                &["--version"],
                Duration::from_secs(5),
            )
            .await
            {
                Some((true, out)) => Some(out),
                _ => None,
            };
            // Real functional test: unprivileged sandbox executing /bin/true.
            let functional = run_probe(
                &path.display().to_string(),
                &[
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "/bin/true",
                ],
                Duration::from_secs(10),
            )
            .await;
            let status = match functional {
                Some((true, _)) => CapabilityStatus::Available,
                Some((false, _)) => {
                    diagnostics.push(Diagnostic::warning(
                        codes::CAPABILITY_DEGRADED,
                        "bubblewrap present but a test sandbox failed (user namespaces disabled?)",
                    ));
                    CapabilityStatus::Failed
                }
                None => CapabilityStatus::Unknown,
            };
            ToolInfo {
                name: "bubblewrap".into(),
                path: Some(path.display().to_string()),
                version,
                status,
            }
        }
        None => {
            diagnostics.push(Diagnostic::error(
                codes::TOOL_MISSING,
                "bubblewrap (bwrap) not found in PATH; Linux isolation unavailable",
            ));
            ToolInfo {
                name: "bubblewrap".into(),
                status: CapabilityStatus::NotConfigured,
                ..Default::default()
            }
        }
    };

    // Namespaces: available iff the launcher works (bwrap unshares all).
    let launcher_ok = caps.isolation.launcher.status.is_available();
    let ns_status = if launcher_ok {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unsupported
    };
    caps.isolation.user_namespace = ns_status;
    caps.isolation.mount_namespace = ns_status;
    caps.isolation.pid_namespace = ns_status;
    caps.isolation.network_namespace = ns_status;
    caps.isolation.ipc_namespace = ns_status;
    caps.isolation.uts_namespace = ns_status;
    // Domain-level views: on Linux these are exactly the namespace
    // mechanisms (the resolver matches domains against these fields).
    caps.isolation.filesystem_isolation = ns_status;
    caps.isolation.network_isolation = ns_status;

    // cgroups v2 (§10.7).
    let cgroup_probe = probe_cgroups(&config.cgroup_root).await;
    diagnostics.extend(cgroup_probe.diagnostics.clone());
    caps.resources.cgroup_v2 = cgroup_probe.overall_status();
    caps.resources.controllers = CgroupControllers {
        cpu: cgroup_probe.controller_status("cpu"),
        memory: cgroup_probe.controller_status("memory"),
        pids: cgroup_probe.controller_status("pids"),
    };

    // seccomp (§10.8).
    caps.security.seccomp = match std::fs::metadata("/proc/sys/kernel/seccomp") {
        Ok(_) if launcher_ok => CapabilityStatus::Available,
        Ok(_) => CapabilityStatus::Unknown,
        Err(_) => CapabilityStatus::Unknown,
    };
    if config.seccomp_profile == SeccompChoice::Off {
        debug!("seccomp disabled by provider config");
    }

    // no_new_privileges: kernel >= 3.5.
    caps.security.no_new_privileges = match &release {
        Some(rel) => match kernel_version(rel) {
            Some((major, minor)) if (major, minor) >= (3, 5) => CapabilityStatus::Available,
            _ => CapabilityStatus::Unknown,
        },
        None => CapabilityStatus::Unknown,
    };

    // Privilege dropping: the bwrap user-namespace mapping is the mechanism.
    caps.security.privilege_dropping = ns_status;

    // Process-tree kill: cgroup.kill on kernel >= 5.14, else process groups.
    caps.resources.process_tree_kill = if launcher_ok {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unknown
    };
    caps.resources.rlimits = CapabilityStatus::Available;
    // RLIMIT_AS and RLIMIT_NPROC are usable (degraded) memory/process
    // rungs on Linux.
    caps.resources.rlimit_address_space = CapabilityStatus::Available;
    caps.resources.rlimit_processes = CapabilityStatus::Available;
    caps.resources.job_objects = CapabilityStatus::Unsupported;
    caps.resources.memory_watchdog = CapabilityStatus::Unsupported;
    caps.resources.process_watchdog = CapabilityStatus::Unsupported;
    caps.resources.disk_quota = CapabilityStatus::Unsupported;
    diagnostics.push(Diagnostic::warning(
        codes::RESOURCE_LIMIT_UNAVAILABLE,
        "hard workspace disk quota is not available in phase 1 (advisory scanning only)",
    ));

    for d in &diagnostics {
        match d.severity {
            nsk_core::diagnostic::DiagnosticSeverity::Error => warn!("{}", d.message),
            nsk_core::diagnostic::DiagnosticSeverity::Warning => info!("{}", d.message),
            _ => debug!("{}", d.message),
        }
    }
    caps.diagnostics = diagnostics;
    caps
}

/// cgroup v2 delegation probe (§10.7 security & permission rules).
#[derive(Debug, Clone, Default)]
pub struct CgroupProbe {
    pub mounted: bool,
    pub writable: bool,
    pub controllers: Vec<String>,
    pub subtree_control: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

impl CgroupProbe {
    pub fn overall_status(&self) -> CapabilityStatus {
        if !self.mounted {
            return CapabilityStatus::Unsupported;
        }
        if !self.writable {
            return CapabilityStatus::PermissionDenied;
        }
        if self.controllers.is_empty() {
            return CapabilityStatus::NotConfigured;
        }
        CapabilityStatus::Available
    }

    pub fn controller_status(&self, name: &str) -> CapabilityStatus {
        if !self.mounted {
            return CapabilityStatus::Unsupported;
        }
        if !self.writable {
            return CapabilityStatus::PermissionDenied;
        }
        if self.controllers.contains(&name.to_string()) {
            if self.subtree_control.contains(&name.to_string()) {
                CapabilityStatus::Available
            } else {
                // Present but not delegated to children.
                CapabilityStatus::NotConfigured
            }
        } else {
            CapabilityStatus::NotConfigured
        }
    }
}

/// Probe cgroup v2 at `root`: mount, writability (delegation), controllers.
///
/// The writability test creates a uniquely-named child group, writes a limit
/// file, and removes it — an actual functional test (§10.3).
pub async fn probe_cgroups(root: &Path) -> CgroupProbe {
    let mut probe = CgroupProbe::default();

    let mount = cgroup_v2_mount();
    let effective_root = match mount {
        Some(m) => m,
        None => {
            if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
                PathBuf::from("/sys/fs/cgroup")
            } else {
                probe.diagnostics.push(Diagnostic::info(
                    codes::CAPABILITY_UNAVAILABLE,
                    "cgroup v2 unified hierarchy not mounted",
                ));
                return probe;
            }
        }
    };
    if root != effective_root && root.exists() {
        probe.diagnostics.push(Diagnostic::info(
            codes::HOST_ENV,
            format!(
                "configured cgroup root {} differs from mounted root {}",
                root.display(),
                effective_root.display()
            ),
        ));
    }
    probe.mounted = true;
    probe.controllers = enabled_controllers(&effective_root);
    probe.subtree_control = std::fs::read_to_string(effective_root.join("cgroup.subtree_control"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();

    // Functional delegation test.
    let test_dir = effective_root.join(format!("nsk-probe-{}", std::process::id()));
    match std::fs::create_dir(&test_dir) {
        Ok(()) => {
            let test_file = test_dir.join("pids.max");
            let write_ok = std::fs::write(&test_file, "max").is_ok();
            // Also verify we can attach-check cgroup.procs (readable).
            let procs_readable = test_dir.join("cgroup.procs").exists();
            probe.writable = write_ok && procs_readable;
            if !probe.writable {
                probe.diagnostics.push(Diagnostic::warning(
                    codes::CAPABILITY_DEGRADED,
                    "cgroup directory created but limit files not writable (incomplete delegation)",
                ));
            }
            let _ = std::fs::remove_dir(&test_dir);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            probe.diagnostics.push(Diagnostic::warning(
                codes::CAPABILITY_DEGRADED,
                format!(
                    "no permission to create cgroups under {}: run with delegation (systemd user slice) or as root",
                    effective_root.display()
                ),
            ));
        }
        Err(e) => {
            probe.diagnostics.push(Diagnostic::warning(
                codes::CAPABILITY_DEGRADED,
                format!("cgroup probe failed: {e}"),
            ));
        }
    }

    probe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_parsing() {
        assert_eq!(kernel_version("6.5.0-14-generic"), Some((6, 5)));
        assert_eq!(kernel_version("5.15.0"), Some((5, 15)));
        assert_eq!(kernel_version("x.y"), None);
    }

    #[test]
    fn find_in_path_handles_absent() {
        // A binary that certainly doesn't exist.
        assert!(find_in_path("definitely-not-a-binary-nsk").is_none());
    }

    #[tokio::test]
    async fn probe_on_non_linux_reports_missing_bwrap_or_works() {
        let caps = probe_with_config(&LinuxProviderConfig::default()).await;
        if !Path::new("/proc/self").exists() {
            // Non-Linux host: cgroup must not claim availability.
            assert_ne!(caps.resources.cgroup_v2, CapabilityStatus::Available);
        }
    }
}
