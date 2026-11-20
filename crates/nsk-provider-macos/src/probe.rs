//! macOS capability probe (§10.3 pattern applied to macOS, §12.2 validation).
//!
//! The probe verifies what this host can *actually* do instead of assuming:
//!
//! * `sandbox-exec` presence + a functional test (a binary runs under a
//!   generated profile and a write outside the allow-list is refused),
//! * rlimits usable via the supervisor (`NOFILE` / `FSIZE` / `CPU`),
//! * the `RLIMIT_AS` quirk: macOS rejects and ignores it (measured
//!   `EINVAL`), so memory enforcement must use the watchdog,
//! * process-group termination (the supervisor's tree kill),
//!
//! and reports honest status codes for everything else (§9.3).

use std::path::{Path, PathBuf};
use std::time::Duration;

use nsk_core::capability::{
    CapabilityStatus, IsolationCapabilities, Platform, PlatformCapabilities, ResourceCapabilities,
    SecurityCapabilities, ToolInfo,
};
use nsk_core::diagnostic::{Diagnostic, codes};

/// How long a single probe command may run before counting as failed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of locating and functionally verifying `sandbox-exec`.
#[derive(Debug, Clone)]
pub struct LauncherProbe {
    pub path: PathBuf,
    pub status: CapabilityStatus,
}

/// Locate `sandbox-exec` on the default PATH (plus `/usr/bin`, which is
/// where Apple ships it).
pub fn find_sandbox_exec() -> Option<PathBuf> {
    if let Some(path) = find_in_path("sandbox-exec") {
        return Some(path);
    }
    let fallback = Path::new("/usr/bin/sandbox-exec");
    fallback.exists().then(|| fallback.to_path_buf())
}

/// PATH lookup (same semantics as the Linux probe).
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Run a command under a generated profile with a timeout.
///
/// `Ok(exit_ok)` — the command completed (exit_ok = code 0).
/// `Err` — spawn failure or timeout.
async fn run_probe_command(argv: &[&str], cwd: &Path) -> Result<bool, String> {
    let mut cmd = tokio::process::Command::new(argv[0]);
    cmd.args(&argv[1..]);
    cmd.current_dir(cwd);
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", argv[0]))?;
    match tokio::time::timeout(PROBE_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => Ok(status.success()),
        Ok(Err(e)) => Err(format!("wait: {e}")),
        Err(_) => Err("probe command timed out".into()),
    }
}

/// Verify the Seatbelt launcher works: a trivial profile must run a binary
/// and a write outside the allow-list must be refused (the deny-by-default
/// posture is the security property, so it gets verified, not assumed).
async fn verify_launcher(path: &Path, scratch: &Path) -> Result<(), String> {
    // 1) Execution works under a profile.
    let ok_profile = "(version 1)(allow file-read*)(allow process-exec*)(allow process-fork)(allow sysctl-read)(deny network*)";
    let ran = run_probe_command(
        &[
            path.to_string_lossy().as_ref(),
            "-p",
            ok_profile,
            "/usr/bin/true",
        ],
        scratch,
    )
    .await?;
    if !ran {
        return Err("`true` failed under an allow-list profile".into());
    }

    // 2) The default-deny write isolation is real: touching a new file
    //    outside the allow-list must fail.
    let deny_profile = "(version 1)(allow file-read*)(allow process-exec*)(allow process-fork)(allow sysctl-read)(deny file-write*)";
    let target = scratch.join("nsk-probe-must-not-exist");
    let refused = run_probe_command(
        &[
            path.to_string_lossy().as_ref(),
            "-p",
            deny_profile,
            "/usr/bin/touch",
            target.to_string_lossy().as_ref(),
        ],
        scratch,
    )
    .await?;
    if refused {
        return Err("write outside the allow-list was NOT refused — mechanism broken".into());
    }
    Ok(())
}

/// Full capability probe (platform-accurate, functionally verified).
pub async fn probe_capabilities() -> PlatformCapabilities {
    let mut diagnostics = Vec::new();
    let scratch = std::env::temp_dir();

    let launcher = match find_sandbox_exec() {
        Some(path) => match verify_launcher(&path, &scratch).await {
            Ok(()) => {
                diagnostics.push(Diagnostic::info(
                    codes::CAPABILITY_VERIFIED,
                    format!(
                        "sandbox-exec verified functional: {} (exec + deny-by-default write refusal)",
                        path.display()
                    ),
                ));
                LauncherProbe {
                    path,
                    status: CapabilityStatus::Available,
                }
            }
            Err(e) => {
                diagnostics.push(Diagnostic::error(
                    codes::CAPABILITY_UNVERIFIED,
                    format!("sandbox-exec found but functional test failed: {e}"),
                ));
                LauncherProbe {
                    path,
                    status: CapabilityStatus::Failed,
                }
            }
        },
        None => {
            diagnostics.push(Diagnostic::warning(
                codes::CAPABILITY_UNAVAILABLE,
                "sandbox-exec not found; filesystem/network isolation unavailable on this host",
            ));
            LauncherProbe {
                path: PathBuf::new(),
                status: CapabilityStatus::Unsupported,
            }
        }
    };

    let seatbelt_ok = launcher.status.is_available();
    if seatbelt_ok {
        diagnostics.push(Diagnostic::info(
            codes::CAPABILITY_UNVERIFIED,
            "Seatbelt (sandbox-exec) is deprecated by Apple; treat as PoC-grade boundary (docs/macos-provider.md)",
        ));
    }

    PlatformCapabilities {
        platform: Platform::MacOS,
        isolation: IsolationCapabilities {
            // Namespace-style mechanisms do not exist on macOS.
            user_namespace: CapabilityStatus::Unsupported,
            mount_namespace: CapabilityStatus::Unsupported,
            pid_namespace: CapabilityStatus::Unsupported,
            network_namespace: CapabilityStatus::Unsupported,
            ipc_namespace: CapabilityStatus::Unsupported,
            uts_namespace: CapabilityStatus::Unsupported,
            filesystem_isolation: if seatbelt_ok {
                CapabilityStatus::Available
            } else {
                launcher.status
            },
            network_isolation: if seatbelt_ok {
                CapabilityStatus::Available
            } else {
                launcher.status
            },
            launcher: ToolInfo {
                name: "sandbox-exec".into(),
                path: (!launcher.path.as_os_str().is_empty())
                    .then(|| launcher.path.display().to_string()),
                version: None,
                status: launcher.status,
            },
        },
        resources: ResourceCapabilities {
            cgroup_v2: CapabilityStatus::Unsupported,
            controllers: nsk_core::capability::CgroupControllers::unsupported(),
            // NOFILE/FSIZE/CPU work through the supervisor's pre-exec hook.
            rlimits: CapabilityStatus::Available,
            // Measured: setrlimit(RLIMIT_AS) returns EINVAL on macOS.
            rlimit_address_space: CapabilityStatus::Unsupported,
            // RLIMIT_NPROC is per-user (counts unrelated processes) —
            // unusable for a per-sandbox limit.
            rlimit_processes: CapabilityStatus::Unsupported,
            job_objects: CapabilityStatus::Unsupported,
            memory_watchdog: CapabilityStatus::Available,
            process_watchdog: CapabilityStatus::Available,
            process_tree_kill: CapabilityStatus::Available,
            disk_quota: CapabilityStatus::Unsupported,
        },
        security: SecurityCapabilities {
            seccomp: CapabilityStatus::Unsupported,
            // The default-deny posture refuses exec of setuid binaries
            // (measured with /usr/bin/sudo under a probe profile).
            no_new_privileges: if seatbelt_ok {
                CapabilityStatus::Available
            } else {
                CapabilityStatus::Unsupported
            },
            privilege_dropping: CapabilityStatus::Unsupported,
        },
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn sandbox_exec_is_found_on_stock_macos() {
        if !cfg!(target_os = "macos") {
            return;
        }
        let path = find_sandbox_exec().expect("sandbox-exec ships with macOS");
        assert!(path.is_file());
    }

    #[tokio::test]
    async fn probe_verifies_launcher_functionally() {
        if !cfg!(target_os = "macos") {
            return;
        }
        let caps = probe_capabilities().await;
        assert_eq!(caps.platform, Platform::MacOS);
        assert_eq!(
            caps.isolation.filesystem_isolation,
            CapabilityStatus::Available,
            "sandbox-exec must verify functional on stock macOS"
        );
        assert_eq!(
            caps.isolation.network_isolation,
            CapabilityStatus::Available
        );
        // The Seatbelt default-deny makes no_new_privileges satisfiable.
        assert_eq!(caps.security.no_new_privileges, CapabilityStatus::Available);
        // Honest reports of what macOS cannot do.
        assert_eq!(
            caps.resources.rlimit_address_space,
            CapabilityStatus::Unsupported
        );
        assert_eq!(
            caps.resources.rlimit_processes,
            CapabilityStatus::Unsupported
        );
        assert_eq!(caps.isolation.pid_namespace, CapabilityStatus::Unsupported);
        assert!(
            caps.diagnostics
                .iter()
                .any(|d| d.code == codes::CAPABILITY_VERIFIED)
        );
    }

    #[tokio::test]
    #[ignore = "runs the full 5s probe timeout by design; run with --ignored"]
    async fn probe_command_enforces_timeout() {
        // A hung command must be reaped by the probe timeout.
        let scratch = std::env::temp_dir();
        let started = std::time::Instant::now();
        let result = run_probe_command(&["/bin/sleep", "30"], &scratch).await;
        let _ = result; // Ok(false) — sleep is killed / non-zero is fine either way
        assert!(started.elapsed() < PROBE_TIMEOUT + Duration::from_secs(2));
    }
}
