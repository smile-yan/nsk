//! Windows capability probe (§9.3, §11).
//!
//! The probe verifies each mechanism functionally instead of assuming:
//!
//! * **Job Objects** — create a probe job, verify limit setting and
//!   accounting queries succeed (always available on Windows 8+),
//! * **Restricted token** — derive a restricted token from the caller's
//!   token and verify no privileges remain enabled,
//! * **AppContainer** — detection facts only (see [`crate::appcontainer`]).
//!
//! Everything Windows does not provide for this MVP (namespaces, rlimits,
//! cgroups, filesystem/network isolation via Job Objects) is reported as
//! `Unsupported` — never claimed, never silently degraded (§2.4, §2.6).

#[cfg(windows)]
use nsk_core::capability::ToolInfo;
use nsk_core::capability::{
    CapabilityStatus, IsolationCapabilities, Platform, PlatformCapabilities, ResourceCapabilities,
    SecurityCapabilities,
};
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;

#[cfg(windows)]
use crate::limits::JobLimits;

/// Full capability probe. On Windows hosts every mechanism is verified
/// functionally; on non-Windows hosts the report stays honest (everything
/// unsupported) and `prepare` refuses before anything can run.
pub async fn probe_capabilities() -> PlatformCapabilities {
    #[cfg(windows)]
    {
        probe_capabilities_windows().await
    }
    #[cfg(not(windows))]
    {
        probe_capabilities_off_host()
    }
}

/// Full capability probe (runs on Windows hosts).
#[cfg(windows)]
async fn probe_capabilities_windows() -> PlatformCapabilities {
    let mut diagnostics = Vec::new();

    // Job Objects: functional verification.
    let job_objects = match crate::job::JobObject::create(JobLimits {
        memory_bytes: Some(64 * 1024 * 1024),
        max_processes: Some(8),
        cpu_rate: None,
        ui_restrictions: false,
    }) {
        Ok(job) => {
            let verified = job.observe_usage().is_ok();
            job.close();
            if verified {
                diagnostics.push(Diagnostic::info(
                    codes::CAPABILITY_VERIFIED,
                    "Job Objects verified functional (create, limits, accounting)",
                ));
                CapabilityStatus::Available
            } else {
                diagnostics.push(Diagnostic::error(
                    codes::CAPABILITY_UNVERIFIED,
                    "Job Object accounting query failed after creation",
                ));
                CapabilityStatus::Failed
            }
        }
        Err(e) => {
            diagnostics.push(Diagnostic::error(
                codes::CAPABILITY_UNAVAILABLE,
                format!("Job Object creation failed: {e}"),
            ));
            CapabilityStatus::Failed
        }
    };

    // Restricted token: machinery verification (spawn integration pending).
    let privilege_dropping = match crate::token::RestrictedToken::from_current_process() {
        Ok(token) => match token.enabled_privileges() {
            Ok(0) => {
                diagnostics.push(Diagnostic::info(
                    codes::CAPABILITY_UNVERIFIED,
                    "restricted-token machinery verified (all privileges disabled); \
                     process creation with the token is not wired in the MVP spawn path — \
                     privileges are NOT reduced for sandboxed processes yet",
                ));
                CapabilityStatus::NotConfigured
            }
            Ok(n) => {
                diagnostics.push(Diagnostic::error(
                    codes::CAPABILITY_UNVERIFIED,
                    format!("restricted token kept {n} privileges enabled; unexpected"),
                ));
                CapabilityStatus::Failed
            }
            Err(e) => {
                diagnostics.push(Diagnostic::error(
                    codes::CAPABILITY_UNVERIFIED,
                    format!("restricted-token privilege query failed: {e}"),
                ));
                CapabilityStatus::Failed
            }
        },
        Err(e) => {
            diagnostics.push(Diagnostic::warning(
                codes::CAPABILITY_UNAVAILABLE,
                format!("restricted-token creation unavailable: {e}"),
            ));
            CapabilityStatus::Unsupported
        }
    };

    // AppContainer: detection facts only; capability stays Unsupported
    // until security validation (§11.5).
    match crate::appcontainer::detect() {
        Ok(facts) => {
            diagnostics.push(Diagnostic::info(
                codes::CAPABILITY_UNVERIFIED,
                format!(
                    "AppContainer detection: in_appcontainer={}, caller_elevated={} — \
                     profile-creation machinery pending security validation (§11.5)",
                    facts.in_appcontainer, facts.caller_elevated
                ),
            ));
        }
        Err(e) => {
            diagnostics.push(Diagnostic::warning(
                codes::CAPABILITY_UNVERIFIED,
                format!("AppContainer detection failed: {e}"),
            ));
        }
    }

    PlatformCapabilities {
        platform: Platform::Windows,
        isolation: IsolationCapabilities {
            user_namespace: CapabilityStatus::Unsupported,
            mount_namespace: CapabilityStatus::Unsupported,
            pid_namespace: CapabilityStatus::Unsupported,
            network_namespace: CapabilityStatus::Unsupported,
            ipc_namespace: CapabilityStatus::Unsupported,
            uts_namespace: CapabilityStatus::Unsupported,
            // Job Objects isolate process *sets and resources*, not
            // filesystem or network access (§11.3) — honestly Unsupported.
            filesystem_isolation: CapabilityStatus::Unsupported,
            network_isolation: CapabilityStatus::Unsupported,
            launcher: ToolInfo {
                name: "none (native Job Object)".into(),
                status: job_objects,
                ..Default::default()
            },
        },
        resources: ResourceCapabilities {
            cgroup_v2: CapabilityStatus::Unsupported,
            controllers: nsk_core::capability::CgroupControllers::unsupported(),
            // No POSIX rlimits on Windows.
            rlimits: CapabilityStatus::Unsupported,
            rlimit_address_space: CapabilityStatus::Unsupported,
            rlimit_processes: CapabilityStatus::Unsupported,
            job_objects,
            memory_watchdog: CapabilityStatus::Unsupported,
            process_watchdog: CapabilityStatus::Unsupported,
            process_tree_kill: job_objects,
            disk_quota: CapabilityStatus::Unsupported,
        },
        security: SecurityCapabilities {
            seccomp: CapabilityStatus::Unsupported,
            // No setuid mechanism exists on Windows; NNP is not applicable.
            no_new_privileges: CapabilityStatus::Unsupported,
            privilege_dropping,
        },
        diagnostics,
    }
}

/// Non-Windows hosts must never pretend to provide Windows mechanisms.
pub fn probe_capabilities_off_host() -> PlatformCapabilities {
    PlatformCapabilities {
        platform: Platform::Windows,
        isolation: IsolationCapabilities::unsupported(),
        resources: ResourceCapabilities {
            cgroup_v2: CapabilityStatus::Unsupported,
            controllers: nsk_core::capability::CgroupControllers::unsupported(),
            rlimits: CapabilityStatus::Unsupported,
            rlimit_address_space: CapabilityStatus::Unsupported,
            rlimit_processes: CapabilityStatus::Unsupported,
            job_objects: CapabilityStatus::Unsupported,
            memory_watchdog: CapabilityStatus::Unsupported,
            process_watchdog: CapabilityStatus::Unsupported,
            process_tree_kill: CapabilityStatus::Unsupported,
            disk_quota: CapabilityStatus::Unsupported,
        },
        security: SecurityCapabilities::unsupported(),
        diagnostics: vec![Diagnostic::warning(
            codes::CAPABILITY_UNAVAILABLE,
            "Windows provider probed on a non-Windows host: no mechanism can be verified \
             or provided here",
        )],
    }
}

/// Validate the probe ran on the right host, used by `probe()`.
pub fn ensure_windows_host() -> Result<(), SandboxError> {
    if std::env::consts::OS == "windows" {
        Ok(())
    } else {
        Err(SandboxError::Provider {
            provider: "windows".into(),
            message: "the Windows provider only runs on Windows hosts".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn off_host_probe_is_honest() {
        if cfg!(windows) {
            return;
        }
        let caps = probe_capabilities_off_host();
        assert_eq!(caps.platform, Platform::Windows);
        assert_eq!(caps.resources.job_objects, CapabilityStatus::Unsupported);
        assert!(!caps.diagnostics.is_empty());
        assert!(caps.diagnostics[0].message.contains("non-Windows host"));
    }

    #[tokio::test]
    async fn on_host_probe_verifies_job_objects() {
        if !cfg!(windows) {
            return;
        }
        let caps = probe_capabilities().await;
        assert_eq!(caps.platform, Platform::Windows);
        assert_eq!(caps.resources.job_objects, CapabilityStatus::Available);
        assert_eq!(
            caps.resources.process_tree_kill,
            CapabilityStatus::Available
        );
        // Job Objects are NOT filesystem/network isolation (§11.3).
        assert_eq!(
            caps.isolation.filesystem_isolation,
            CapabilityStatus::Unsupported
        );
        assert_eq!(
            caps.isolation.network_isolation,
            CapabilityStatus::Unsupported
        );
        assert!(
            caps.diagnostics
                .iter()
                .any(|d| d.code == codes::CAPABILITY_VERIFIED)
        );
    }
}
