//! Platform capability model (design document §2.6, §9.3).
//!
//! Capabilities describe what a platform can *actually* provide. They are
//! deliberately not plain booleans: availability must distinguish
//! "unsupported", "not configured", "permission denied" and "unknown" so the
//! Policy Engine can fail closed with precise diagnostics (§9.3).

use serde::{Deserialize, Serialize};

use crate::diagnostic::Diagnostic;

/// Host platform kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    #[default]
    Unknown,
}

impl Platform {
    /// The platform this build is running on.
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Platform::Linux,
            "macos" => Platform::MacOS,
            "windows" => Platform::Windows,
            _ => Platform::Unknown,
        }
    }
}

/// Status of a single capability (§9.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Verified available in this environment.
    Available,
    /// Platform cannot provide it at all.
    Unsupported,
    /// Exists but the current user may not use it.
    PermissionDenied,
    /// Exists but not enabled/configured on this host.
    NotConfigured,
    /// Probe detected it but a functional test failed.
    Failed,
    /// Could not be determined.
    #[default]
    Unknown,
}

impl CapabilityStatus {
    /// Only `Available` counts as satisfied for fail-closed checks.
    pub fn is_available(self) -> bool {
        self == CapabilityStatus::Available
    }

    /// True when the status alone already explains a failure.
    pub fn is_definitively_missing(self) -> bool {
        matches!(
            self,
            CapabilityStatus::Unsupported
                | CapabilityStatus::PermissionDenied
                | CapabilityStatus::NotConfigured
                | CapabilityStatus::Failed
        )
    }
}

/// Description of an external tool the provider relies on (e.g. bubblewrap).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub status: CapabilityStatus,
}

/// Isolation mechanism capabilities (§9.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationCapabilities {
    pub user_namespace: CapabilityStatus,
    pub mount_namespace: CapabilityStatus,
    pub pid_namespace: CapabilityStatus,
    pub network_namespace: CapabilityStatus,
    pub ipc_namespace: CapabilityStatus,
    pub uts_namespace: CapabilityStatus,
    /// External isolation launcher used by the provider.
    pub launcher: ToolInfo,
}

/// Resource-control capabilities (§9.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    /// cgroups v2 unified hierarchy usable by the current user.
    pub cgroup_v2: CapabilityStatus,
    pub controllers: CgroupControllers,
    /// rlimit-based enforcement (RLIMIT_*).
    pub rlimits: CapabilityStatus,
    /// Reliable whole-process-tree termination.
    pub process_tree_kill: CapabilityStatus,
    /// Hard disk quota for the workspace (not just scanning).
    pub disk_quota: CapabilityStatus,
}

/// cgroup controller availability (§10.7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupControllers {
    pub cpu: CapabilityStatus,
    pub memory: CapabilityStatus,
    pub pids: CapabilityStatus,
}

/// Security mechanism capabilities (§9.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityCapabilities {
    pub seccomp: CapabilityStatus,
    pub no_new_privileges: CapabilityStatus,
    /// Can the sandbox run with reduced privileges?
    pub privilege_dropping: CapabilityStatus,
}

/// Full capability report of a platform/provider (§9.3).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub platform: Platform,
    pub isolation: IsolationCapabilities,
    pub resources: ResourceCapabilities,
    pub security: SecurityCapabilities,
    pub diagnostics: Vec<Diagnostic>,
}

impl PlatformCapabilities {
    /// Report for a platform whose provider is not implemented yet.
    pub fn unimplemented(platform: Platform, provider_note: &str) -> Self {
        Self {
            platform,
            isolation: IsolationCapabilities::unsupported(),
            resources: ResourceCapabilities::unsupported(),
            security: SecurityCapabilities::unsupported(),
            diagnostics: vec![Diagnostic::warning(
                crate::diagnostic::codes::CAPABILITY_UNAVAILABLE,
                provider_note,
            )],
        }
    }
}

impl IsolationCapabilities {
    /// Honest "unsupported" isolation report for a platform.
    pub fn unsupported() -> Self {
        let s = CapabilityStatus::Unsupported;
        Self {
            user_namespace: s,
            mount_namespace: s,
            pid_namespace: s,
            network_namespace: s,
            ipc_namespace: s,
            uts_namespace: s,
            launcher: ToolInfo {
                name: "none".into(),
                status: CapabilityStatus::Unsupported,
                ..Default::default()
            },
        }
    }
}

impl ResourceCapabilities {
    /// Honest "unsupported" resource report for a platform.
    pub fn unsupported() -> Self {
        Self {
            cgroup_v2: CapabilityStatus::Unsupported,
            controllers: CgroupControllers::unsupported(),
            rlimits: CapabilityStatus::Available,
            process_tree_kill: CapabilityStatus::Unknown,
            disk_quota: CapabilityStatus::Unsupported,
        }
    }
}

impl SecurityCapabilities {
    /// Honest "unsupported" security report for a platform.
    pub fn unsupported() -> Self {
        let s = CapabilityStatus::Unsupported;
        Self {
            seccomp: s,
            no_new_privileges: s,
            privilege_dropping: s,
        }
    }
}

impl CgroupControllers {
    /// Honest "unsupported" controller report for a platform.
    pub fn unsupported() -> Self {
        let s = CapabilityStatus::Unsupported;
        Self {
            cpu: s,
            memory: s,
            pids: s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_semantics() {
        assert!(CapabilityStatus::Available.is_available());
        assert!(!CapabilityStatus::Unknown.is_available());
        for s in [
            CapabilityStatus::Unsupported,
            CapabilityStatus::PermissionDenied,
            CapabilityStatus::NotConfigured,
            CapabilityStatus::Failed,
        ] {
            assert!(s.is_definitively_missing());
        }
        assert!(!CapabilityStatus::Unknown.is_definitively_missing());
    }

    #[test]
    fn current_platform_resolves() {
        let p = Platform::current();
        assert_ne!(p, Platform::Unknown);
    }

    #[test]
    fn unimplemented_reports_are_honest() {
        let caps = PlatformCapabilities::unimplemented(Platform::MacOS, "macOS provider pending");
        assert_eq!(caps.isolation.user_namespace, CapabilityStatus::Unsupported);
        assert_eq!(caps.platform, Platform::MacOS);
        assert_eq!(caps.diagnostics.len(), 1);
    }

    #[test]
    fn serde_roundtrip() {
        let caps = PlatformCapabilities::unimplemented(Platform::Windows, "win provider pending");
        let json = serde_json::to_string(&caps).unwrap();
        let back: PlatformCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back, caps);
    }
}
