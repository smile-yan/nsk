//! Diagnostics model (design document §15.2) and well-known diagnostic codes.
//!
//! Diagnostics are the kernel's structured way of reporting conditions that
//! are not fatal errors: capability limitations, degraded enforcement,
//! cleanup problems, etc. They are attached to results and capability
//! reports instead of being silently dropped.

use serde::{Deserialize, Serialize};

/// Severity of a diagnostic entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// A structured diagnostic record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable machine-readable code, e.g. `NSK1102`.
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    /// Optional additional context (never contains user file contents).
    pub details: Option<String>,
}

impl Diagnostic {
    pub fn info(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            severity: DiagnosticSeverity::Info,
            message: message.into(),
            details: None,
        }
    }

    pub fn warning(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            severity: DiagnosticSeverity::Warning,
            message: message.into(),
            details: None,
        }
    }

    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            severity: DiagnosticSeverity::Error,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Well-known diagnostic code namespaces.
///
/// The first digit encodes the subsystem, the rest is a free counter:
/// `1` host/capability, `2` policy, `3` isolation, `4` resources,
/// `5` process/execution, `6` output, `7` cleanup, `8` filesystem.
pub mod codes {
    // 1xxx — host & capabilities
    pub const HOST_ENV: &str = "NSK1000";
    pub const CAPABILITY_UNAVAILABLE: &str = "NSK1100";
    pub const CAPABILITY_DEGRADED: &str = "NSK1101";
    pub const CAPABILITY_UNVERIFIED: &str = "NSK1102";
    pub const TOOL_MISSING: &str = "NSK1103";

    // 2xxx — policy
    pub const POLICY_INVALID: &str = "NSK2000";
    pub const POLICY_CONFLICT: &str = "NSK2001";
    pub const POLICY_NORMALIZED: &str = "NSK2002";
    pub const POLICY_PATH_INVALID: &str = "NSK2003";

    // 3xxx — isolation
    pub const ISOLATION_FAILED: &str = "NSK3000";
    pub const ISOLATION_DEGRADED: &str = "NSK3001";
    pub const ISOLATION_NOT_APPLIED: &str = "NSK3002";

    // 4xxx — resources
    pub const RESOURCE_LIMIT_UNAVAILABLE: &str = "NSK4000";
    pub const RESOURCE_LIMIT_DEGRADED: &str = "NSK4001";
    pub const RESOURCE_USAGE_UNAVAILABLE: &str = "NSK4002";
    pub const OOM_SUSPECTED: &str = "NSK4100";
    pub const OOM_CONFIRMED: &str = "NSK4101";
    pub const PIDS_LIMIT_HIT: &str = "NSK4200";

    // 5xxx — process & execution
    pub const SPAWN_FAILED: &str = "NSK5000";
    pub const KILLED_BY_SIGNAL: &str = "NSK5001";
    pub const TERMINATION_INCOMPLETE: &str = "NSK5002";
    pub const CANCEL_REQUESTED: &str = "NSK5003";

    // 6xxx — output
    pub const OUTPUT_TRUNCATED: &str = "NSK6000";
    pub const OUTPUT_LIMIT_EXCEEDED: &str = "NSK6001";

    // 7xxx — cleanup
    pub const CLEANUP_FAILED: &str = "NSK7000";
    pub const CLEANUP_SKIPPED: &str = "NSK7001";
    pub const CLEANUP_INCOMPLETE: &str = "NSK7002";
    pub const RESOURCE_LEAK_SUSPECTED: &str = "NSK7003";

    // 8xxx — filesystem
    pub const FS_PATH_ESCAPE: &str = "NSK8000";
    pub const FS_SYMLINK_REJECTED: &str = "NSK8001";
    pub const FS_WORKSPACE_NOT_REMOVED: &str = "NSK8002";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_set_severity() {
        let d = Diagnostic::warning(codes::CAPABILITY_DEGRADED, "cpu controller missing");
        assert_eq!(d.severity, DiagnosticSeverity::Warning);
        assert_eq!(d.details, None);
        let d = d.with_details("cgroup.subtree_control empty");
        assert_eq!(d.details.as_deref(), Some("cgroup.subtree_control empty"));
    }
}
