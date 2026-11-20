//! Capability reporting helpers shared by `doctor` / `capabilities`.

use nsk_core::capability::{CapabilityStatus, PlatformCapabilities};

/// Render a capability status as a stable short token.
pub fn status_token(s: CapabilityStatus) -> &'static str {
    match s {
        CapabilityStatus::Available => "available",
        CapabilityStatus::Unsupported => "unsupported",
        CapabilityStatus::PermissionDenied => "permission-denied",
        CapabilityStatus::NotConfigured => "not-configured",
        CapabilityStatus::Failed => "failed",
        CapabilityStatus::Unknown => "unknown",
    }
}

/// A flat capability table row (for JSON output).
#[derive(Debug, serde::Serialize)]
pub struct CapabilityRow {
    pub name: String,
    pub status: String,
    pub detail: Option<String>,
}

/// Flatten a capability report into rows.
pub fn flatten(caps: &PlatformCapabilities) -> Vec<CapabilityRow> {
    let mut rows = Vec::new();
    let iso = &caps.isolation;
    for (name, status) in [
        ("isolation.user_namespace", iso.user_namespace),
        ("isolation.mount_namespace", iso.mount_namespace),
        ("isolation.pid_namespace", iso.pid_namespace),
        ("isolation.network_namespace", iso.network_namespace),
        ("isolation.ipc_namespace", iso.ipc_namespace),
        ("isolation.uts_namespace", iso.uts_namespace),
    ] {
        rows.push(CapabilityRow {
            name: name.into(),
            status: status_token(status).into(),
            detail: None,
        });
    }
    rows.push(CapabilityRow {
        name: format!("isolation.launcher.{}", iso.launcher.name),
        status: status_token(iso.launcher.status).into(),
        detail: iso.launcher.version.clone(),
    });

    let res = &caps.resources;
    for (name, status) in [
        ("resources.cgroup_v2", res.cgroup_v2),
        ("resources.controllers.cpu", res.controllers.cpu),
        ("resources.controllers.memory", res.controllers.memory),
        ("resources.controllers.pids", res.controllers.pids),
        ("resources.rlimits", res.rlimits),
        ("resources.process_tree_kill", res.process_tree_kill),
        ("resources.disk_quota", res.disk_quota),
    ] {
        rows.push(CapabilityRow {
            name: name.into(),
            status: status_token(status).into(),
            detail: None,
        });
    }

    let sec = &caps.security;
    for (name, status) in [
        ("security.seccomp", sec.seccomp),
        ("security.no_new_privileges", sec.no_new_privileges),
        ("security.privilege_dropping", sec.privilege_dropping),
    ] {
        rows.push(CapabilityRow {
            name: name.into(),
            status: status_token(status).into(),
            detail: None,
        });
    }
    rows
}

/// Does this report allow *any* isolated execution?
pub fn isolation_usable(caps: &PlatformCapabilities) -> bool {
    caps.isolation.launcher.status.is_available()
}
