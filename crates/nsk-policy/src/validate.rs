//! Policy validation rules (design document §6.3).
//!
//! All rules are pure checks over the request; filesystem-level path safety
//! is layered on top by `nsk-workspace` and the providers.

use std::path::Path;
use std::time::Duration;

use nsk_core::diagnostic::{Diagnostic, DiagnosticSeverity, codes};
use nsk_core::error::SandboxError;
use nsk_core::policy::{
    CpuQuota, FilesystemPolicy, IsolationPolicy, NetworkPolicy, OutputPolicy, ProcessPolicy,
    ResourceLimits, SandboxPolicy, SecurityPolicy,
};
use nsk_core::spec::SandboxSpec;
use nsk_core::validation as bounds;

/// Validate the full request: spec structure + policy bounds + conflicts.
///
/// Only `Error`-severity diagnostics block execution; `Warning`-severity
/// findings are surfaced through [`diagnose_spec`] and recorded as policy
/// limitations.
pub fn validate_spec(spec: &SandboxSpec) -> Result<(), SandboxError> {
    let diags = diagnose_spec(spec);
    fail_on_errors(diags)
}

/// Collect all diagnostics for a request without failing.
pub fn diagnose_spec(spec: &SandboxSpec) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    // Structural spec rules (argument encoding, env whitelist, ...).
    if let Err(SandboxError::PolicyValidation(structural)) = spec.validate() {
        diags.extend(structural);
    }

    diagnose_policy_into(&spec.policy, &mut diags);
    diags
}

/// Final decision helper: fail when any Error-severity diagnostic exists.
fn fail_on_errors(diags: Vec<Diagnostic>) -> Result<(), SandboxError> {
    if diags
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Error)
    {
        Err(SandboxError::PolicyValidation(diags))
    } else {
        Ok(())
    }
}

/// Collect all diagnostics for a policy into `diags`.
pub fn diagnose_policy_into(policy: &SandboxPolicy, diags: &mut Vec<Diagnostic>) {
    validate_isolation(&policy.isolation, &policy.filesystem, diags);
    validate_resources(&policy.resources, diags);
    validate_output(&policy.output, &policy.resources, diags);
    validate_process(&policy.process, &policy.resources, diags);
    validate_network(&policy.network, diags);
    validate_security(&policy.security, diags);
    validate_filesystem(&policy.filesystem, diags);
}

/// Validate a policy: fails only on Error-severity diagnostics.
pub fn validate_policy(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    let mut diags = Vec::new();
    diagnose_policy_into(policy, &mut diags);
    fail_on_errors(diags)
}

/// Collect all diagnostics for a policy without failing.
pub fn diagnose_policy(policy: &SandboxPolicy) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    diagnose_policy_into(policy, &mut diags);
    diags
}

fn push(diags: &mut Vec<Diagnostic>, msg: impl Into<String>) {
    diags.push(Diagnostic::error(codes::POLICY_INVALID, msg));
}

fn validate_isolation(
    isolation: &IsolationPolicy,
    filesystem: &FilesystemPolicy,
    diags: &mut Vec<Diagnostic>,
) {
    // Root isolation is part of filesystem isolation; requesting it alone is
    // contradictory.
    if filesystem.isolate_root && !isolation.isolate_filesystem {
        diags.push(Diagnostic::error(
            codes::POLICY_CONFLICT,
            "filesystem.isolate_root requires isolation.isolate_filesystem",
        ));
    }
    // deny_host_paths cannot be guaranteed without filesystem isolation.
    if filesystem.deny_host_paths && !isolation.isolate_filesystem {
        diags.push(Diagnostic::error(
            codes::POLICY_CONFLICT,
            "filesystem.deny_host_paths requires isolation.isolate_filesystem",
        ));
    }
}

fn validate_resources(resources: &ResourceLimits, diags: &mut Vec<Diagnostic>) {
    if let Err(msg) = bounds::check_wall_time(resources.wall_time) {
        push(diags, format!("resources.wall_time: {msg}"));
    }
    if let Some(cpu_time) = resources.cpu_time {
        if cpu_time.is_zero() || cpu_time > resources.wall_time {
            push(diags, "resources.cpu_time must be > 0 and <= wall_time");
        }
    }
    if let Err(msg) = bounds::check_memory(resources.memory_bytes) {
        push(diags, format!("resources.memory_bytes: {msg}"));
    }
    if let Some(swap) = resources.swap_bytes {
        if swap > resources.memory_bytes {
            push(diags, "resources.swap_bytes must be <= memory_bytes");
        }
    }
    if resources.max_processes < bounds::MIN_PROCESSES
        || resources.max_processes > bounds::MAX_PROCESSES
    {
        push(diags, "resources.max_processes out of range");
    }
    if resources.max_open_files < bounds::MIN_OPEN_FILES
        || resources.max_open_files > bounds::MAX_OPEN_FILES
    {
        push(diags, "resources.max_open_files out of range");
    }
    if resources.max_file_size_bytes < bounds::MIN_FILE_SIZE_BYTES
        || resources.max_file_size_bytes > bounds::MAX_FILE_SIZE_BYTES
    {
        push(diags, "resources.max_file_size_bytes out of range");
    }
    if resources.max_disk_bytes < bounds::MIN_DISK_BYTES
        || resources.max_disk_bytes > bounds::MAX_DISK_BYTES
    {
        push(diags, "resources.max_disk_bytes out of range");
    }
    if let Err(msg) = bounds::check_output_limit(resources.max_output_bytes) {
        push(diags, format!("resources.max_output_bytes: {msg}"));
    }
    if let Some(quota) = &resources.cpu_quota {
        if let Err(msg) = check_cpu_quota(quota) {
            push(diags, format!("resources.cpu_quota: {msg}"));
        }
    }
}

/// Validate a CPU quota value.
pub fn check_cpu_quota(quota: &CpuQuota) -> Result<(), &'static str> {
    bounds::check_cpu_quota(quota.cores)
}

fn validate_output(output: &OutputPolicy, resources: &ResourceLimits, diags: &mut Vec<Diagnostic>) {
    for (name, value) in [
        ("output.max_stdout_bytes", output.max_stdout_bytes),
        ("output.max_stderr_bytes", output.max_stderr_bytes),
        ("output.combined_limit_bytes", output.combined_limit_bytes),
    ] {
        if let Err(msg) = bounds::check_output_limit(value) {
            push(diags, format!("{name}: {msg}"));
        }
    }
    let single_max = output.max_stdout_bytes.max(output.max_stderr_bytes);
    if output.combined_limit_bytes < single_max {
        push(
            diags,
            "output.combined_limit_bytes must be >= max(stdout, stderr)",
        );
    }
    if resources.max_output_bytes < output.combined_limit_bytes {
        push(
            diags,
            "resources.max_output_bytes must be >= output.combined_limit_bytes",
        );
    }
}

fn validate_process(
    process: &ProcessPolicy,
    resources: &ResourceLimits,
    diags: &mut Vec<Diagnostic>,
) {
    if process.max_processes != resources.max_processes {
        diags.push(Diagnostic::error(
            codes::POLICY_CONFLICT,
            "process.max_processes must equal resources.max_processes (normalized automatically)",
        ));
    }
    if process.allow_daemonize && process.kill_process_tree {
        diags.push(Diagnostic::warning(
            codes::POLICY_CONFLICT,
            "allow_daemonize with kill_process_tree: detached children are still killed at teardown",
        ));
    }
}

fn validate_network(network: &NetworkPolicy, diags: &mut Vec<Diagnostic>) {
    match network {
        NetworkPolicy::Disabled | NetworkPolicy::LoopbackOnly => {}
        NetworkPolicy::Restricted => {
            push(
                diags,
                "NetworkPolicy::Restricted is not implemented in phase 1; use Disabled or LoopbackOnly",
            );
        }
        NetworkPolicy::AllowAll => {
            push(
                diags,
                "NetworkPolicy::AllowAll is refused by the kernel: no provider can offer a safe full-network sandbox in phase 1",
            );
        }
    }
}

fn validate_security(security: &SecurityPolicy, diags: &mut Vec<Diagnostic>) {
    if security.require_seccomp && !security.use_seccomp {
        diags.push(Diagnostic::error(
            codes::POLICY_CONFLICT,
            "security.require_seccomp requires security.use_seccomp = true",
        ));
    }
}

fn validate_filesystem(filesystem: &FilesystemPolicy, diags: &mut Vec<Diagnostic>) {
    for p in filesystem
        .readonly_paths
        .iter()
        .chain(filesystem.writable_paths.iter())
    {
        if !p.is_absolute() {
            diags.push(Diagnostic::error(
                codes::POLICY_PATH_INVALID,
                format!("filesystem policy paths must be absolute: {}", p.display()),
            ));
        }
        if contains_parent_component(p) {
            diags.push(Diagnostic::error(
                codes::POLICY_PATH_INVALID,
                format!("filesystem policy path contains '..': {}", p.display()),
            ));
        }
    }
    let total = filesystem.readonly_paths.len() + filesystem.writable_paths.len();
    if total > bounds::MAX_POLICY_PATHS {
        push(
            diags,
            format!(
                "too many filesystem policy paths (max {})",
                bounds::MAX_POLICY_PATHS
            ),
        );
    }
    // A path must not be declared both readonly and writable.
    for ro in &filesystem.readonly_paths {
        if filesystem.writable_paths.contains(ro) {
            diags.push(Diagnostic::error(
                codes::POLICY_CONFLICT,
                format!("path declared both readonly and writable: {}", ro.display()),
            ));
        }
    }
}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|c| c == std::path::Component::ParentDir)
}

/// Conveniences used by tests and the CLI: check a wall time directly.
pub fn check_wall_time(d: Duration) -> Result<(), &'static str> {
    bounds::check_wall_time(d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use nsk_core::spec::{CommandSpec, WorkspaceSpec};
    use std::path::PathBuf;

    fn base_spec() -> SandboxSpec {
        let mut s = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        s.workspace = WorkspaceSpec::ephemeral();
        s
    }

    #[test]
    fn minimal_policy_is_valid() {
        assert!(validate_policy(&SandboxPolicy::minimal()).is_ok());
        assert!(validate_policy(&SandboxPolicy::strict()).is_ok());
        assert!(validate_policy(&SandboxPolicy::extended()).is_ok());
        assert!(validate_spec(&base_spec()).is_ok());
    }

    #[test]
    fn out_of_bounds_values_rejected() {
        let mut p = SandboxPolicy::minimal();
        p.resources.wall_time = Duration::from_secs(7200);
        let err = validate_policy(&p).unwrap_err();
        match &err {
            SandboxError::PolicyValidation(diags) => {
                assert!(
                    diags
                        .iter()
                        .any(|d| d.message.contains("resources.wall_time"))
                );
            }
            other => panic!("unexpected error: {other}"),
        }

        let mut p = SandboxPolicy::minimal();
        p.resources.memory_bytes = 999;
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.resources.max_processes = 0;
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.output.max_stdout_bytes = 100;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn cpu_quota_bounds() {
        let mut p = SandboxPolicy::minimal();
        p.resources.cpu_quota = Some(CpuQuota::new(0.0));
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.resources.cpu_quota = Some(CpuQuota::new(100000.0));
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn swap_must_not_exceed_memory() {
        let mut p = SandboxPolicy::minimal();
        p.resources.swap_bytes = Some(p.resources.memory_bytes * 2);
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn combined_output_limit_must_cover_singles() {
        let mut p = SandboxPolicy::minimal();
        p.output.combined_limit_bytes = p.output.max_stderr_bytes - 1024;
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.resources.max_output_bytes = p.output.combined_limit_bytes - 1024;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn network_policies() {
        let mut p = SandboxPolicy::minimal();
        p.network = NetworkPolicy::AllowAll;
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.network = NetworkPolicy::Restricted;
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.network = NetworkPolicy::LoopbackOnly;
        assert!(validate_policy(&p).is_ok());
    }

    #[test]
    fn seccomp_conflict_detected() {
        let mut p = SandboxPolicy::minimal();
        p.security.require_seccomp = true;
        p.security.use_seccomp = false;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn filesystem_conflicts_detected() {
        let mut p = SandboxPolicy::minimal();
        p.isolation.isolate_filesystem = false;
        p.filesystem.deny_host_paths = true;
        assert!(validate_policy(&p).is_err());

        let mut p = SandboxPolicy::minimal();
        p.filesystem.isolate_root = true;
        p.isolation.isolate_filesystem = false;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn dual_role_path_rejected() {
        let mut p = SandboxPolicy::minimal();
        let path = PathBuf::from("/etc/localtime");
        p.filesystem.readonly_paths.push(path.clone());
        p.filesystem.writable_paths.push(path);
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn traversal_path_rejected() {
        let mut p = SandboxPolicy::minimal();
        p.filesystem
            .readonly_paths
            .push(PathBuf::from("/etc/../etc/passwd"));
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn daemonize_conflict_is_warning_only() {
        let mut p = SandboxPolicy::minimal();
        p.process.allow_daemonize = true;
        // Warning must not block execution…
        assert!(validate_policy(&p).is_ok());
        // …but must be surfaced by diagnosis.
        let diags = diagnose_policy(&p);
        assert!(
            diags
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Warning
                    && d.message.contains("daemonize"))
        );
    }
}
