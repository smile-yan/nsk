//! Policy normalization (design document §6.2 Policy Normalization).
//!
//! Normalization turns a requested policy into a canonical form so that
//! validation and capability matching only ever see consistent input:
//! * duplicate environment variables / paths are removed (first wins),
//! * output limits are reconciled (`combined >= max(single)`,
//!   `resources.max_output_bytes >= combined`),
//! * `process.max_processes` is synced with `resources.max_processes`,
//! * empty working directory marker is left untouched (resolved later by the
//!   runtime against the workspace root).
//!
//! Every adjustment is reported as a `Warning` diagnostic so the caller can
//! see how the effective policy differs from the request.

use std::collections::HashSet;
use std::path::PathBuf;

use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::policy::SandboxPolicy;
use nsk_core::spec::{SandboxSpec, WorkspaceSpec};

/// Normalize a spec (id, command, workspace, environment and policy).
pub fn normalize_spec(spec: &SandboxSpec) -> (SandboxSpec, Vec<Diagnostic>) {
    let mut diags = Vec::new();

    let mut normalized = spec.clone();

    // Environment: dedupe keys, first wins.
    let mut seen = HashSet::new();
    let mut env = Vec::new();
    for var in &spec.environment.variables {
        if seen.insert(var.key.clone()) {
            env.push(var.clone());
        } else {
            diags.push(Diagnostic::warning(
                codes::POLICY_NORMALIZED,
                format!("duplicate environment variable dropped: {}", var.key),
            ));
        }
    }
    normalized.environment.variables = env;

    // Workspace: dedupe paths.
    normalized.workspace = normalize_workspace(&spec.workspace, &mut diags);

    // Policy.
    let (policy, policy_diags) = normalize_policy(&spec.policy);
    normalized.policy = policy;
    diags.extend(policy_diags);

    (normalized, diags)
}

/// Normalize a workspace spec.
pub fn normalize_workspace(spec: &WorkspaceSpec, diags: &mut Vec<Diagnostic>) -> WorkspaceSpec {
    let dedupe = |paths: &[PathBuf], diags: &mut Vec<Diagnostic>| -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for p in paths {
            if seen.insert(p.clone()) {
                out.push(p.clone());
            } else {
                diags.push(Diagnostic::warning(
                    codes::POLICY_NORMALIZED,
                    format!("duplicate workspace path dropped: {}", p.display()),
                ));
            }
        }
        out
    };

    WorkspaceSpec {
        root: spec.root.clone(),
        writable_paths: dedupe(&spec.writable_paths, diags),
        readonly_paths: dedupe(&spec.readonly_paths, diags),
        cleanup_on_exit: spec.cleanup_on_exit,
    }
}

/// Normalize a policy; returns the canonical policy and its diagnostics.
pub fn normalize_policy(policy: &SandboxPolicy) -> (SandboxPolicy, Vec<Diagnostic>) {
    let mut diags = Vec::new();
    let mut p = policy.clone();

    // Sync process limit with resource limit.
    if p.process.max_processes != p.resources.max_processes {
        p.process.max_processes = p.resources.max_processes;
        diags.push(Diagnostic::warning(
            codes::POLICY_NORMALIZED,
            "process.max_processes synced with resources.max_processes",
        ));
    }

    // Reconcile output limits.
    let single_max = p.output.max_stdout_bytes.max(p.output.max_stderr_bytes);
    if p.output.combined_limit_bytes < single_max {
        p.output.combined_limit_bytes = single_max;
        diags.push(Diagnostic::warning(
            codes::POLICY_NORMALIZED,
            "output.combined_limit_bytes raised to max(stdout, stderr)",
        ));
    }
    if p.resources.max_output_bytes < p.output.combined_limit_bytes {
        p.resources.max_output_bytes = p.output.combined_limit_bytes;
        diags.push(Diagnostic::warning(
            codes::POLICY_NORMALIZED,
            "resources.max_output_bytes raised to output.combined_limit_bytes",
        ));
    }

    // Deduplicate filesystem paths.
    let dedupe_fs = |paths: &[PathBuf], what: &str, diags: &mut Vec<Diagnostic>| -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for path in paths {
            if seen.insert(path.clone()) {
                out.push(path.clone());
            } else {
                diags.push(Diagnostic::warning(
                    codes::POLICY_NORMALIZED,
                    format!("duplicate {what} path dropped: {}", path.display()),
                ));
            }
        }
        out
    };
    p.filesystem.readonly_paths = dedupe_fs(&p.filesystem.readonly_paths, "readonly", &mut diags);
    p.filesystem.writable_paths = dedupe_fs(&p.filesystem.writable_paths, "writable", &mut diags);

    (p, diags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsk_core::spec::CommandSpec;

    #[test]
    fn duplicate_env_dropped_first_wins() {
        let spec = SandboxSpec::new(CommandSpec::new("/bin/echo"))
            .with_env("A", "first")
            .with_env("A", "second");
        let (norm, diags) = normalize_spec(&spec);
        assert_eq!(norm.environment.variables.len(), 1);
        assert_eq!(norm.environment.variables[0].value, "first");
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn process_limit_synced() {
        let mut p = SandboxPolicy::minimal();
        p.process.max_processes = 99;
        let (norm, diags) = normalize_policy(&p);
        assert_eq!(norm.process.max_processes, norm.resources.max_processes);
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn output_limits_reconciled_upwards() {
        let mut p = SandboxPolicy::minimal();
        p.output.max_stdout_bytes = 2048;
        p.output.max_stderr_bytes = 2048;
        p.output.combined_limit_bytes = 1024;
        p.resources.max_output_bytes = 1024;
        let (norm, diags) = normalize_policy(&p);
        assert_eq!(norm.output.combined_limit_bytes, 2048);
        assert_eq!(norm.resources.max_output_bytes, 2048);
        assert_eq!(diags.len(), 2);
        // Normalized policy must now pass validation.
        assert!(nsk_policy_validate(&norm));
    }

    fn nsk_policy_validate(p: &SandboxPolicy) -> bool {
        crate::validate::validate_policy(p).is_ok()
    }

    #[test]
    fn duplicate_paths_dropped() {
        let mut p = SandboxPolicy::minimal();
        p.filesystem
            .readonly_paths
            .push(std::path::PathBuf::from("/etc/hosts"));
        p.filesystem
            .readonly_paths
            .push(std::path::PathBuf::from("/etc/hosts"));
        let (norm, diags) = normalize_policy(&p);
        assert_eq!(norm.filesystem.readonly_paths.len(), 1);
        assert_eq!(diags.len(), 1);
    }
}
