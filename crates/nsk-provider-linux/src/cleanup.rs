//! Provider-level cleanup manager (§10.2 Cleanup Manager, §4.3 lifecycle
//! management rules).
//!
//! Cleanup is idempotent, ordered (cgroup kill → workspace → seccomp temp
//! files) and failure-tolerant: every failure becomes a diagnostic so
//! results are never lost to a cleanup problem (§4.3).

use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::id::SandboxId;
use tracing::{info, warn};

use crate::cgroup::CgroupManager;

/// Everything the cleanup pass needs to know about one sandbox.
#[derive(Debug, Clone, Default)]
pub struct CleanupTarget {
    pub id: SandboxId,
    pub cgroup: Option<CgroupManager>,
    /// Host paths owned by the provider (seccomp profile files).
    pub owned_files: Vec<std::path::PathBuf>,
}

/// Perform provider cleanup. Idempotent: safe to call repeatedly.
pub fn cleanup_sandbox(target: &CleanupTarget) -> Result<Vec<Diagnostic>, SandboxError> {
    let mut diags = Vec::new();

    // 1. Kill and destroy the cgroup (strongest resource first).
    if let Some(cg) = &target.cgroup {
        match cg.destroy() {
            Ok(mut d) => diags.append(&mut d),
            Err(e) => {
                warn!(id = %target.id, error = %e, "cgroup destroy failed");
                diags.push(Diagnostic::error(
                    codes::CLEANUP_FAILED,
                    format!("cgroup destroy failed: {e}"),
                ));
            }
        }
    }

    // 2. Remove provider-owned files (best effort).
    for file in &target.owned_files {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                diags.push(Diagnostic::warning(
                    codes::CLEANUP_INCOMPLETE,
                    format!("could not remove {}: {e}", file.display()),
                ));
            }
        }
    }

    if diags.is_empty() {
        info!(id = %target.id, "provider cleanup complete");
    } else {
        warn!(id = %target.id, count = diags.len(), "provider cleanup incomplete");
    }
    Ok(diags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_without_resources_is_noop() {
        let target = CleanupTarget {
            id: SandboxId::new(),
            cgroup: None,
            owned_files: vec![],
        };
        let diags = cleanup_sandbox(&target).expect("cleanup");
        assert!(diags.is_empty());
    }

    #[test]
    fn cleanup_tolerates_missing_files() {
        let target = CleanupTarget {
            id: SandboxId::new(),
            cgroup: None,
            owned_files: vec![std::path::PathBuf::from("/nonexistent-nsk/file.tmp")],
        };
        let diags = cleanup_sandbox(&target).expect("cleanup");
        assert!(diags.is_empty(), "missing file is not a failure");
    }
}
