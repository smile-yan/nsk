//! Idempotent, symlink-safe tree removal (§4.3 cleanup rules).
//!
//! Safety properties:
//! * symlinks encountered during traversal are removed as *links*, never
//!   followed, so cleanup cannot delete anything outside the workspace,
//! * removing a missing target succeeds (idempotency),
//! * failures are collected instead of aborting the first error.

use std::path::Path;

use nsk_core::diagnostic::{Diagnostic, codes};

/// Outcome of one tree removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupOutcome {
    /// True when the path is gone (or never existed).
    pub removed: bool,
    /// Diagnostics for anything that could not be removed.
    pub diagnostics: Vec<Diagnostic>,
}

impl CleanupOutcome {
    pub fn ok() -> Self {
        Self {
            removed: true,
            diagnostics: Vec::new(),
        }
    }
}

/// Remove a directory tree without following symlinks.
///
/// `remove_dir_all` in the standard library is already symlink-safe on Unix
/// (it refuses to cross symlink boundaries); this wrapper adds idempotency,
/// diagnostics collection and an explicit symlink unlinked-as-link pass.
pub fn remove_tree_safe(path: &Path) -> CleanupOutcome {
    if let Err(e) = reject_hostile_components(path) {
        return CleanupOutcome {
            removed: false,
            diagnostics: vec![Diagnostic::error(codes::CLEANUP_FAILED, e)],
        };
    }

    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                match std::fs::remove_file(path) {
                    Ok(()) => CleanupOutcome::ok(),
                    Err(e) => CleanupOutcome {
                        removed: false,
                        diagnostics: vec![Diagnostic::error(
                            codes::CLEANUP_FAILED,
                            format!("failed to remove symlink {}: {e}", path.display()),
                        )],
                    },
                }
            } else {
                match remove_dir_all_careful(path) {
                    Ok(()) => CleanupOutcome::ok(),
                    Err(diags) => CleanupOutcome {
                        removed: false,
                        diagnostics: diags,
                    },
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Already gone: idempotent success.
            CleanupOutcome::ok()
        }
        Err(e) => CleanupOutcome {
            removed: false,
            diagnostics: vec![Diagnostic::error(
                codes::CLEANUP_FAILED,
                format!("failed to inspect {}: {e}", path.display()),
            )],
        },
    }
}

fn reject_hostile_components(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("refusing to remove empty path".into());
    }
    if path
        .components()
        .any(|c| c == std::path::Component::RootDir)
    {
        // Safety valve: never remove filesystem root or first-level dirs.
        if path.parent() == Some(Path::new("/")) || path == Path::new("/") {
            return Err(format!(
                "refusing to remove top-level path {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn remove_dir_all_careful(path: &Path) -> Result<(), Vec<Diagnostic>> {
    // First unlink any symlink entries at any depth (they must not be
    // traversed); std's remove_dir_all already treats symlinks correctly on
    // unix, but we double-check explicitly for diagnostics.
    let mut diags = Vec::new();
    unlink_symlinks_below(path, &mut diags, 0);
    match std::fs::remove_dir_all(path) {
        Ok(()) => {
            if diags.is_empty() {
                Ok(())
            } else {
                Err(diags)
            }
        }
        Err(e) => {
            diags.push(Diagnostic::error(
                codes::CLEANUP_FAILED,
                format!("failed to remove {}: {e}", path.display()),
            ));
            Err(diags)
        }
    }
}

const MAX_CLEANUP_DEPTH: usize = 64;

fn unlink_symlinks_below(dir: &Path, diags: &mut Vec<Diagnostic>, depth: usize) {
    if depth > MAX_CLEANUP_DEPTH {
        diags.push(Diagnostic::warning(
            codes::CLEANUP_INCOMPLETE,
            format!("cleanup depth limit reached at {}", dir.display()),
        ));
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            if let Err(e) = std::fs::remove_file(&p) {
                diags.push(Diagnostic::warning(
                    codes::CLEANUP_INCOMPLETE,
                    format!("failed to unlink symlink {}: {e}", p.display()),
                ));
            }
        } else if meta.is_dir() {
            unlink_symlinks_below(&p, diags, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn removes_plain_tree() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("tree");
        fs::create_dir_all(target.join("a/b")).unwrap();
        fs::write(target.join("a/b/f"), b"x").unwrap();

        assert!(remove_tree_safe(&target).removed);
        assert!(!target.exists());
    }

    #[test]
    fn idempotent_removal() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone");
        let outcome = remove_tree_safe(&missing);
        assert!(outcome.removed);
        assert!(outcome.diagnostics.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn removes_symlink_without_following() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        fs::write(&victim, b"important").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let outcome = remove_tree_safe(&link);
        assert!(outcome.removed);
        // The link is gone; the victim survives.
        assert!(!link.exists());
        assert!(victim.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tree_with_symlinks_does_not_follow_out() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"keep").unwrap();

        let tree = dir.path().join("tree");
        fs::create_dir_all(&tree).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("out")).unwrap();

        assert!(remove_tree_safe(&tree).removed);
        assert!(!tree.exists());
        // Outside directory untouched.
        assert!(outside.join("keep").exists());
    }

    #[test]
    fn refuses_root() {
        let outcome = remove_tree_safe(Path::new("/"));
        assert!(!outcome.removed);
        assert_eq!(outcome.diagnostics.len(), 1);
        let outcome = remove_tree_safe(Path::new(""));
        assert!(!outcome.removed);
    }
}
