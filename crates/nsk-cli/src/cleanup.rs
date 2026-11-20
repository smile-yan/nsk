//! `cleanup` subcommand: recover stale kernel-owned workspaces (§16.6
//! Recovery Tests support, `nsk cleanup` in Phase 13).

use nsk_workspace::manager::{WorkspaceManager, WorkspaceManagerConfig};

/// Scan and optionally remove stale workspaces.
///
/// Returns (found, removed) counts. Removal only touches directories the
/// kernel created (matching the `nsk-ws-` prefix under the configured base).
pub fn run_cleanup(
    base_dir: Option<std::path::PathBuf>,
    dry_run: bool,
    assume_yes: bool,
) -> Result<(usize, usize), String> {
    let manager = WorkspaceManager::new(match base_dir {
        Some(dir) => WorkspaceManagerConfig {
            base_dir: Some(dir),
            ..Default::default()
        },
        None => WorkspaceManagerConfig::default(),
    });
    let stale = manager
        .find_stale_workspaces()
        .map_err(|e| format!("scan failed: {e}"))?;
    let found = stale.len();
    if found == 0 {
        println!("no stale workspaces found");
        return Ok((0, 0));
    }

    for path in &stale {
        println!("stale workspace: {}", path.display());
    }

    if dry_run {
        println!("dry run: {found} stale workspace(s) would be removed");
        return Ok((found, 0));
    }

    if !assume_yes {
        println!("pass --yes to remove them");
        return Ok((found, 0));
    }

    let mut removed = 0;
    for path in &stale {
        match nsk_workspace::remove_tree_safe(path) {
            outcome if outcome.removed => {
                removed += 1;
                println!("removed: {}", path.display());
            }
            outcome => {
                for d in &outcome.diagnostics {
                    eprintln!("warning [{}]: {}", d.code, d.message);
                }
                eprintln!("failed to remove: {}", path.display());
            }
        }
    }
    println!("removed {removed}/{found} stale workspace(s)");
    Ok((found, removed))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn dry_run_reports_without_removal() {
        let base = tempfile::tempdir().unwrap();
        // Fabricate a stale workspace.
        let ws = base.path().join("nsk-workspaces/nsk-ws-stale1234");
        std::fs::create_dir_all(&ws).unwrap();

        let (found, removed) =
            run_cleanup(Some(base.path().to_path_buf()), true, false).expect("cleanup");
        assert_eq!(found, 1);
        assert_eq!(removed, 0);
        assert!(ws.exists());
    }

    #[test]
    fn removal_with_yes() {
        let base = tempfile::tempdir().unwrap();
        let ws = base.path().join("nsk-workspaces/nsk-ws-gone");
        std::fs::create_dir_all(&ws).unwrap();

        let (found, removed) =
            run_cleanup(Some(base.path().to_path_buf()), false, true).expect("cleanup");
        assert_eq!((found, removed), (1, 1));
        assert!(!ws.exists());
    }

    #[test]
    fn foreign_directories_untouched() {
        let base = tempfile::tempdir().unwrap();
        let foreign = base.path().join("nsk-workspaces/my-important-data");
        std::fs::create_dir_all(&foreign).unwrap();

        let (found, _) =
            run_cleanup(Some(base.path().to_path_buf()), false, true).expect("cleanup");
        assert_eq!(found, 0, "non-kernel directories are not candidates");
        assert!(foreign.exists());
    }
}
