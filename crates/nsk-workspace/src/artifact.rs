//! Artifact listing (§ Phase 4: Artifact Collection).
//!
//! Reports which files a program left in the workspace. Bound by count and
//! depth to keep result sizes predictable.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// One artifact discovered in the workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// Path relative to the workspace root.
    pub relative_path: String,
    pub size_bytes: u64,
    pub is_dir: bool,
}

/// Options for artifact collection.
#[derive(Debug, Clone, Copy)]
pub struct CollectOptions {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_depth: 16,
        }
    }
}

/// Collect the artifact list of a workspace.
///
/// Returns `(artifacts, truncated)`; `truncated` is true when the listing
/// was cut short by `max_entries` or `max_depth`.
pub fn collect_artifacts(root: &Path) -> (Vec<ArtifactInfo>, bool) {
    collect_artifacts_with(root, CollectOptions::default())
}

/// Collect artifacts with explicit options.
pub fn collect_artifacts_with(root: &Path, opts: CollectOptions) -> (Vec<ArtifactInfo>, bool) {
    let mut out = Vec::new();
    let truncated = walk(root, root, &mut out, 0, opts);
    (out, truncated)
}

fn walk(
    root: &Path,
    dir: &Path,
    out: &mut Vec<ArtifactInfo>,
    depth: usize,
    opts: CollectOptions,
) -> bool {
    if depth > opts.max_depth || out.len() >= opts.max_entries {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut truncated = false;
    for entry in entries.flatten() {
        if out.len() >= opts.max_entries {
            return true;
        }
        let path = entry.path();
        // Do not follow symlinks while listing (informational only).
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let is_dir = meta.is_dir();
        out.push(ArtifactInfo {
            relative_path: rel,
            size_bytes: if is_dir { 0 } else { meta.len() },
            is_dir,
        });
        if is_dir && !meta.file_type().is_symlink() {
            truncated |= walk(root, &path, out, depth + 1, opts);
        }
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn lists_files_and_dirs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("out/sub")).unwrap();
        fs::write(dir.path().join("out/a.txt"), b"12345").unwrap();
        fs::write(dir.path().join("out/sub/b.bin"), b"xy").unwrap();

        let (arts, truncated) = collect_artifacts(dir.path());
        assert!(!truncated);
        assert_eq!(arts.len(), 4); // out/, out/a.txt, out/sub/, out/sub/b.bin
        let a = arts
            .iter()
            .find(|a| a.relative_path == "out/a.txt")
            .expect("a.txt");
        assert_eq!(a.size_bytes, 5);
        assert!(!a.is_dir);
    }

    #[test]
    fn respects_entry_cap() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
        }
        let (arts, truncated) = collect_artifacts_with(
            dir.path(),
            CollectOptions {
                max_entries: 5,
                max_depth: 8,
            },
        );
        assert_eq!(arts.len(), 5);
        assert!(truncated);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_listed_but_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("deep_file"), b"z").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();

        let (arts, _) = collect_artifacts(dir.path());
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0].relative_path, "escape");
        // symlink_metadata: the link itself is not a directory entry we follow
        assert!(!arts[0].is_dir);
        // The outside file must not be listed.
        assert!(!arts.iter().any(|a| a.relative_path.contains("deep_file")));
    }
}
