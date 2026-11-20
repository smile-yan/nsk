//! Path safety primitives (design document §6.3 path rules).
//!
//! Rules implemented here:
//! * paths are validated against their **canonical** (fully symlink-resolved)
//!   form, never by string comparison,
//! * symlink escapes are detected before they happen: a path is accepted
//!   only when its canonical form stays inside the canonical root,
//! * `..` traversal is neutralized by canonicalization.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Path validation failures.
#[derive(Debug, Error)]
pub enum PathError {
    #[error("path contains a `..` component: {0}")]
    ParentComponent(PathBuf),
    #[error("path {0} does not exist")]
    NotFound(PathBuf),
    #[error("path {0} is not a directory")]
    NotADirectory(PathBuf),
    #[error("path {0} is outside the allowed root {1}")]
    OutsideRoot(PathBuf, PathBuf),
    #[error("path {0} resolves through a symlink outside the allowed root {1}")]
    SymlinkEscape(PathBuf, PathBuf),
    #[error("io error on {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("path contains NUL byte: {0}")]
    NulByte(PathBuf),
}

/// A validator bound to one canonical root.
#[derive(Debug, Clone)]
pub struct PathValidator {
    canonical_root: PathBuf,
    /// When false, only syntactic checks are applied (used for host paths
    /// the provider will mount; containment is the provider's decision).
    enforce_containment: bool,
}

impl PathValidator {
    /// Create a validator rooted at `root` (created if missing).
    pub fn new(root: &Path) -> Result<Self, PathError> {
        std::fs::create_dir_all(root).map_err(|e| PathError::Io(root.to_path_buf(), e))?;
        let canonical = canonicalize_strict(root)?;
        Ok(Self {
            canonical_root: canonical,
            enforce_containment: true,
        })
    }

    /// A validator that performs syntactic checks but no containment check.
    pub fn without_containment() -> Self {
        Self {
            canonical_root: PathBuf::new(),
            enforce_containment: false,
        }
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Validate that `path` is a safe, existing, canonical-inside-root path.
    ///
    /// Symlinks are followed; the *resolved* location must remain inside the
    /// root (§6.3: symlink escape must not bypass policy).
    pub fn validate_inside(&self, path: &Path) -> Result<PathBuf, PathError> {
        self.validate_components(path)?;
        if path.is_symlink() && self.enforce_containment {
            // Symlink itself will be resolved below; flag only the escape case.
        }
        let canonical = canonicalize_strict(path)?;
        if self.enforce_containment && !canonical.starts_with(&self.canonical_root) {
            return Err(PathError::SymlinkEscape(
                path.to_path_buf(),
                self.canonical_root.clone(),
            ));
        }
        Ok(canonical)
    }

    /// Validate a path that may not exist yet; the deepest existing ancestor
    /// must stay inside the root.
    pub fn validate_inside_possible(&self, path: &Path) -> Result<PathBuf, PathError> {
        self.validate_components(path)?;
        let deepest = deepest_existing(path)?;
        let canonical = canonicalize_strict(&deepest)?;
        if self.enforce_containment && !canonical.starts_with(&self.canonical_root) {
            return Err(PathError::SymlinkEscape(
                path.to_path_buf(),
                self.canonical_root.clone(),
            ));
        }
        Ok(path.to_path_buf())
    }

    /// Reject `..` components and NUL bytes; allow absolute paths.
    fn validate_components(&self, path: &Path) -> Result<(), PathError> {
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.contains(&0) {
            return Err(PathError::NulByte(path.to_path_buf()));
        }
        if path.components().any(|c| c == Component::ParentDir) {
            return Err(PathError::ParentComponent(path.to_path_buf()));
        }
        Ok(())
    }
}

/// Canonicalize strictly: error when the path does not exist.
pub fn canonicalize_strict(path: &Path) -> Result<PathBuf, PathError> {
    std::fs::canonicalize(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PathError::NotFound(path.to_path_buf())
        } else {
            PathError::Io(path.to_path_buf(), e)
        }
    })
}

/// Find the deepest ancestor of `path` that exists on disk.
fn deepest_existing(path: &Path) -> Result<PathBuf, PathError> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return Ok(current);
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => return Err(PathError::NotFound(path.to_path_buf())),
        }
    }
}

/// Check that a path is a directory.
pub fn ensure_directory(path: &Path) -> Result<(), PathError> {
    let meta = std::fs::metadata(path).map_err(|e| PathError::Io(path.to_path_buf(), e))?;
    if !meta.is_dir() {
        return Err(PathError::NotADirectory(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn accepts_paths_inside_root() {
        let dir = tmpdir();
        let root = dir.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("file.txt"), b"x").unwrap();

        let validator = PathValidator::new(&root).unwrap();
        let canon = validator.validate_inside(&root.join("file.txt")).unwrap();
        assert!(canon.ends_with("file.txt"));
    }

    #[test]
    fn rejects_parent_components() {
        let dir = tmpdir();
        let root = dir.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        let validator = PathValidator::new(&root).unwrap();
        let p = root.join("..").join("escape");
        assert!(matches!(
            validator.validate_inside(&p).unwrap_err(),
            PathError::ParentComponent(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn detects_symlink_escape() {
        let dir = tmpdir();
        let root = dir.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        let secret = dir.path().join("secret.txt");
        fs::write(&secret, b"top secret").unwrap();
        std::os::unix::fs::symlink(&secret, root.join("innocent")).unwrap();

        let validator = PathValidator::new(&root).unwrap();
        let err = validator
            .validate_inside(&root.join("innocent"))
            .unwrap_err();
        assert!(
            matches!(err, PathError::SymlinkEscape(_, _)),
            "expected symlink escape, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_chain_inside_root_is_allowed() {
        let dir = tmpdir();
        let root = dir.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        let real = root.join("real.txt");
        fs::write(&real, b"ok").unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();

        let validator = PathValidator::new(&root).unwrap();
        let canon = validator.validate_inside(&root.join("alias")).unwrap();
        assert!(canon.starts_with(validator.canonical_root()));
    }

    #[test]
    fn nonexistent_path_rejected() {
        let dir = tmpdir();
        let root = dir.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        let validator = PathValidator::new(&root).unwrap();
        assert!(matches!(
            validator.validate_inside(&root.join("nope.txt")),
            Err(PathError::NotFound(_))
        ));
    }

    #[test]
    fn possible_paths_validated_via_ancestors() {
        let dir = tmpdir();
        let root = dir.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        let validator = PathValidator::new(&root).unwrap();
        // Future directory inside root: accepted.
        assert!(
            validator
                .validate_inside_possible(&root.join("out/build"))
                .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_root_itself_is_resolved() {
        // Root is a symlink to the real dir: validator canonicalizes it, so
        // validation still works on real paths.
        let dir = tmpdir();
        let real = dir.path().join("real-root");
        fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("root-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        fs::write(real.join("f"), b"x").unwrap();

        let validator = PathValidator::new(&link).unwrap();
        assert!(validator.validate_inside(&link.join("f")).is_ok());
        // And a file outside the (canonical) root is rejected.
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, b"x").unwrap();
        assert!(validator.validate_inside(&outside).is_err());
    }
}
