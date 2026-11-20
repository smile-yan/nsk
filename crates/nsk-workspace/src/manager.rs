//! Workspace manager (design document §5.5, Phase 4).
//!
//! Responsibilities:
//! * create a kernel-owned ephemeral workspace or adopt a user-provided root,
//! * create requested writable sub-directories,
//! * verify path safety with symlink awareness,
//! * clean up kernel-owned workspaces when policy asks for it.
//!
//! Safety rules:
//! * **User-provided roots are never deleted** by the kernel, regardless of
//!   `cleanup_on_exit` (deleting a caller's directory is not a sandbox
//!   decision). The deviation is recorded as a diagnostic.
//! * Kernel-owned workspaces live under a dedicated base directory and their
//!   names embed the sandbox id, so cleanup targets are unambiguous.

use std::path::{Path, PathBuf};

use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::id::SandboxId;
use nsk_core::spec::WorkspaceSpec;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::cleanup::remove_tree_safe;
use crate::path::{PathValidator, ensure_directory};

/// Configuration of the workspace manager.
#[derive(Debug, Clone)]
pub struct WorkspaceManagerConfig {
    /// Base directory for kernel-owned workspaces. `None` = OS temp dir
    /// joined with `nsk-workspaces`.
    pub base_dir: Option<PathBuf>,
    /// Prefix for kernel-owned workspace directory names.
    pub prefix: String,
    /// Maximum artifact entries reported per execution.
    pub max_artifacts: usize,
}

impl Default for WorkspaceManagerConfig {
    fn default() -> Self {
        Self {
            base_dir: None,
            prefix: "nsk-ws-".to_string(),
            max_artifacts: 1024,
        }
    }
}

impl WorkspaceManagerConfig {
    /// Resolve the effective base directory (always ends with a dedicated
    /// `nsk-workspaces` segment so cleanup scans never mix with other data).
    pub fn effective_base(&self) -> PathBuf {
        match &self.base_dir {
            Some(p) => p.join("nsk-workspaces"),
            None => std::env::temp_dir().join("nsk-workspaces"),
        }
    }
}

/// A prepared workspace handed to the provider and supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedWorkspace {
    /// Workspace root (canonical, existing).
    pub root: PathBuf,
    /// Writable sub-directories created inside the root (relative).
    pub writable_subdirs: Vec<PathBuf>,
    /// Host paths mounted read-only (from the workspace spec).
    pub readonly_host_paths: Vec<PathBuf>,
    /// True when the kernel created this workspace and owns its lifecycle.
    pub kernel_created: bool,
    /// Whether cleanup should remove the directory.
    pub cleanup_on_exit: bool,
    /// Diagnostics produced during preparation.
    pub diagnostics: Vec<Diagnostic>,
}

impl PreparedWorkspace {
    /// The child working directory for `relative` inside the workspace.
    pub fn subdir(&self, relative: &Path) -> PathBuf {
        self.root.join(relative)
    }
}

/// Workspace preparation / cleanup failures.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace path validation failed: {0}")]
    Path(#[from] crate::path::PathError),
    #[error("workspace io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

/// Creates, validates and cleans workspaces.
#[derive(Debug, Clone)]
pub struct WorkspaceManager {
    config: WorkspaceManagerConfig,
}

impl WorkspaceManager {
    pub fn new(config: WorkspaceManagerConfig) -> Self {
        Self { config }
    }

    /// Manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(WorkspaceManagerConfig::default())
    }

    /// Prepare the workspace described by `spec` for sandbox `id`.
    ///
    /// Behavior:
    /// * `spec.root` empty → create `<base>/<prefix><id>` (kernel-created),
    /// * `spec.root` set → must exist (or is created when missing? No: must
    ///   exist and be a directory; adopting a directory the kernel did not
    ///   create is restricted to existing directories to avoid surprises),
    /// * writable sub-dirs are created and symlink-checked,
    /// * readonly host paths are existence-checked when present.
    pub fn prepare(
        &self,
        spec: &WorkspaceSpec,
        id: &SandboxId,
    ) -> Result<PreparedWorkspace, WorkspaceError> {
        let mut diagnostics = Vec::new();
        let (root, kernel_created) = if spec.root.as_os_str().is_empty() {
            let base = self.config.effective_base();
            std::fs::create_dir_all(&base)?;
            let dir = base.join(format!("{}{}", self.config.prefix, id.short()));
            std::fs::create_dir(&dir).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    WorkspaceError::Other(format!(
                        "workspace {} already exists from a previous run; remove it or use a new id",
                        dir.display()
                    ))
                } else {
                    WorkspaceError::Io(e)
                }
            })?;
            (dir, true)
        } else {
            ensure_directory(&spec.root)?;
            (spec.root.clone(), false)
        };

        if !kernel_created && spec.cleanup_on_exit {
            diagnostics.push(Diagnostic::warning(
                codes::CLEANUP_SKIPPED,
                format!(
                    "cleanup_on_exit requested but workspace root {} was not created by the kernel; it will not be deleted",
                    root.display()
                ),
            ));
        }

        let validator = PathValidator::new(&root)?;

        // Writable sub-directories.
        let mut writable_subdirs = Vec::new();
        for rel in &spec.writable_paths {
            let target = root.join(rel);
            if !target.exists() {
                std::fs::create_dir_all(&target)?;
            }
            let canonical = validator.validate_inside(&target)?;
            writable_subdirs.push(canonical);
            debug!(workspace = %root.display(), dir = %target.display(), "workspace writable dir ready");
        }

        // Readonly host paths: existence check when present (mounting is the
        // provider's job).
        for host in &spec.readonly_paths {
            if !host.exists() {
                return Err(WorkspaceError::Other(format!(
                    "readonly host path does not exist: {}",
                    host.display()
                )));
            }
            // The host path must not point into the workspace itself as a
            // symlink trick to gain write access later.
            if host.is_symlink() {
                diagnostics.push(Diagnostic::warning(
                    codes::FS_SYMLINK_REJECTED,
                    format!(
                        "readonly host path {} is a symlink; its target will be mounted read-only",
                        host.display()
                    ),
                ));
            }
        }

        Ok(PreparedWorkspace {
            root: validator.canonical_root().to_path_buf(),
            writable_subdirs,
            readonly_host_paths: spec.readonly_paths.clone(),
            kernel_created,
            cleanup_on_exit: spec.cleanup_on_exit && kernel_created,
            diagnostics,
        })
    }

    /// Idempotent cleanup of a prepared workspace.
    ///
    /// Only kernel-created workspaces with `cleanup_on_exit` are deleted.
    pub fn cleanup(
        &self,
        workspace: &PreparedWorkspace,
    ) -> Result<Vec<Diagnostic>, WorkspaceError> {
        let mut diags = workspace.diagnostics.clone();
        if !workspace.kernel_created || !workspace.cleanup_on_exit {
            if workspace.kernel_created {
                debug!(workspace = %workspace.root.display(), "workspace cleanup skipped by policy");
            }
            return Ok(diags);
        }
        let outcome = remove_tree_safe(&workspace.root);
        diags.extend(outcome.diagnostics);
        if !outcome.removed && workspace.root.exists() {
            warn!(workspace = %workspace.root.display(), "workspace cleanup incomplete");
            diags.push(Diagnostic::error(
                codes::FS_WORKSPACE_NOT_REMOVED,
                format!(
                    "workspace {} could not be fully removed",
                    workspace.root.display()
                ),
            ));
            return Err(WorkspaceError::Other(format!(
                "cleanup incomplete for {}",
                workspace.root.display()
            )));
        }
        debug!(workspace = %workspace.root.display(), "workspace removed");
        Ok(diags)
    }

    /// Scan the base directory for stale kernel-owned workspaces.
    ///
    /// Returns workspace directories matching the kernel prefix. Used by
    /// recovery tooling (`nsk cleanup`) after crashes.
    pub fn find_stale_workspaces(&self) -> Result<Vec<PathBuf>, WorkspaceError> {
        let base = self.config.effective_base();
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&base) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(WorkspaceError::Io(e)),
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(&self.config.prefix) {
                        out.push(p);
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn config(&self) -> &WorkspaceManagerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> SandboxId {
        SandboxId::new()
    }

    #[test]
    fn creates_ephemeral_workspace() {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });

        let ws = manager
            .prepare(&WorkspaceSpec::ephemeral(), &id())
            .expect("prepare");
        assert!(ws.kernel_created);
        assert!(ws.cleanup_on_exit);
        assert!(ws.root.exists());
        let canonical_base = std::fs::canonicalize(base.path().join("nsk-workspaces")).unwrap();
        assert!(ws.root.starts_with(canonical_base));

        let diags = manager.cleanup(&ws).expect("cleanup");
        assert!(!ws.root.exists());
        assert!(diags.is_empty());
    }

    #[test]
    fn creates_writable_subdirs() {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });

        let spec = WorkspaceSpec {
            root: PathBuf::new(),
            writable_paths: vec![PathBuf::from("out"), PathBuf::from("tmp/cache")],
            readonly_paths: vec![],
            cleanup_on_exit: true,
        };
        let ws = manager.prepare(&spec, &id()).expect("prepare");
        assert!(ws.subdir(Path::new("out")).is_dir());
        assert!(ws.subdir(Path::new("tmp/cache")).is_dir());
        assert_eq!(ws.writable_subdirs.len(), 2);
        manager.cleanup(&ws).expect("cleanup");
    }

    #[test]
    fn user_root_never_deleted() {
        let user_dir = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });

        let spec = WorkspaceSpec {
            root: user_dir.path().to_path_buf(),
            writable_paths: vec![],
            readonly_paths: vec![],
            cleanup_on_exit: true, // kernel must still refuse to delete
        };
        let ws = manager.prepare(&spec, &id()).expect("prepare");
        assert!(!ws.kernel_created);
        assert!(!ws.cleanup_on_exit);
        assert!(
            ws.diagnostics
                .iter()
                .any(|d| d.code == codes::CLEANUP_SKIPPED)
        );

        manager.cleanup(&ws).expect("cleanup must be a no-op");
        assert!(user_dir.path().exists(), "user directory must survive");
    }

    #[test]
    fn missing_user_root_rejected() {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });
        let spec = WorkspaceSpec {
            root: base.path().join("does-not-exist"),
            ..Default::default()
        };
        assert!(manager.prepare(&spec, &id()).is_err());
    }

    #[test]
    fn readonly_host_path_must_exist() {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });
        let spec = WorkspaceSpec {
            root: PathBuf::new(),
            writable_paths: vec![],
            readonly_paths: vec![base.path().join("ghost-file")],
            cleanup_on_exit: true,
        };
        assert!(manager.prepare(&spec, &id()).is_err());
    }

    #[test]
    fn stale_workspaces_are_discoverable() {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });
        let ws = manager
            .prepare(&WorkspaceSpec::ephemeral(), &id())
            .expect("prepare");
        let stale = manager.find_stale_workspaces().expect("scan");
        assert_eq!(stale.len(), 1);
        // find_stale_workspaces lists directory entries as-is (non-canonical)
        // on macOS (/var -> /private/var); compare canonicalized.
        assert_eq!(
            std::fs::canonicalize(&stale[0]).unwrap(),
            ws.root,
            "stale entry should be the created workspace"
        );
        manager.cleanup(&ws).expect("cleanup");
        let stale = manager.find_stale_workspaces().expect("scan");
        assert!(stale.is_empty());
    }

    #[test]
    fn duplicate_prepare_on_same_id_is_rejected() {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });
        let sandbox_id = id();
        manager
            .prepare(&WorkspaceSpec::ephemeral(), &sandbox_id)
            .expect("first prepare");
        let second = manager.prepare(&WorkspaceSpec::ephemeral(), &sandbox_id);
        assert!(second.is_err(), "same-id workspace must not be recreated");
        // But cleanup of the first succeeds and frees the name.
        // (The first handle is required; emulate by listing stale dirs.)
        let stale = manager.find_stale_workspaces().unwrap();
        assert_eq!(stale.len(), 1);
        assert!(remove_tree_safe(&stale[0]).removed);
        manager
            .prepare(&WorkspaceSpec::ephemeral(), &sandbox_id)
            .expect("prepare after manual cleanup");
    }
}
