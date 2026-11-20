//! Linux mount plan builder (§10.5).
//!
//! Turns the effective filesystem policy + host system shape into a concrete
//! [`MountPlan`]. Only explicitly allowed sources are ever mounted; with
//! `deny_host_paths` the allowed set is exactly: the default system set,
//! policy-declared readonly paths, and the workspace.

use std::path::{Path, PathBuf};

use nsk_core::policy::{FilesystemPolicy, IsolationPolicy};
use nsk_workspace::mount::{MountEntry, MountPlan};

use crate::bwrap::SandboxPathMapper;

/// System directories mounted read-only into every sandbox.
///
/// This is the phase-1 default for running typical dynamically-linked
/// programs (see §10.5). Deployments tune this via provider config.
#[derive(Debug, Clone)]
pub struct SystemMountSet {
    pub readonly_roots: Vec<PathBuf>,
    pub readonly_files: Vec<PathBuf>,
}

impl SystemMountSet {
    /// Default minimal set: /usr (+ merged-usr symlinks), ld.so.cache,
    /// /etc/localtime try-bind.
    pub fn default_for_host() -> Self {
        Self {
            readonly_roots: vec![PathBuf::from("/usr")],
            readonly_files: vec![
                PathBuf::from("/etc/ld.so.cache"),
                PathBuf::from("/etc/localtime"),
            ],
        }
    }

    /// All sources this set may expose (used for policy allowlisting).
    pub fn sources(&self) -> Vec<PathBuf> {
        self.readonly_roots
            .iter()
            .chain(self.readonly_files.iter())
            .cloned()
            .collect()
    }
}

/// Build the default mount plan for a sandbox.
///
/// Handles merged-usr systems (`/bin` → `usr/bin` symlinks) versus classic
/// layouts (`/bin` a real directory) by inspecting the host filesystem.
pub fn build_default_mount_plan(
    workspace_host_root: &Path,
    policy_fs: &FilesystemPolicy,
    isolation: &IsolationPolicy,
    system: &SystemMountSet,
) -> MountPlan {
    let mut plan = MountPlan::new();

    if isolation.isolate_filesystem {
        for root in &system.readonly_roots {
            if root.exists() {
                plan.push(MountEntry::ReadOnlyBind {
                    src: root.clone(),
                    dest: root.clone(),
                });
                // Merged-usr symlinks at the sandbox root.
                for (link, target) in [
                    ("/bin", "usr/bin"),
                    ("/lib", "usr/lib"),
                    ("/lib64", "usr/lib64"),
                    ("/sbin", "usr/sbin"),
                ] {
                    let host = PathBuf::from(link);
                    if host.is_symlink() {
                        plan.push(MountEntry::Symlink {
                            target: target.to_string(),
                            dest: host.to_path_buf(),
                        });
                    } else if host.exists() {
                        plan.push(MountEntry::ReadOnlyBind {
                            src: host.clone(),
                            dest: host.clone(),
                        });
                    }
                }
            }
        }
        for file in &system.readonly_files {
            if file.exists() {
                plan.push(MountEntry::ReadOnlyBindTry {
                    src: file.clone(),
                    dest: file.clone(),
                });
            }
        }

        // Policy-declared readonly host paths.
        for p in &policy_fs.readonly_paths {
            plan.push(MountEntry::ReadOnlyBindTry {
                src: p.clone(),
                dest: p.clone(),
            });
        }

        // /etc minimal directory so ld.so.cache etc. have a parent.
        plan.push(MountEntry::Tmpfs {
            dest: "/etc".into(),
        });
        plan.push(MountEntry::Proc {
            dest: "/proc".into(),
        });
        plan.push(MountEntry::Dev {
            dest: "/dev".into(),
        });
        plan.push(MountEntry::Tmpfs {
            dest: "/tmp".into(),
        });
    }

    // Workspace is always mounted writable.
    plan.push(MountEntry::Bind {
        src: workspace_host_root.to_path_buf(),
        dest: PathBuf::from("/workspace"),
    });

    plan
}

/// Build the path mapper matching a plan produced by
/// [`build_default_mount_plan`].
pub fn path_mapper(
    workspace_host_root: &Path,
    policy_fs: &FilesystemPolicy,
    system: &SystemMountSet,
) -> SandboxPathMapper {
    let mut host_prefixes = system.sources();
    host_prefixes.extend(policy_fs.readonly_paths.iter().cloned());
    SandboxPathMapper {
        workspace_host_root: workspace_host_root.to_path_buf(),
        workspace_sandbox_root: PathBuf::from("/workspace"),
        host_prefixes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_contains_workspace_and_fresh_trees() {
        let system = SystemMountSet::default_for_host();
        let policy = FilesystemPolicy::default();
        let isolation = IsolationPolicy::default();
        let plan = build_default_mount_plan(Path::new("/tmp/ws"), &policy, &isolation, &system);

        assert!(plan.entries.iter().any(
            |e| matches!(e, MountEntry::Bind { dest, .. } if dest == &PathBuf::from("/workspace"))
        ));
        assert!(
            plan.entries
                .iter()
                .any(|e| matches!(e, MountEntry::Tmpfs { dest } if dest == &PathBuf::from("/tmp")))
        );
        assert!(
            plan.entries
                .iter()
                .any(|e| matches!(e, MountEntry::Proc { dest } if dest == &PathBuf::from("/proc")))
        );
        assert!(
            plan.entries
                .iter()
                .any(|e| matches!(e, MountEntry::Dev { dest } if dest == &PathBuf::from("/dev")))
        );
    }

    #[test]
    fn home_is_never_mounted() {
        let system = SystemMountSet::default_for_host();
        let policy = FilesystemPolicy::default();
        let isolation = IsolationPolicy::default();
        let plan = build_default_mount_plan(Path::new("/tmp/ws"), &policy, &isolation, &system);
        for e in &plan.entries {
            let src = match e {
                MountEntry::ReadOnlyBind { src, .. }
                | MountEntry::ReadOnlyBindTry { src, .. }
                | MountEntry::Bind { src, .. } => Some(src),
                _ => None,
            };
            if let Some(src) = src {
                assert!(!src.starts_with("/home"), "host home must never be mounted");
                assert!(
                    !src.starts_with("/root"),
                    "host root home must never be mounted"
                );
                assert!(!src.starts_with("/var"), "/var must never be mounted");
            }
        }
    }

    #[test]
    fn policy_readonly_paths_are_included() {
        let system = SystemMountSet::default_for_host();
        let mut policy = FilesystemPolicy::default();
        policy.readonly_paths.push(PathBuf::from("/opt/datasets"));
        let isolation = IsolationPolicy::default();
        let plan = build_default_mount_plan(Path::new("/tmp/ws"), &policy, &isolation, &system);
        assert!(plan
            .entries
            .iter()
            .any(|e| matches!(e, MountEntry::ReadOnlyBindTry { src, .. } if src == &PathBuf::from("/opt/datasets"))));
    }

    #[test]
    fn mapper_rejects_unmapped_paths() {
        let system = SystemMountSet::default_for_host();
        let policy = FilesystemPolicy::default();
        let mapper = path_mapper(Path::new("/tmp/ws"), &policy, &system);
        assert!(
            mapper
                .to_sandbox_path(Path::new("/home/user/secret"))
                .is_none()
        );
        assert!(mapper.to_sandbox_path(Path::new("/usr/bin/sh")).is_some());
    }
}
