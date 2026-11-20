//! bubblewrap argument builder (§10.4, §10.5).
//!
//! **bwrap arguments are generated exclusively from structured policy** —
//! callers can never pass arbitrary flags (§10.4 prohibition).
//!
//! Layout inside the sandbox (§10.5):
//!
//! ```text
//! /            fresh root (no host root)
//! /usr         read-only bind (host)
//! /bin,/lib…   symlinks into /usr (merged-usr) or ro-binds
//! /etc         minimal read-only pieces (ld.so.cache, localtime)
//! /dev         fresh minimal dev tmpfs
//! /proc        fresh procfs
//! /tmp         fresh writable tmpfs
//! /workspace   the sandbox workspace (writable)
//! ```
//!
//! The host home directory, credentials, sockets, devices and any unlisted
//! host path are never mounted (§10.5 threat list).

use std::path::{Path, PathBuf};

use nsk_workspace::mount::{MountEntry, MountPlan};

/// Everything bwrap needs beyond the mount plan.
#[derive(Debug, Clone, Default)]
pub struct BwrapOptions {
    /// `--unshare-all` (pid, net, ipc, uts, user, cgroup).
    pub unshare_all: bool,
    /// die-with-parent + new-session (lifecycle hygiene).
    pub session_hygiene: bool,
    /// seccomp filter fd number (None = no filter).
    pub seccomp_fd: Option<i32>,
    /// Environment whitelist (already merged with sandbox defaults).
    pub env: Vec<(String, String)>,
    /// Working directory *inside* the sandbox.
    pub chdir: PathBuf,
}

/// Build the bwrap argv prefix for a mount plan (program path excluded).
///
/// Returns the argv up to (but not including) the `--` separator; the caller
/// appends `--` and the sandbox command.
pub fn build_bwrap_args(plan: &MountPlan, options: &BwrapOptions) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    if options.session_hygiene {
        args.push("--die-with-parent".into());
        args.push("--new-session".into());
    }
    if options.unshare_all {
        args.push("--unshare-all".into());
    }

    for entry in &plan.entries {
        match entry {
            MountEntry::ReadOnlyBind { src, dest } => {
                args.push("--ro-bind".into());
                args.push(src.display().to_string());
                args.push(dest.display().to_string());
            }
            MountEntry::ReadOnlyBindTry { src, dest } => {
                args.push("--ro-bind-try".into());
                args.push(src.display().to_string());
                args.push(dest.display().to_string());
            }
            MountEntry::Bind { src, dest } => {
                args.push("--bind".into());
                args.push(src.display().to_string());
                args.push(dest.display().to_string());
            }
            MountEntry::Tmpfs { dest } => {
                args.push("--tmpfs".into());
                args.push(dest.display().to_string());
            }
            MountEntry::Proc { dest } => {
                args.push("--proc".into());
                args.push(dest.display().to_string());
            }
            MountEntry::Dev { dest } => {
                args.push("--dev".into());
                args.push(dest.display().to_string());
            }
            MountEntry::Symlink { target, dest } => {
                args.push("--symlink".into());
                args.push(target.clone());
                args.push(dest.display().to_string());
            }
        }
    }

    // Environment: clear everything, then set the whitelist.
    args.push("--clearenv".into());
    for (k, v) in &options.env {
        args.push("--setenv".into());
        args.push(k.clone());
        args.push(v.clone());
    }

    args.push("--chdir".into());
    args.push(options.chdir.display().to_string());

    if let Some(fd) = options.seccomp_fd {
        args.push("--seccomp-fd".into());
        args.push(fd.to_string());
    }

    args.push("--".into());
    args
}

/// Path mapper: host paths ↔ sandbox paths (§10.5 mount semantics).
#[derive(Debug, Clone)]
pub struct SandboxPathMapper {
    /// Workspace root on the host.
    pub workspace_host_root: PathBuf,
    /// Workspace root inside the sandbox.
    pub workspace_sandbox_root: PathBuf,
    /// Extra host→sandbox prefix mappings from readonly binds.
    pub host_prefixes: Vec<PathBuf>,
}

impl SandboxPathMapper {
    /// Map a host path to its sandbox location.
    ///
    /// Returns `None` when the path is not reachable from inside the
    /// sandbox (which the Policy Engine treats as a policy violation).
    pub fn to_sandbox_path(&self, host: &Path) -> Option<PathBuf> {
        if let Ok(rel) = host.strip_prefix(&self.workspace_host_root) {
            return Some(self.workspace_sandbox_root.join(rel));
        }
        for prefix in &self.host_prefixes {
            if let Ok(rel) = host.strip_prefix(prefix) {
                return Some(prefix.join(rel));
            }
        }
        // System roots are mounted 1:1 (/usr → /usr etc.).
        if self.host_prefixes.iter().any(|p| p == host) {
            return Some(host.to_path_buf());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> MountPlan {
        let mut plan = MountPlan::new();
        plan.push(MountEntry::ReadOnlyBind {
            src: "/usr".into(),
            dest: "/usr".into(),
        });
        plan.push(MountEntry::ReadOnlyBindTry {
            src: "/etc/ld.so.cache".into(),
            dest: "/etc/ld.so.cache".into(),
        });
        plan.push(MountEntry::Symlink {
            target: "usr/bin".into(),
            dest: "/bin".into(),
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
        plan.push(MountEntry::Bind {
            src: "/tmp/ws".into(),
            dest: "/workspace".into(),
        });
        plan
    }

    #[test]
    fn argv_contains_expected_flags() {
        let opts = BwrapOptions {
            unshare_all: true,
            session_hygiene: true,
            seccomp_fd: Some(9),
            env: vec![("PATH".into(), "/usr/bin".into())],
            chdir: "/workspace".into(),
        };
        let args = build_bwrap_args(&sample_plan(), &opts);
        let s = args.join(" ");
        assert!(s.contains("--unshare-all"));
        assert!(s.contains("--die-with-parent"));
        assert!(s.contains("--new-session"));
        assert!(s.contains("--ro-bind /usr /usr"));
        assert!(s.contains("--ro-bind-try /etc/ld.so.cache"));
        assert!(s.contains("--symlink usr/bin /bin"));
        assert!(s.contains("--proc /proc"));
        assert!(s.contains("--dev /dev"));
        assert!(s.contains("--tmpfs /tmp"));
        assert!(s.contains("--bind /tmp/ws /workspace"));
        assert!(s.contains("--clearenv"));
        assert!(s.contains("--setenv PATH /usr/bin"));
        assert!(s.contains("--chdir /workspace"));
        assert!(s.contains("--seccomp-fd 9"));
        assert!(args.last().expect("argv ends with --") == "--");
    }

    #[test]
    fn host_paths_never_appear_by_accident() {
        // Only sources explicitly in the plan may appear; a stray host path
        // in options must not leak into argv.
        let opts = BwrapOptions {
            chdir: "/workspace".into(),
            ..Default::default()
        };
        let args = build_bwrap_args(&MountPlan::new(), &opts);
        assert!(!args.iter().any(|a| a.contains("/home/")));
    }

    #[test]
    fn path_mapper_workspace() {
        let mapper = SandboxPathMapper {
            workspace_host_root: "/tmp/ws".into(),
            workspace_sandbox_root: "/workspace".into(),
            host_prefixes: vec!["/usr".into()],
        };
        assert_eq!(
            mapper.to_sandbox_path(Path::new("/tmp/ws/out/build.log")),
            Some(PathBuf::from("/workspace/out/build.log"))
        );
        assert_eq!(
            mapper.to_sandbox_path(Path::new("/usr/bin/sh")),
            Some(PathBuf::from("/usr/bin/sh"))
        );
        assert_eq!(mapper.to_sandbox_path(Path::new("/home/user/x")), None);
    }
}
