//! Mount plan model shared with providers (design document §10.5).
//!
//! The plan is a *declaration* of what will be mounted where. The Linux
//! provider turns it into bubblewrap arguments; validation of source paths
//! (existence, symlink policy) happens in `nsk-workspace` before the plan is
//! built, so a plan is safe to serialize and audit.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One planned mount operation inside the sandbox root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum MountEntry {
    /// Bind a host path read-only.
    ReadOnlyBind { src: PathBuf, dest: PathBuf },
    /// Bind a host path read-only when it exists (optional system file).
    ReadOnlyBindTry { src: PathBuf, dest: PathBuf },
    /// Bind a host path read-write.
    Bind { src: PathBuf, dest: PathBuf },
    /// Fresh writable tmpfs (contents die with the sandbox).
    Tmpfs { dest: PathBuf },
    /// Fresh /proc inside the sandbox.
    Proc { dest: PathBuf },
    /// Fresh minimal /dev inside the sandbox.
    Dev { dest: PathBuf },
    /// Create a symlink inside the sandbox root.
    Symlink { target: String, dest: PathBuf },
}

/// Ordered mount plan for one sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountPlan {
    pub entries: Vec<MountEntry>,
}

impl MountPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entry: MountEntry) {
        self.entries.push(entry);
    }

    /// Count entries by kind, for reports.
    pub fn summary(&self) -> String {
        let ro = self
            .entries
            .iter()
            .filter(|e| matches!(e, MountEntry::ReadOnlyBind { .. }))
            .count();
        let rw = self
            .entries
            .iter()
            .filter(|e| matches!(e, MountEntry::Bind { .. }))
            .count();
        let tmp = self
            .entries
            .iter()
            .filter(|e| matches!(e, MountEntry::Tmpfs { .. }))
            .count();
        format!(
            "{ro} ro-binds, {rw} binds, {tmp} tmpfs, {} other",
            self.entries.len() - ro - rw - tmp
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_builds_and_summarizes() {
        let mut plan = MountPlan::new();
        plan.push(MountEntry::ReadOnlyBind {
            src: PathBuf::from("/usr"),
            dest: PathBuf::from("/usr"),
        });
        plan.push(MountEntry::Bind {
            src: PathBuf::from("/tmp/ws"),
            dest: PathBuf::from("/workspace"),
        });
        plan.push(MountEntry::Tmpfs {
            dest: PathBuf::from("/tmp"),
        });
        plan.push(MountEntry::Proc {
            dest: PathBuf::from("/proc"),
        });
        plan.push(MountEntry::Dev {
            dest: PathBuf::from("/dev"),
        });
        plan.push(MountEntry::Symlink {
            target: "usr/bin".into(),
            dest: PathBuf::from("/bin"),
        });

        assert_eq!(plan.entries.len(), 6);
        assert!(plan.summary().contains("1 ro-binds"));
        assert!(plan.summary().contains("1 binds"));
        assert!(plan.summary().contains("1 tmpfs"));
    }

    #[test]
    fn plan_is_serializable() {
        let mut plan = MountPlan::new();
        plan.push(MountEntry::Tmpfs {
            dest: PathBuf::from("/tmp"),
        });
        let json = serde_json::to_string(&plan).unwrap();
        let back: MountPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
    }
}
