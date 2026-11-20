//! # nsk-workspace
//!
//! Workspace Manager (design document §5.5, Phase 4 / M4).
//!
//! * create kernel-owned ephemeral workspaces,
//! * validate host paths against workspace boundaries (symlink-aware),
//! * idempotent, symlink-safe cleanup,
//! * artifact listing for result reporting,
//! * mount-plan data structures shared with providers.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod artifact;
pub mod cleanup;
pub mod manager;
pub mod mount;
pub mod path;

pub use artifact::{ArtifactInfo, collect_artifacts};
pub use cleanup::{CleanupOutcome, remove_tree_safe};
pub use manager::{PreparedWorkspace, WorkspaceManager, WorkspaceManagerConfig};
pub use mount::{MountEntry, MountPlan};
pub use path::{PathError, PathValidator};
