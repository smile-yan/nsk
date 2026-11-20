//! # nsk-provider-linux
//!
//! Linux Provider — the phase-1 reference implementation (design document
//! §10).
//!
//! Isolation stack: bubblewrap launcher + namespaces (`--unshare-all`),
//! cgroups v2 resource control, optional seccomp allowlist, minimal
//! filesystem via bind mounts, no network (`NetworkPolicy::Disabled`).
//!
//! The crate compiles on any host (pure file operations + process launch)
//! but is only functional on Linux; the capability probe reports honestly
//! everywhere (§2.6 Explicit Capabilities).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod bwrap;
pub mod cgroup;
pub mod cleanup;
pub mod mount;
pub mod probe;
pub mod provider;
pub mod seccomp;

pub use bwrap::{BwrapOptions, SandboxPathMapper, build_bwrap_args};
pub use cgroup::{CgroupManager, ControllersState};
pub use mount::{SystemMountSet, build_default_mount_plan};
pub use probe::{linux_capabilities, probe_with_config};
pub use provider::{LinuxProvider, LinuxProviderConfig, SeccompChoice};
pub use seccomp::{SECCOMP_AUX_FD, SeccompArch, SeccompProfile};
