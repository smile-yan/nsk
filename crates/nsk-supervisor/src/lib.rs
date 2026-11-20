//! # nsk-supervisor
//!
//! Supervisor of sandbox execution units (design document §8).
//!
//! Responsibilities: process spawn, stdin/stdout/stderr handling, bounded
//! output collection, wall-time deadlines, cancellation, resource-limit
//! triggered termination, process-tree termination and exit collection.
//!
//! The supervisor is provider-agnostic: providers hand it an
//! [`process::ProcessSpec`] (which may be a bubblewrap command line) and get
//! back a [`process::SupervisedProcess`] handle.
//!
//! Process-tree termination strategy (§8.4): on Unix the child runs as a
//! process-group leader and the whole group receives SIGTERM → (grace) →
//! SIGKILL. Providers with stronger mechanisms (cgroups) perform their own
//! group kill first and use this as a fallback.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod monitor;
pub mod output;
pub mod process;
pub mod stdin;
pub mod terminate;
pub mod timer;

/// Reactive enforcement watchdogs (§7.2 monitor + §7.4 evidence) for
/// platforms without preventive per-tree mechanisms (macOS PoC).
#[cfg(target_os = "macos")]
pub mod watchdog;

pub use monitor::{OutcomeReason, SupervisorConfig, SupervisorEvent};
pub use output::{LimitCrossing, OutputBuffer, OutputSnapshot, OutputStream};
pub use process::{ProcessSpec, SupervisedProcess};
pub use terminate::TerminateKind;
pub use timer::Deadline;
