//! # nsk-resource
//!
//! Resource Controller building blocks (design document §7).
//!
//! * limit conversions (policy values → cgroup / rlimit encodings),
//! * usage accounting (current, peak, limit-crossing detection),
//! * usage sources & sampling,
//! * pure enforcement decisions (usage + limits → exceeded limit kinds).
//!
//! Monitoring never replaces enforcement (§7.4): the decisions here are
//! consumed by the supervisor and providers, which own the actual kill
//! mechanisms.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod accounting;
pub mod enforcement;
pub mod limits;
pub mod monitor;
pub mod usage;

pub use accounting::{UsageAccountant, UsageSnapshotAccumulator};
pub use enforcement::{LimitDecision, evaluate_limit_crossings};
pub use limits::{CgroupLimitFiles, RlimitSpec, cpu_quota_to_cgroup_max, duration_to_cgroup_cpu};
pub use monitor::{UsageSampler, UsageSource};
pub use usage::OutputTracker;
