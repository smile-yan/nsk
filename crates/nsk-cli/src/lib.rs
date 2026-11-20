//! # nsk-cli
//!
//! Kernel diagnostics & testing CLI (§1.3, Phase 13) — a development tool,
//! **not** the kernel itself.
//!
//! Subcommands (§ Phase 13): `doctor`, `capabilities`, `run`, `inspect`,
//! `cleanup`. Cancellation within `run` maps SIGINT to a sandbox cancel
//! (a long-lived daemon with remote cancel is out of scope in phase 1).
//!
//! Exit codes: `0` sandbox success · `2` program exited non-zero ·
//! `3` limit exceeded · `4` kernel refused / internal error · `130` cancelled.

pub mod capabilities;
pub mod cleanup;
pub mod doctor;
pub mod inspect;
pub mod report;
pub mod run;
