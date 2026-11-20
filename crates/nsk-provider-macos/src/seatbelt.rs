//! Seatbelt (SBPL) profile generation for the macOS provider (§12).
//!
//! `sandbox-exec` profiles are **deny-by-default**: every operation not
//! explicitly allowed is denied. The provider therefore generates strict
//! allow-list profiles — this is the security posture, not an optional
//! hardening:
//!
//! * file reads are allowed globally (dynamic loader, frameworks, inputs),
//! * file writes are allowed only to the workspace (canonical), the
//!   policy's `writable_paths` and `/dev/null`,
//! * network access follows the requested [`NetworkPolicy`],
//! * process execution/fork and sysctl reads are allowed (required to run
//!   any dynamically linked binary),
//! * setuid/setgid exec is denied by the default-deny posture — the
//!   mechanism that makes `no_new_privileges` satisfiable on macOS.
//!
//! What the profile deliberately does **not** provide (documented limits,
//! see `docs/macos-provider.md`): host-path hiding (`deny_host_paths`),
//! root remapping (`isolate_root`), and per-binary read restrictions.

use nsk_core::policy::NetworkPolicy;

/// A generated profile plus what it actually enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatbeltProfile {
    /// Full SBPL source, suitable for `sandbox-exec -p`.
    pub source: String,
    /// Filesystem writes restricted to this set (canonical paths).
    pub write_allowlist: Vec<String>,
}

/// Quote a string as an SBPL literal (paths and filters are double-quoted).
fn sbpl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Build the profile for one sandbox.
///
/// * `workspace_root` — canonical workspace path (write-allowed).
/// * `writable_paths` — additional canonical write-allowed paths.
/// * `network` — requested network policy.
pub fn build_profile(
    workspace_root: &std::path::Path,
    writable_paths: &[std::path::PathBuf],
    network: NetworkPolicy,
) -> SeatbeltProfile {
    let mut source = String::from("(version 1)\n");

    // Reads are global: dyld, frameworks and inputs are outside our control
    // on macOS (documented limitation — no host-path hiding).
    source.push_str("(allow file-read*)\n");

    // Write allow-list: workspace (canonical) + policy paths + /dev/null.
    let mut writes = vec![workspace_root.display().to_string()];
    for p in writable_paths {
        writes.push(p.display().to_string());
    }
    let allow_list = writes
        .iter()
        .map(|p| format!("(subpath {})", sbpl_quote(p)))
        .collect::<Vec<_>>()
        .join(" ");
    source.push_str(&format!("(allow file-write* {allow_list})\n"));
    source.push_str("(allow file-write* (literal \"/dev/null\"))\n");

    // Run any dynamically linked program.
    source.push_str("(allow process-exec*)\n");
    source.push_str("(allow process-fork)\n");
    source.push_str("(allow sysctl-read)\n");

    // Network: deny-by-default already blocks everything; add explicit rules
    // only where the policy grants access.
    match network {
        NetworkPolicy::Disabled => {
            // Explicit deny documents intent (and blocks profile-extension
            // paths that could re-enable sockets).
            source.push_str("(deny network*)\n");
        }
        NetworkPolicy::LoopbackOnly => {
            source.push_str("(deny network-outbound)\n");
            source.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
            source.push_str("(deny network-inbound)\n");
            source.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
            source.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
        }
        NetworkPolicy::AllowAll => {
            source.push_str("(allow network*)\n");
        }
        // Restricted is rejected by validation (§6.3); defensive record only.
        NetworkPolicy::Restricted => {
            source.push_str("(deny network*)\n");
        }
    }

    SeatbeltProfile {
        source,
        write_allowlist: writes,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn base_profile_is_deny_by_default() {
        let p = build_profile(
            &PathBuf::from("/private/tmp/ws"),
            &[],
            NetworkPolicy::Disabled,
        );
        // No `allow default` — the whole posture depends on this.
        assert!(!p.source.contains("allow default"));
        assert!(p.source.starts_with("(version 1)\n"));
        for required in [
            "(allow file-read*)",
            "(allow process-exec*)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(deny network*)",
        ] {
            assert!(p.source.contains(required), "missing: {required}");
        }
        assert!(p.source.contains("(subpath \"/private/tmp/ws\")"));
        assert!(p.source.contains("(literal \"/dev/null\")"));
    }

    #[test]
    fn writable_paths_are_included() {
        let p = build_profile(
            &PathBuf::from("/private/tmp/ws"),
            &[PathBuf::from("/private/tmp/extra")],
            NetworkPolicy::Disabled,
        );
        assert!(p.source.contains("(subpath \"/private/tmp/extra\")"));
        assert_eq!(p.write_allowlist.len(), 2);
    }

    #[test]
    fn loopback_profile_allows_only_localhost() {
        let p = build_profile(&PathBuf::from("/ws"), &[], NetworkPolicy::LoopbackOnly);
        assert!(p.source.contains("(deny network-outbound)"));
        assert!(
            p.source
                .contains("(allow network-outbound (remote ip \"localhost:*\"))")
        );
        assert!(p.source.contains("(deny network-inbound)"));
        assert!(
            p.source
                .contains("(allow network-bind (local ip \"localhost:*\"))")
        );
        assert!(!p.source.contains("(allow network*)"));
    }

    #[test]
    fn allowall_profile_permits_network() {
        let p = build_profile(&PathBuf::from("/ws"), &[], NetworkPolicy::AllowAll);
        assert!(p.source.contains("(allow network*)"));
        assert!(!p.source.contains("(deny network"));
    }

    #[test]
    fn paths_with_quotes_are_escaped() {
        let p = build_profile(
            &PathBuf::from("/tmp/we\"ird\\path"),
            &[],
            NetworkPolicy::Disabled,
        );
        assert!(p.source.contains("we\\\"ird\\\\path"));
    }
}
