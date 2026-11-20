//! `inspect` subcommand: parse a stored run result (JSON) and report.
//!
//! The phase-1 CLI is a single-shot process; the sandbox registry lives
//! inside one process. `inspect` therefore reads a result document produced
//! by `run --json > result.json` and renders it (incl. diagnostics).

use std::path::PathBuf;

use nsk_core::result::SandboxResult;

/// Load a result from a JSON file.
pub fn load_result(path: &PathBuf) -> Result<SandboxResult, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("invalid result JSON in {}: {e}", path.display()))
}

/// Render the inspect report.
pub fn inspect(path: &PathBuf) -> Result<i32, String> {
    let result = load_result(path)?;
    crate::report::print_result_summary(&result);
    Ok(crate::run::exit_code_for(result.status))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn roundtrip_result_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        let mut r = nsk_core::result::SandboxResult::new(
            nsk_core::id::SandboxId::new(),
            nsk_core::result::SandboxStatus::Success,
        );
        r.output.stdout.total_bytes = 3;
        std::fs::write(&path, serde_json::to_string(&r).unwrap()).unwrap();
        let loaded = load_result(&path).unwrap();
        assert_eq!(loaded.status, nsk_core::result::SandboxStatus::Success);
        assert_eq!(loaded.output.stdout.total_bytes, 3);
    }

    #[test]
    fn invalid_file_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(load_result(&path).is_err());
    }
}
