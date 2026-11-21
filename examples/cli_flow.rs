//! Example: the CLI's exact code path, called from Rust (§ Phase 13).
//!
//! Run with: `cargo run -p nsk-examples --example cli_flow`
//!
//! The `nsk` CLI is a thin wrapper over the kernel API, and its pieces are
//! a library (`nsk-cli` has a lib target). This example walks the same
//! path in-process, mirroring three subcommands — each step shows the
//! equivalent shell command:
//!
//! * `nsk doctor` — capability table (`cargo run -p nsk-cli -- doctor`);
//! * `nsk run --profile strict --relax-unsupported --json -- …`
//!   — build the spec, relax unsupported domains, execute, and emit the
//!   result JSON document that `--json` prints;
//! * `nsk inspect result.json` — re-read a stored result document.

use std::path::PathBuf;

use nsk_cli::doctor::print_report;
use nsk_cli::inspect::inspect;
use nsk_cli::run::{build_runtime, build_spec, exit_code_for, relax_unsupported_domains};
use nsk_runtime::create_default_provider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Step 1: `nsk doctor` ────────────────────────────────────────────
    let provider = create_default_provider()?;
    let caps = provider.probe().await?;
    println!("$ nsk doctor");
    let usable = print_report(&caps, provider.name());
    println!("→ isolated execution usable: {usable}\n");

    // ── Step 2: `nsk run --profile strict --relax-unsupported --json -- …` ──
    // build_spec() mirrors the option overrides: --wall-time 10 here.
    let mut spec = build_spec(
        "/bin/sh".to_string(),
        vec!["-c".to_string(), "echo cli-flow demo; pwd".to_string()],
        "strict",
        Some(10),
        None, // --memory
        None, // --pids
        None, // --stdin-file
        None, // --stdin-str
        false,
        vec![], // --env KEY=VALUE
    )?;

    let dropped = relax_unsupported_domains(&mut spec, &caps);
    if dropped.is_empty() {
        println!("$ nsk run --profile strict --relax-unsupported --json -- /bin/sh -c '…'");
        println!("--relax-unsupported: nothing to relax");
    } else {
        println!(
            "WARNING: --relax-unsupported dropped unavailable domains: {}",
            dropped.join(", ")
        );
    }

    let runtime = build_runtime(provider).await?;
    let result = runtime.execute(spec).await?;
    println!(
        "→ process exit code that `nsk run` would return: {} ({:?})\n",
        exit_code_for(result.status),
        result.status
    );

    // The document `--json` prints to stdout; store it in a temp file to
    // feed step 3 (`nsk run --json … > result.json`).
    let json = serde_json::to_string_pretty(&*result)?;

    // ── Step 3: `nsk inspect result.json` ───────────────────────────────
    let dir = tempfile::tempdir()?;
    let path = PathBuf::from(dir.path()).join("result.json");
    std::fs::write(&path, json)?;

    println!("$ nsk inspect {}", path.display());
    let code = inspect(&path)?;
    println!("→ inspect exit code: {code}");
    println!("→ the tempdir cleans itself up when `dir` drops");

    Ok(())
}
