//! NSK command line interface (§ Phase 13) — kernel diagnostics & testing
//! tool. Not part of the kernel itself (§1.3).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;

use nsk_provider::traits::SandboxProvider;

mod capabilities;
mod cleanup;
mod doctor;
mod inspect;
mod report;
mod run;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProviderChoice {
    /// Platform default (Linux provider on Linux; fail-closed stubs
    /// elsewhere).
    Platform,
    /// Linux provider explicitly (works only on Linux hosts).
    Linux,
    /// macOS provider stub (always fails closed).
    Macos,
    /// Windows provider stub (always fails closed).
    Windows,
    /// Test provider WITHOUT isolation — explicit opt-in only.
    Mock,
}

#[derive(Parser)]
#[command(
    name = "nsk",
    version,
    about = "NSK · Native Sandbox Kernel — diagnostics & testing CLI",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Probe the host and report usable isolation capabilities.
    Doctor {
        #[arg(long, value_enum, default_value = "platform")]
        provider: ProviderChoice,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Print the capability report (alias of doctor with JSON default).
    Capabilities {
        #[arg(long, value_enum, default_value = "platform")]
        provider: ProviderChoice,
    },
    /// Run a program inside a sandbox (§14.3 execute).
    Run {
        /// Policy profile (§17).
        #[arg(long, value_enum, default_value = "minimal")]
        profile: ProfileChoice,
        /// Wall-time limit in seconds (overrides the profile).
        #[arg(long)]
        wall_time: Option<u64>,
        /// Memory limit in MiB (overrides the profile).
        #[arg(long)]
        memory: Option<u64>,
        /// Max processes (overrides the profile).
        #[arg(long)]
        pids: Option<u32>,
        /// Environment whitelist entries KEY=VALUE (repeatable).
        #[arg(long = "env")]
        env_vars: Vec<String>,
        /// Stdin from file.
        #[arg(long)]
        stdin_file: Option<PathBuf>,
        /// Stdin from a string.
        #[arg(long)]
        stdin_str: Option<String>,
        /// Do not delete the kernel-managed workspace afterwards.
        #[arg(long)]
        keep_workspace: bool,
        #[arg(long, value_enum, default_value = "platform")]
        provider: ProviderChoice,
        /// Relax isolation requirements (required for the mock provider;
        /// the program then runs WITHOUT isolation on the host).
        #[arg(long)]
        no_isolation: bool,
        /// Emit the full result as JSON.
        #[arg(long)]
        json: bool,
        /// The program and its arguments (after `--`).
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Render a stored run result (from `run --json > result.json`).
    Inspect {
        /// Path to the result JSON document.
        #[arg(required = true)]
        result_file: PathBuf,
    },
    /// Find and remove stale kernel-owned workspaces (recovery tooling).
    Cleanup {
        /// Workspace base directory (default: <tmpdir>/nsk-workspaces).
        #[arg(long)]
        base_dir: Option<PathBuf>,
        /// Only report what would be removed.
        #[arg(long)]
        dry_run: bool,
        /// Actually remove stale workspaces.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProfileChoice {
    Minimal,
    Strict,
    Extended,
}

fn make_provider(choice: ProviderChoice) -> Result<Arc<dyn SandboxProvider>, String> {
    match choice {
        ProviderChoice::Platform => {
            nsk_runtime::create_default_provider().map_err(|e| e.to_string())
        }
        ProviderChoice::Linux => Ok(Arc::new(nsk_provider_linux::LinuxProvider::new(
            nsk_provider_linux::LinuxProviderConfig::default(),
        ))),
        ProviderChoice::Macos => Ok(Arc::new(nsk_provider_macos::MacOSProvider::new())),
        ProviderChoice::Windows => Ok(Arc::new(nsk_provider_windows::WindowsProvider::new())),
        ProviderChoice::Mock => Ok(nsk_runtime::create_mock_provider()),
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { provider, json } => {
            let provider = match make_provider(provider) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(4);
                }
            };
            match provider.probe().await {
                Ok(caps) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&caps).unwrap_or_default()
                        );
                    } else {
                        doctor::print_report(&caps, provider.name());
                    }
                }
                Err(e) => {
                    eprintln!("probe failed: {e}");
                    std::process::exit(4);
                }
            }
        }

        Commands::Capabilities { provider } => {
            let provider = match make_provider(provider) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(4);
                }
            };
            match provider.probe().await {
                Ok(caps) => {
                    let rows = capabilities::flatten(&caps);
                    let doc = serde_json::json!({
                        "platform": caps.platform,
                        "provider": provider.name(),
                        "capabilities": rows,
                        "isolated_execution_available": capabilities::isolation_usable(&caps),
                    });
                    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
                }
                Err(e) => {
                    eprintln!("probe failed: {e}");
                    std::process::exit(4);
                }
            }
        }

        Commands::Run {
            profile,
            wall_time,
            memory,
            pids,
            env_vars,
            stdin_file,
            stdin_str,
            keep_workspace,
            provider,
            no_isolation,
            json,
            command,
        } => {
            let provider = match make_provider(provider) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(4);
                }
            };

            if provider.name() == "mock" && !no_isolation {
                eprintln!("refusing: the mock provider provides NO isolation.");
                eprintln!(
                    "pass --no-isolation to acknowledge this for tests, or use a Linux host for real isolation."
                );
                std::process::exit(4);
            }
            if provider.name() == "mock" && no_isolation {
                eprintln!("WARNING: running WITHOUT isolation (mock provider) — for tests only");
            }

            let mut env = Vec::new();
            for var in env_vars {
                if let Some((k, v)) = var.split_once('=') {
                    env.push((k.to_string(), v.to_string()));
                } else {
                    eprintln!("invalid --env entry (want KEY=VALUE): {var}");
                    std::process::exit(4);
                }
            }

            let profile_name = match profile {
                ProfileChoice::Minimal => "minimal",
                ProfileChoice::Strict => "strict",
                ProfileChoice::Extended => "extended",
            };
            let mut spec = match run::build_spec(
                command[0].clone(),
                command[1..].to_vec(),
                profile_name,
                wall_time,
                memory,
                pids,
                stdin_file.map(|p| p.display().to_string()),
                stdin_str,
                keep_workspace,
                env,
            ) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("invalid spec: {e}");
                    std::process::exit(4);
                }
            };
            if no_isolation {
                run::relax_isolation(&mut spec);
            }

            let runtime = match run::build_runtime(provider).await {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("runtime init failed: {e}");
                    std::process::exit(4);
                }
            };

            match run::run(runtime, spec, json).await {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("execution failed: {e}");
                    std::process::exit(4);
                }
            }
        }

        Commands::Inspect { result_file } => match inspect::inspect(&result_file) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(4);
            }
        },

        Commands::Cleanup {
            base_dir,
            dry_run,
            yes,
        } => match cleanup::run_cleanup(base_dir, dry_run, yes) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("cleanup failed: {e}");
                std::process::exit(4);
            }
        },
    }
}
