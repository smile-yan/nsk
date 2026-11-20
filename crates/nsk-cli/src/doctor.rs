//! Human-readable capability report rendering (`doctor`).

use std::sync::Arc;

use nsk_core::capability::PlatformCapabilities;
use nsk_provider::traits::SandboxProvider;

use crate::capabilities::{flatten, isolation_usable};

/// Probe a provider and return the capability report.
#[allow(dead_code)] // used by tests and future subcommand wiring
pub async fn doctor_report(
    provider: &Arc<dyn SandboxProvider>,
) -> Result<PlatformCapabilities, nsk_core::error::SandboxError> {
    provider.probe().await
}

/// Print the report; returns a health verdict for the exit code.
pub fn print_report(caps: &PlatformCapabilities, provider_name: &str) -> bool {
    println!("NSK doctor — provider: {provider_name}");
    println!("platform: {:?}", caps.platform);
    println!();
    println!("Capability                    Status            Detail");
    println!("-----------------------------------------------------------");
    for row in flatten(caps) {
        println!(
            "{:<28} {:<16} {}",
            row.name,
            row.status,
            row.detail.as_deref().unwrap_or("-")
        );
    }
    println!();
    if !caps.diagnostics.is_empty() {
        println!("Diagnostics:");
        for d in &caps.diagnostics {
            println!(
                "  [{severity:?}] {code}: {message}",
                severity = d.severity,
                code = d.code,
                message = d.message
            );
            if let Some(details) = &d.details {
                println!("      {details}");
            }
        }
        println!();
    }
    let usable = isolation_usable(caps);
    if usable {
        println!("verdict: isolated execution available on this host");
    } else {
        println!("verdict: isolated execution NOT available");
        println!("  - isolated policies will be refused (fail-closed, §2.4)");
        println!("  - use the `mock` provider explicitly for tests (NO isolation)");
        println!("  - or run on a Linux host with bubblewrap installed");
    }
    usable
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn mock_report_is_negative_verdict() {
        let provider = nsk_provider::create_mock_provider();
        let caps = doctor_report(&provider).await.unwrap();
        assert!(!print_report(&caps, provider.name()));
    }

    #[tokio::test]
    async fn linux_provider_report_succeeds_even_off_linux() {
        // The Linux probe is honest on every host; on macOS it reports
        // missing bwrap rather than pretending.
        let provider: Arc<dyn SandboxProvider> = Arc::new(nsk_provider_linux::LinuxProvider::new(
            nsk_provider_linux::LinuxProviderConfig::default(),
        ));
        let caps = doctor_report(&provider).await.unwrap();
        // Verdict must match actual availability (false on non-Linux dev
        // hosts without bwrap; true on a provisioned Linux CI host).
        let verdict = print_report(&caps, provider.name());
        assert_eq!(verdict, caps.isolation.launcher.status.is_available());
    }
}
