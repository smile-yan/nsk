//! Platform provider wiring (§9.1 Provider Factory — implemented at the
//! runtime layer per dependency rule §13.2: the runtime composes modules).

use std::sync::Arc;

use nsk_core::capability::Platform;
use nsk_core::error::SandboxError;
use nsk_provider::traits::SandboxProvider;

/// Create the default provider for the current platform.
///
/// * Linux → `LinuxProvider` (bubblewrap + namespaces + cgroups v2)
/// * macOS → `MacOSProvider` (fail-closed stub in phase 1)
/// * Windows → `WindowsProvider` (fail-closed stub in phase 1)
pub fn create_default_provider() -> Result<Arc<dyn SandboxProvider>, SandboxError> {
    provider_for_platform(Platform::current())
}

/// Create the provider for a specific platform (diagnostics & tests).
pub fn provider_for_platform(platform: Platform) -> Result<Arc<dyn SandboxProvider>, SandboxError> {
    match platform {
        Platform::Linux => Ok(Arc::new(nsk_provider_linux::LinuxProvider::new(
            nsk_provider_linux::LinuxProviderConfig::default(),
        ))),
        Platform::MacOS => Ok(Arc::new(nsk_provider_macos::MacOSProvider::new())),
        Platform::Windows => Ok(Arc::new(nsk_provider_windows::WindowsProvider::new())),
        Platform::Unknown => Err(SandboxError::Provider {
            provider: "factory".into(),
            message: "unknown platform: no provider available".into(),
        }),
    }
}

/// Create the mock provider — explicit opt-in only (no isolation).
pub fn create_mock_provider() -> Arc<dyn SandboxProvider> {
    nsk_provider::create_mock_provider()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_provider_matches_platform() {
        let p = create_default_provider().expect("provider");
        match Platform::current() {
            Platform::Linux => assert_eq!(p.name(), "linux"),
            Platform::MacOS => assert_eq!(p.name(), "macos"),
            Platform::Windows => assert_eq!(p.name(), "windows"),
            Platform::Unknown => panic!("unexpected unknown platform"),
        }
    }
}
