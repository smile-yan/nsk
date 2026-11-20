//! AppContainer capability detection (§11.5 PoC scope).
//!
//! AppContainer is the Windows mechanism for filesystem/network/resource
//! access isolation. The design document is explicit (§11.5): its isolation
//! boundary **must be confirmed by real security testing** before it may be
//! relied on. This module implements the PoC detection layer only:
//!
//! * is the current process already running inside an AppContainer,
//! * is the caller elevated (creating AppContainer profiles requires
//!   writing the HKLM ProfileList, an administrator operation),
//!
//! and the capability report stays `Unsupported` until the full
//! profile-creation + process-launch machinery passes security validation.
//! That keeps the fail-closed posture intact (§2.4) while honestly
//! recording what was verified.

use nsk_core::error::SandboxError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppContainerFacts {
    /// The current process runs inside an AppContainer.
    pub in_appcontainer: bool,
    /// The caller token is elevated (admin) — a *precondition* for creating
    /// profiles, not a capability claim.
    pub caller_elevated: bool,
}

/// Query the AppContainer facts of the current process.
///
/// # Errors
/// Win32 token query failures (surfaced honestly, never defaulted).
pub fn detect() -> Result<AppContainerFacts, SandboxError> {
    let in_appcontainer = is_current_process_in_appcontainer()?;
    let caller_elevated = crate::token::RestrictedToken::caller_is_elevated()?;
    Ok(AppContainerFacts {
        in_appcontainer,
        caller_elevated,
    })
}

/// `GetTokenInformation(TokenIsAppContainer)` for the process token.
fn is_current_process_in_appcontainer() -> Result<bool, SandboxError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: single u32 query on the process token; handle closed on all
    // paths.
    unsafe {
        const TOKEN_IS_APP_CONTAINER: i32 = 29;
        let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let rc = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
        if rc == 0 {
            return Err(SandboxError::Isolation(format!(
                "OpenProcessToken failed: {}",
                crate::token::last_error()
            )));
        }
        let mut value: u32 = 0;
        let mut ret_len = 0u32;
        let rc = GetTokenInformation(
            token,
            TOKEN_IS_APP_CONTAINER,
            &mut value as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        if rc == 0 {
            return Err(SandboxError::Isolation(format!(
                "GetTokenInformation(TokenIsAppContainer) failed: {}",
                crate::token::last_error()
            )));
        }
        Ok(value != 0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn detection_succeeds_and_is_specific() {
        if !cfg!(windows) {
            return;
        }
        let facts = detect().expect("detection must not fail on a healthy host");
        // CI runners are not AppContainers.
        assert!(!facts.in_appcontainer);
        // The fact must be reproducible.
        let again = detect().expect("detection is deterministic");
        assert_eq!(facts, again);
    }
}
