//! Restricted Token machinery (§11.4) — Windows implementation.
//!
//! This module proves and exercises the token machinery: duplicating the
//! caller's primary token and deriving a restricted token with
//! `DISABLE_MAX_PRIVILEGE` (every privilege disabled/removed). This is the
//! foundation for reduced-privilege process creation.
//!
//! MVP boundary (honest reporting, §2.6): creating a process *with* the
//! restricted token (`CreateProcessAsUserW` + custom pipe plumbing) is not
//! wired into the supervisor-driven spawn path in the PoC; the capability
//! report therefore records `privilege_dropping: NotConfigured` with a
//! diagnostic rather than claiming a privilege reduction that does not
//! happen. Spawn integration is documented in `docs/windows-provider.md`.

use nsk_core::error::SandboxError;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetTokenInformation,
    SecurityAnonymous, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenPrimary, TokenPrivileges,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// TokenElevation information class (i32 per the GetTokenInformation ABI).
const TOKEN_INFO_ELEVATION: i32 = 20;

/// A restricted primary token derived from the caller's process token.
#[derive(Debug)]
pub struct RestrictedToken {
    handle: HANDLE,
}

// SAFETY: token handles are usable from other threads.
unsafe impl Send for RestrictedToken {}
unsafe impl Sync for RestrictedToken {}

impl RestrictedToken {
    /// Derive a restricted primary token with all privileges disabled from
    /// the current process token.
    ///
    /// `CreateRestrictedToken` requires no special privilege, so this
    /// works for ordinary user processes (probed/verified, not assumed).
    pub fn from_current_process() -> Result<Self, SandboxError> {
        // SAFETY: standard token query/duplicate protocol; every handle is
        // closed on all error paths and the final handle is owned by the
        // returned struct (closed in Drop).
        unsafe {
            let mut current: HANDLE = std::ptr::null_mut();
            let rc = OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut current,
            );
            if rc == 0 {
                return Err(SandboxError::Isolation(format!(
                    "OpenProcessToken failed: {}",
                    last_error()
                )));
            }

            let mut duplicated: HANDLE = std::ptr::null_mut();
            let rc = DuplicateTokenEx(
                current,
                TOKEN_QUERY | TOKEN_DUPLICATE,
                std::ptr::null_mut(),
                SecurityAnonymous,
                TokenPrimary,
                &mut duplicated,
            );
            CloseHandle(current);
            if rc == 0 {
                return Err(SandboxError::Isolation(format!(
                    "DuplicateTokenEx failed: {}",
                    last_error()
                )));
            }

            let mut restricted: HANDLE = std::ptr::null_mut();
            let rc = CreateRestrictedToken(
                duplicated,
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut restricted,
            );
            CloseHandle(duplicated);
            if rc == 0 {
                return Err(SandboxError::Isolation(format!(
                    "CreateRestrictedToken failed: {}",
                    last_error()
                )));
            }
            Ok(Self { handle: restricted })
        }
    }

    /// Count of privileges still enabled in the token (must be 0 after
    /// `DISABLE_MAX_PRIVILEGE`).
    pub fn enabled_privileges(&self) -> Result<usize, SandboxError> {
        // SAFETY: query protocol with a grow-once buffer; the returned
        // buffer is read before being freed.
        unsafe {
            let mut len = 0u32;
            let _ = GetTokenInformation(
                self.handle,
                TokenPrivileges,
                std::ptr::null_mut(),
                0,
                &mut len,
            );
            let mut buf = vec![0u8; len as usize];
            let rc = GetTokenInformation(
                self.handle,
                TokenPrivileges,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                len,
                &mut len,
            );
            if rc == 0 {
                return Err(SandboxError::Isolation(format!(
                    "GetTokenInformation(TokenPrivileges) failed: {}",
                    last_error()
                )));
            }
            let privileges = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
            let count = privileges.PrivilegeCount as usize;
            let entries = std::slice::from_raw_parts(privileges.Privileges.as_ptr(), count);
            Ok(entries
                .iter()
                .filter(|p| (p.Attributes & 2) != 0) // SE_PRIVILEGE_ENABLED
                .count())
        }
    }

    /// Is the *caller* running elevated? (Informative for diagnostics; a
    /// restricted token does not de-elevate, it disables privileges.)
    pub fn caller_is_elevated() -> Result<bool, SandboxError> {
        // SAFETY: single u32 query on the process token.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            let rc = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
            if rc == 0 {
                return Err(SandboxError::Isolation(format!(
                    "OpenProcessToken failed: {}",
                    last_error()
                )));
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            let rc = GetTokenInformation(
                token,
                TOKEN_INFO_ELEVATION,
                &mut elevation as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            if rc == 0 {
                return Err(SandboxError::Isolation(format!(
                    "GetTokenInformation(TokenElevation) failed: {}",
                    last_error()
                )));
            }
            Ok(elevation.TokenIsElevated != 0)
        }
    }

    /// Raw handle (for future `CreateProcessAsUserW` integration).
    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for RestrictedToken {
    fn drop(&mut self) {
        // SAFETY: the handle is owned exclusively by this struct.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Last Win32 error code (thread-local).
pub fn last_error() -> u32 {
    // SAFETY: GetLastError is thread-local and always safe.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn restricted_token_disables_all_privileges() {
        if !cfg!(windows) {
            return;
        }
        let token = RestrictedToken::from_current_process().expect("token machinery");
        assert_eq!(
            token.enabled_privileges().expect("privilege query"),
            0,
            "DISABLE_MAX_PRIVILEGE must leave no enabled privileges"
        );
    }

    #[test]
    fn elevation_query_works() {
        if !cfg!(windows) {
            return;
        }
        let _ = RestrictedToken::caller_is_elevated().expect("elevation query");
    }
}
