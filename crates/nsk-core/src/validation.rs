//! Cross-cutting validation helpers and policy bound constants.

use std::time::Duration;

/// Environment variable keys must match `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_ENV_KEY_LEN {
        return false;
    }
    let mut chars = key.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Returns true when the byte slice contains a NUL byte.
pub fn contains_nul(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Maximum length of an environment variable key.
pub const MAX_ENV_KEY_LEN: usize = 256;
/// Maximum length of a single environment variable value.
pub const MAX_ENV_VALUE_LEN: usize = 16 * 1024;
/// Maximum number of explicitly whitelisted environment variables.
pub const MAX_ENV_COUNT: usize = 128;
/// Maximum number of command arguments.
pub const MAX_ARGS: usize = 4096;
/// Maximum length of a single argument.
pub const MAX_ARG_LEN: usize = 64 * 1024;

// ---- policy bound constants -------------------------------------------------

pub const MIN_WALL_TIME: Duration = Duration::from_millis(100);
pub const MAX_WALL_TIME: Duration = Duration::from_secs(3600);
pub const MIN_MEMORY_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB
pub const MIN_PROCESSES: u32 = 1;
pub const MAX_PROCESSES: u32 = 65536;
pub const MIN_OPEN_FILES: u64 = 3;
pub const MAX_OPEN_FILES: u64 = 1 << 20;
pub const MIN_FILE_SIZE_BYTES: u64 = 1024;
pub const MAX_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MIN_DISK_BYTES: u64 = 1024 * 1024;
pub const MAX_DISK_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const MIN_OUTPUT_BYTES: u64 = 1024;
pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
/// CPU quota range, in cores.
pub const MIN_CPU_CORES: f64 = 0.05;
pub const MAX_CPU_CORES: f64 = 1024.0;
/// Maximum number of paths accepted in one filesystem policy.
pub const MAX_POLICY_PATHS: usize = 1024;

/// Check a wall-time limit against policy bounds.
pub fn check_wall_time(d: Duration) -> Result<(), &'static str> {
    if d < MIN_WALL_TIME {
        return Err("wall time below minimum (100ms)");
    }
    if d > MAX_WALL_TIME {
        return Err("wall time above maximum (1h)");
    }
    Ok(())
}

/// Check a memory limit against policy bounds.
pub fn check_memory(bytes: u64) -> Result<(), &'static str> {
    if bytes < MIN_MEMORY_BYTES {
        return Err("memory limit below minimum (1 MiB)");
    }
    if bytes > MAX_MEMORY_BYTES {
        return Err("memory limit above maximum (64 GiB)");
    }
    Ok(())
}

/// Check a CPU quota against policy bounds.
pub fn check_cpu_quota(cores: f64) -> Result<(), &'static str> {
    if !cores.is_finite() || !(MIN_CPU_CORES..=MAX_CPU_CORES).contains(&cores) {
        return Err("cpu quota out of range (0.05 ..= 1024 cores)");
    }
    Ok(())
}

/// Check an output limit against policy bounds.
pub fn check_output_limit(bytes: u64) -> Result<(), &'static str> {
    if bytes < MIN_OUTPUT_BYTES {
        return Err("output limit below minimum (1 KiB)");
    }
    if bytes > MAX_OUTPUT_BYTES {
        return Err("output limit above maximum (1 GiB)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_key_charset() {
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("_A1"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("1ABC"));
        assert!(!is_valid_env_key("A-B"));
        assert!(!is_valid_env_key("A B"));
        assert!(!is_valid_env_key(&"x".repeat(MAX_ENV_KEY_LEN + 1)));
    }

    #[test]
    fn nul_detection() {
        assert!(contains_nul(b"abc\0"));
        assert!(!contains_nul(b"abc"));
    }

    #[test]
    fn bound_checks() {
        assert!(check_wall_time(Duration::from_secs(5)).is_ok());
        assert!(check_wall_time(Duration::from_millis(10)).is_err());
        assert!(check_wall_time(Duration::from_secs(7200)).is_err());
        assert!(check_memory(MIN_MEMORY_BYTES).is_ok());
        assert!(check_memory(1024).is_err());
        assert!(check_cpu_quota(1.0).is_ok());
        assert!(check_cpu_quota(0.0).is_err());
        assert!(check_cpu_quota(f64::NAN).is_err());
        assert!(check_output_limit(8 * 1024 * 1024).is_ok());
        assert!(check_output_limit(100).is_err());
    }
}
