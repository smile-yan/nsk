//! Sandbox specification types (design document §5.2–§5.5).
//!
//! A [`SandboxSpec`] fully describes one sandbox execution request. Commands
//! always use executable-path + argument-vector form; shell interpretation of
//! user input is never implied (§5.3).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::diagnostic::{Diagnostic, codes};
use crate::error::SandboxError;
use crate::id::SandboxId;
use crate::policy::SandboxPolicy;
use crate::validation;

/// Standard input configuration for the executed program.
///
/// The first phase has no interactive terminal (PTY) support (§5.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdinSpec {
    /// No stdin is provided; the child's stdin is closed immediately.
    #[default]
    Closed,
    /// Fixed bytes written to the child's stdin, then the pipe is closed.
    Bytes(Vec<u8>),
}

/// The command to execute (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// Executable path. Must point to an executable file; the kernel never
    /// resolves user input through a shell.
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    /// Working directory inside the sandbox. An empty path means "the
    /// workspace root" and is resolved by the runtime during preparation.
    pub working_directory: PathBuf,
    pub stdin: StdinSpec,
}

impl CommandSpec {
    /// Build a command spec with closed stdin and the workspace root as
    /// working directory.
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            args: Vec::new(),
            working_directory: PathBuf::new(),
            stdin: StdinSpec::Closed,
        }
    }

    /// Append one argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set fixed stdin bytes.
    pub fn stdin_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = StdinSpec::Bytes(bytes.into());
        self
    }

    /// Set the working directory (sandbox-relative or host path depending
    /// on provider semantics; validated by the Policy Engine).
    pub fn working_directory(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_directory = dir.into();
        self
    }
}

/// Explicit environment variable whitelist entry (§5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    pub key: String,
    pub value: String,
}

impl EnvironmentVariable {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Explicit environment variable whitelist (§5.4).
///
/// The child environment contains **only** these variables — the host
/// environment is never inherited implicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSpec {
    pub variables: Vec<EnvironmentVariable>,
}

impl EnvironmentSpec {
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self {
            variables: pairs
                .into_iter()
                .map(|(k, v)| EnvironmentVariable::new(k, v))
                .collect(),
        }
    }

    /// Add a variable.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.push(EnvironmentVariable::new(key, value));
        self
    }
}

/// Workspace layout request (§5.5).
///
/// `root` is the workspace directory. When empty, the kernel creates a
/// private temporary directory and owns its lifecycle. When set, the
/// directory must already exist and is **never deleted** by the kernel
/// (see `nsk-workspace` safety rules).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSpec {
    /// Workspace root path; empty = kernel-managed temporary directory.
    pub root: PathBuf,
    /// Sub-directories to create and expose writable inside the workspace.
    pub writable_paths: Vec<PathBuf>,
    /// Paths (host paths) mounted read-only into the sandbox.
    pub readonly_paths: Vec<PathBuf>,
    /// Delete the workspace (only when kernel-created) after execution.
    pub cleanup_on_exit: bool,
}

impl WorkspaceSpec {
    /// Kernel-managed, auto-cleaning workspace.
    pub fn ephemeral() -> Self {
        Self {
            root: PathBuf::new(),
            writable_paths: Vec::new(),
            readonly_paths: Vec::new(),
            cleanup_on_exit: true,
        }
    }
}

/// Full sandbox execution request (§5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub id: SandboxId,
    pub command: CommandSpec,
    pub workspace: WorkspaceSpec,
    pub environment: EnvironmentSpec,
    pub policy: SandboxPolicy,
}

impl SandboxSpec {
    /// Build a spec with a fresh id, a minimal policy and an ephemeral
    /// workspace.
    pub fn new(command: CommandSpec) -> Self {
        Self {
            id: SandboxId::new(),
            command,
            workspace: WorkspaceSpec::ephemeral(),
            environment: EnvironmentSpec::default(),
            policy: SandboxPolicy::minimal(),
        }
    }

    /// Override the policy.
    pub fn with_policy(mut self, policy: SandboxPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Add an environment whitelist entry.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment = self.environment.with(key, value);
        self
    }

    /// Override the workspace spec.
    pub fn with_workspace(mut self, workspace: WorkspaceSpec) -> Self {
        self.workspace = workspace;
        self
    }

    /// Structural validation (§6.3 basic rules) that needs no OS access.
    ///
    /// Deeper checks (existence, permissions, path safety) are performed by
    /// the Policy Engine and Workspace Manager against the real filesystem.
    pub fn validate(&self) -> Result<(), SandboxError> {
        let mut diags = Vec::new();

        // Executable must be a non-empty path without NUL and must be
        // absolute or a bare file name (resolved against sandbox PATH).
        let exe = self.command.executable.as_os_str().as_encoded_bytes();
        if exe.is_empty() {
            diags.push(Diagnostic::error(
                codes::POLICY_INVALID,
                "executable path is empty",
            ));
        } else if validation::contains_nul(exe) {
            diags.push(Diagnostic::error(
                codes::POLICY_INVALID,
                "executable path contains NUL byte",
            ));
        } else if self.command.executable.is_absolute() {
            // fine
        } else if self.command.executable.components().count() != 1 {
            diags.push(Diagnostic::error(
                codes::POLICY_INVALID,
                "executable must be an absolute path or a bare program name",
            ));
        }

        // Arguments must not contain NUL bytes.
        if self.command.args.len() > validation::MAX_ARGS {
            diags.push(Diagnostic::error(
                codes::POLICY_INVALID,
                format!("too many arguments (max {})", validation::MAX_ARGS),
            ));
        }
        for (i, arg) in self.command.args.iter().enumerate() {
            let bytes = arg.as_encoded_bytes();
            if bytes.len() > validation::MAX_ARG_LEN {
                diags.push(Diagnostic::error(
                    codes::POLICY_INVALID,
                    format!("argument {i} exceeds maximum length"),
                ));
            }
            if validation::contains_nul(bytes) {
                diags.push(Diagnostic::error(
                    codes::POLICY_INVALID,
                    format!("argument {i} contains NUL byte"),
                ));
            }
        }

        // Environment whitelist validation.
        if self.environment.variables.len() > validation::MAX_ENV_COUNT {
            diags.push(Diagnostic::error(
                codes::POLICY_INVALID,
                format!(
                    "too many environment variables (max {})",
                    validation::MAX_ENV_COUNT
                ),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for var in &self.environment.variables {
            if !validation::is_valid_env_key(&var.key) {
                diags.push(Diagnostic::error(
                    codes::POLICY_INVALID,
                    format!("invalid environment variable key: {:?}", var.key),
                ));
            }
            if seen.contains(&var.key) {
                diags.push(Diagnostic::error(
                    codes::POLICY_INVALID,
                    format!("duplicate environment variable key: {}", var.key),
                ));
            }
            seen.insert(var.key.clone());
            if var.value.len() > validation::MAX_ENV_VALUE_LEN {
                diags.push(Diagnostic::error(
                    codes::POLICY_INVALID,
                    format!("environment variable {} exceeds maximum length", var.key),
                ));
            }
            if var.value.contains('\0') {
                diags.push(Diagnostic::error(
                    codes::POLICY_INVALID,
                    format!("environment variable {} contains NUL byte", var.key),
                ));
            }
        }

        // Workspace paths: writable sub-paths are workspace-internal
        // (relative allowed); readonly paths are host paths and must be
        // absolute.
        for p in &self.workspace.readonly_paths {
            if !p.as_os_str().is_empty() && !p.is_absolute() {
                diags.push(Diagnostic::error(
                    codes::POLICY_PATH_INVALID,
                    format!("workspace readonly path must be absolute: {}", p.display()),
                ));
            }
        }

        if diags.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::PolicyValidation(diags))
        }
    }

    /// The effective working directory: explicit path or workspace root.
    pub fn working_directory<'a>(&'a self, workspace_root: &'a Path) -> &'a Path {
        if self.command.working_directory.as_os_str().is_empty() {
            workspace_root
        } else {
            &self.command.working_directory
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SandboxId;

    #[cfg(unix)]
    fn echo() -> PathBuf {
        PathBuf::from("/bin/echo")
    }

    #[cfg(not(unix))]
    fn echo() -> PathBuf {
        PathBuf::from("echo")
    }

    #[test]
    fn valid_spec_passes() {
        let spec = SandboxSpec::new(CommandSpec::new(echo()).arg("hello"));
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn empty_executable_rejected() {
        let mut spec = SandboxSpec::new(CommandSpec::new(""));
        if let Err(SandboxError::PolicyValidation(diags)) = spec.validate() {
            assert!(!diags.is_empty());
        } else {
            panic!("expected PolicyValidation error");
        }
        let _ = &mut spec;
    }

    #[test]
    fn relative_multi_component_executable_rejected() {
        let spec = SandboxSpec::new(CommandSpec::new(Path::new("a/b/c")));
        assert!(spec.validate().is_err());
    }

    #[test]
    fn nul_in_args_rejected() {
        let spec = SandboxSpec::new(CommandSpec::new(echo()).arg("bad\0arg"));
        assert!(spec.validate().is_err());
    }

    #[test]
    fn env_validation() {
        let spec = SandboxSpec::new(CommandSpec::new(echo()))
            .with_env("GOOD_KEY", "v")
            .with_env("BAD-KEY", "v")
            .with_env("GOOD_KEY", "dup");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn workspace_path_semantics() {
        // Relative writable sub-path is workspace-internal: allowed.
        let spec = SandboxSpec::new(CommandSpec::new(echo())).with_workspace(WorkspaceSpec {
            root: PathBuf::new(),
            writable_paths: vec![PathBuf::from("relative/out")],
            readonly_paths: vec![],
            cleanup_on_exit: true,
        });
        assert!(spec.validate().is_ok());

        // Readonly host paths must be absolute.
        let spec = SandboxSpec::new(CommandSpec::new(echo())).with_workspace(WorkspaceSpec {
            root: PathBuf::new(),
            writable_paths: vec![],
            readonly_paths: vec![PathBuf::from("relative/host")],
            cleanup_on_exit: true,
        });
        assert!(spec.validate().is_err());
    }

    #[test]
    fn working_directory_defaults_to_workspace_root() {
        let spec = SandboxSpec::new(CommandSpec::new(echo()));
        let wd = spec.working_directory(Path::new("/tmp/ws"));
        assert_eq!(wd, Path::new("/tmp/ws"));

        let spec = SandboxSpec::new(CommandSpec::new(echo()).working_directory("/tmp/ws/sub"));
        let wd = spec.working_directory(Path::new("/tmp/ws"));
        assert_eq!(wd, Path::new("/tmp/ws/sub"));
    }

    #[test]
    fn ids_differ_per_spec() {
        let a = SandboxSpec::new(CommandSpec::new(echo()));
        let b = SandboxSpec::new(CommandSpec::new(echo()));
        assert_ne!(a.id, b.id);
        let _ = SandboxId::new();
    }

    #[test]
    fn serde_roundtrip() {
        let spec = SandboxSpec::new(CommandSpec::new(echo()).arg("x").stdin_bytes(b"abc"));
        let json = serde_json::to_string(&spec).unwrap();
        let back: SandboxSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }
}
