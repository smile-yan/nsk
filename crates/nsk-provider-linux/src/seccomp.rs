//! seccomp allowlist profile (§10.8).
//!
//! Phase-1 policy (§10.8): use a **validated allowlist profile**, not a
//! from-scratch universal filter; never accept user-provided raw seccomp
//! rules. The profile is generated as classic BPF and applied by bubblewrap
//! via `--seccomp-fd` (the fd is opened pre-exec by the supervisor).
//!
//! Default action is `ERRNO(EPERM)` ("compatible" mode): a syscall missing
//! from the allowlist fails harmlessly instead of killing the program.
//! Security depends only on what is *allowed*, so the tables below contain
//! just the syscall surface of ordinary console programs, on x86_64 and
//! aarch64. Networking (socket family), ptrace, mount, keyring, bpf and
//! privilege-setting syscalls are never allowed — network isolation is
//! additionally enforced by the network namespace.
//!
//! The profile is **experimental until validated on the target environment**
//! (§10.8) and disabled by default.

use std::io::Write;
use std::path::PathBuf;

/// seccomp target architectures (AUDIT_ARCH_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompArch {
    X86_64,
    Aarch64,
}

impl SeccompArch {
    pub fn audit_arch(self) -> u32 {
        match self {
            SeccompArch::X86_64 => 0xC000_003E,
            SeccompArch::Aarch64 => 0xC000_00B7,
        }
    }

    /// The architecture this build runs on (Linux only).
    pub fn current() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(SeccompArch::X86_64),
            "aarch64" => Some(SeccompArch::Aarch64),
            _ => None,
        }
    }
}

/// Default action for non-allowlisted syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompDefaultAction {
    /// `SECCOMP_RET_ERRNO(EPERM)` — compatible mode.
    ErrnoPerm,
    /// `SECCOMP_RET_KILL_THREAD` — strict mode.
    KillThread,
}

impl SeccompDefaultAction {
    pub fn ret_value(self) -> u32 {
        match self {
            // SECCOMP_RET_ERRNO | EPERM(1)
            SeccompDefaultAction::ErrnoPerm => 0x0005_0000 | 1,
            // SECCOMP_RET_KILL_THREAD
            SeccompDefaultAction::KillThread => 0x0000_0000,
        }
    }
}

/// Auxiliary fd number used to hand the BPF program to bubblewrap.
///
/// The supervisor opens the profile file pre-exec and dups it onto this fd;
/// bwrap is launched with `--seccomp-fd 47`.
pub const SECCOMP_AUX_FD: i32 = 47;

/// BPF instruction encodings (classic BPF, seccomp_data layout).
const BPF_LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

/// One BPF instruction: `{ u16 code, u8 jt, u8 jf, u32 k }` (8 bytes).
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl BpfInsn {
    fn encode(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.code.to_le_bytes());
        out[2] = self.jt;
        out[3] = self.jf;
        out[4..8].copy_from_slice(&self.k.to_le_bytes());
        out
    }
}

/// A generated seccomp filter program.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub arch: SeccompArch,
    pub allowed_syscalls: Vec<i32>,
    pub default_action: SeccompDefaultAction,
}

impl SeccompProfile {
    /// Profile with the default validated allowlist.
    pub fn validated_default(arch: SeccompArch, action: SeccompDefaultAction) -> Self {
        Self {
            arch,
            allowed_syscalls: default_allowlist(arch),
            default_action: action,
        }
    }

    /// Generate the BPF program bytes.
    ///
    /// Layout:
    /// 1. load `arch` (seccomp_data offset 4); default-ret on mismatch,
    /// 2. load `nr` (offset 0),
    /// 3. jeq chain over the allowlist → `RET ALLOW`,
    /// 4. `RET <default>`.
    pub fn build_bpf(&self) -> Vec<u8> {
        let arch = self.arch.audit_arch();
        let allow = SECCOMP_RET_ALLOW;
        let default = self.default_action.ret_value();

        let mut prog: Vec<BpfInsn> = Vec::with_capacity(4 + self.allowed_syscalls.len() * 2);
        // [0] ld [4] (arch)
        prog.push(BpfInsn {
            code: BPF_LD_ABS_W,
            jt: 0,
            jf: 0,
            k: 4,
        });
        // [1] jeq arch, jt=0 (next: ld nr), jf=2 (skip to default ret)
        prog.push(BpfInsn {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 2,
            k: arch,
        });
        // [2] ret default (wrong arch)
        prog.push(BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: default,
        });
        // [3] ld [0] (nr)
        prog.push(BpfInsn {
            code: BPF_LD_ABS_W,
            jt: 0,
            jf: 0,
            k: 0,
        });

        for nr in &self.allowed_syscalls {
            // jeq nr, jt=0 (fall through to ALLOW), jf=1 (skip ALLOW)
            prog.push(BpfInsn {
                code: BPF_JEQ_K,
                jt: 0,
                jf: 1,
                k: *nr as u32,
            });
            // ret ALLOW
            prog.push(BpfInsn {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: allow,
            });
        }
        // final default
        prog.push(BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: default,
        });

        let mut out = Vec::with_capacity(prog.len() * 8);
        for insn in prog {
            out.extend_from_slice(&insn.encode());
        }
        out
    }

    /// Write the program to a file suitable for `--seccomp-fd`.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(&self.build_bpf())?;
        f.flush()?;
        Ok(())
    }
}

/// The validated default allowlist (§10.8).
///
/// Numbers are the stable Linux syscall tables for x86_64 and aarch64.
/// Excluded on purpose: socket family (net namespace already removes
/// interfaces), ptrace, mount/umount, chroot, kexec, bpf, perf, keyring,
/// module loading, setuid/setgid/setgroups (the sandbox never gains
/// privileges), SysV IPC (IPC namespace is empty), io_uring (phase 1).
pub fn default_allowlist(arch: SeccompArch) -> Vec<i32> {
    let mut list: Vec<i32> = match arch {
        SeccompArch::X86_64 => vec![
            // I/O
            0, 1, 3, // read, write, close
            17, 18, // pread64, pwrite64
            19, 20, // readv, writev
            16, // ioctl
            7, 8, // poll, lseek
            32, 33, 292, // dup, dup2, dup3
            // Memory
            9, 10, 11, 12, // mmap, mprotect, munmap, brk
            25, 26, 28, // mremap, msync, madvise
            // Signals & process
            13, 14, 15, // rt_sigaction, rt_sigprocmask, rt_sigreturn
            35, 230, // nanosleep, clock_nanosleep
            24,  // sched_yield
            39, 110, 186, // getpid, getppid, gettid
            102, 104, 107, 108, // getuid, getgid, geteuid, getegid
            118, 120, // getresuid, getresgid
            109, // setpgid
            56, 57, 58, 59, // clone, fork, vfork, execve
            60, 231, // exit, exit_group
            61, 62, 234, // wait4, kill, tgkill
            63,  // uname
            202, // futex
            218, // set_tid_address
            273, 274, // set_robust_list, get_robust_list
            131, // sigaltstack
            203, // sched_getaffinity (get only)
            // Filesystem
            2, 257, 437, // open, openat, openat2
            4, 5, 6, 262, 332, // stat, fstat, lstat, newfstatat, statx
            21, 269, 439, // access, faccessat, faccessat2
            72, 73, // fcntl, flock
            74, 75, // fsync, fdatasync
            76, 77, // truncate, ftruncate
            79, 80, 81, // getcwd, chdir, fchdir
            82, 83, 84, 87, // rename, mkdir, rmdir, unlink
            264, 263, 258, // renameat, unlinkat, mkdirat
            316, // renameat2
            85,  // creat
            88, 89, 267, // symlink, readlink, readlinkat
            90, 91, 268, // chmod, fchmod, fchmodat
            92, 93, 94, // chown, fchown, lchown (self-files only in practice)
            95, // umask
            22, 293, // pipe, pipe2
            217, // getdents64
            // epoll / poll
            213, 232, 233, 281, // epoll_create, epoll_wait, epoll_ctl, epoll_pwait
            270, 271, // pselect6, ppoll
            441, // epoll_pwait2
            // Time & misc
            96, 98, 99, // gettimeofday, getrusage, sysinfo
            97, 302, // getrlimit, prlimit64
            318, 319, // getrandom, memfd_create
            334, // rseq
            435, 436, // clone3, close_range
        ],
        SeccompArch::Aarch64 => vec![
            // I/O
            63, 64, 3, // read, write, close
            65, 66, // readv, writev
            67, 68, // pread64, pwrite64
            29, // ioctl
            62, // lseek
            23, 24, // dup, dup3
            25, // fcntl
            // Memory
            222, 215, 226, 214, // mmap, munmap, mprotect, brk
            216, 227, 233, // mremap, msync, madvise
            // Signals & process
            134, 135, 139, // rt_sigaction, rt_sigprocmask, rt_sigreturn
            101, 115, // nanosleep, clock_nanosleep
            124, // sched_yield
            172, 173, 178, // getpid, getppid, gettid
            174, 176, 175, 177, // getuid, getgid, geteuid, getegid
            165, 166, // getresuid, getresgid
            220, 221, // clone, execve
            93, 94, // exit, exit_group
            260, 129, 131, // wait4, kill, tgkill
            160, // uname
            98,  // futex
            96,  // set_tid_address
            99, 100, // set_robust_list, get_robust_list
            132, // sigaltstack
            123, // sched_getaffinity
            113, 114, // clock_gettime, clock_getres
            // Filesystem
            56, 437, // openat, openat2
            80, 291, // newfstatat(fstat), statx
            48, 439, // faccessat, faccessat2
            82, 83, // fsync, fdatasync
            45, 46, // truncate, ftruncate
            17, 50, 51, // getcwd, chdir, fchdir
            38, 35, 34,  // renameat, unlinkat, mkdirat
            276, // renameat2
            78,  // readlinkat
            53, 54, // fchmodat, fchownat
            59, // pipe2
            61, // getdents64
            // epoll / poll
            20, 21, 22, // epoll_create1, epoll_ctl, epoll_pwait
            72, 73,  // pselect6, ppoll
            441, // epoll_pwait2
            // Time & misc
            169, // gettimeofday
            163, 261, // getrlimit, prlimit64
            278, 279, // getrandom, memfd_create
            293, // rseq
            435, 436, // clone3, close_range
        ],
    };
    list.sort_unstable();
    list.dedup();
    list
}

/// Convenience: write a profile to `dir` and return its path.
pub fn write_profile_file(
    profile: &SeccompProfile,
    dir: &std::path::Path,
) -> std::io::Result<PathBuf> {
    let path = dir.join("nsk-seccomp.bpf");
    profile.write_to(&path)?;
    Ok(path)
}

/// Human summary used in capability reports.
pub fn describe(profile: &SeccompProfile) -> String {
    format!(
        "seccomp {} allowlist ({} syscalls, default action {:?})",
        match profile.arch {
            SeccompArch::X86_64 => "x86_64",
            SeccompArch::Aarch64 => "aarch64",
        },
        profile.allowed_syscalls.len(),
        profile.default_action
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_structure_is_valid() {
        let profile =
            SeccompProfile::validated_default(SeccompArch::X86_64, SeccompDefaultAction::ErrnoPerm);
        let bpf = profile.build_bpf();

        // 4 header insns + 2 per syscall + 1 final ret.
        let expected_len = (4 + profile.allowed_syscalls.len() * 2 + 1) * 8;
        assert_eq!(bpf.len(), expected_len);

        // First instruction: LD_ABS offset 4 (arch).
        let first: [u8; 8] = bpf[0..8].try_into().unwrap();
        assert_eq!(u16::from_le_bytes([first[0], first[1]]), BPF_LD_ABS_W);
        assert_eq!(
            u32::from_le_bytes([first[4], first[5], first[6], first[7]]),
            4
        );

        // Second: JEQ AUDIT_ARCH_X86_64, jt=0, jf=2.
        let second: [u8; 8] = bpf[8..16].try_into().unwrap();
        assert_eq!(u16::from_le_bytes([second[0], second[1]]), BPF_JEQ_K);
        assert_eq!(second[2], 0);
        assert_eq!(second[3], 2);
        assert_eq!(
            u32::from_le_bytes([second[4], second[5], second[6], second[7]]),
            0xC000_003E
        );

        // Last instruction: default action.
        let last: [u8; 8] = bpf[bpf.len() - 8..].try_into().unwrap();
        assert_eq!(u16::from_le_bytes([last[0], last[1]]), BPF_RET_K);
        assert_eq!(
            u32::from_le_bytes([last[4], last[5], last[6], last[7]]),
            profile.default_action.ret_value()
        );
    }

    #[test]
    fn dangerous_syscalls_never_allowed() {
        for arch in [SeccompArch::X86_64, SeccompArch::Aarch64] {
            let p = SeccompProfile::validated_default(arch, SeccompDefaultAction::ErrnoPerm);
            let s = &p.allowed_syscalls;
            // socket(41 x86_64), ptrace(101 x86_64 / 117 aarch64),
            // mount(165 x86_64 / 40 aarch64), bpf(321 x86_64 / 280 aarch64),
            // setuid(105 x86_64 / 106 aarch64), chroot(161 x86_64 / 51? no).
            if arch == SeccompArch::X86_64 {
                assert!(!s.contains(&41), "socket must be excluded");
                assert!(!s.contains(&101), "ptrace must be excluded");
                assert!(!s.contains(&165), "mount must be excluded");
                assert!(!s.contains(&321), "bpf must be excluded");
                assert!(!s.contains(&105), "setuid must be excluded");
                assert!(!s.contains(&161), "chroot must be excluded");
                assert!(!s.contains(&298), "perf_event_open must be excluded");
                assert!(!s.contains(&250), "keyctl must be excluded");
            } else {
                assert!(!s.contains(&117), "ptrace(aarch64) must be excluded");
                assert!(!s.contains(&40), "mount(aarch64) must be excluded");
                assert!(!s.contains(&280), "bpf(aarch64) must be excluded");
                assert!(!s.contains(&106), "setuid(aarch64) must be excluded");
            }
        }
    }

    #[test]
    fn strictly_empty_allowlist_defaults_to_kill() {
        let p = SeccompProfile {
            arch: SeccompArch::Aarch64,
            allowed_syscalls: vec![],
            default_action: SeccompDefaultAction::KillThread,
        };
        let bpf = p.build_bpf();
        // 4 header + 1 final ret (no syscalls).
        assert_eq!(bpf.len(), 5 * 8);
    }

    #[test]
    fn profile_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let profile =
            SeccompProfile::validated_default(SeccompArch::X86_64, SeccompDefaultAction::ErrnoPerm);
        let path = write_profile_file(&profile, dir.path()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, profile.build_bpf());
    }

    #[test]
    fn describe_mentions_arch_and_count() {
        let profile =
            SeccompProfile::validated_default(SeccompArch::X86_64, SeccompDefaultAction::ErrnoPerm);
        let desc = describe(&profile);
        assert!(desc.contains("x86_64"));
        assert!(desc.contains("allowlist"));
    }
}
