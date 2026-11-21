//! Job Object manager (§11.3) — Windows implementation.
//!
//! One Job Object per sandbox: process-set containment, preventive memory /
//! process-count / CPU-rate limits, and whole-tree termination
//! (`TerminateJobObject`; `KILL_ON_JOB_CLOSE` is the crash backstop).
//!
//! Idempotency contract (§9.2): `terminate` and `close` may be called any
//! number of times in any order; every call after the first is a no-op.
//! The handle is closed exactly once (`Drop`).

use std::sync::atomic::{AtomicBool, Ordering};

use nsk_core::error::SandboxError;
use nsk_core::result::ResourceUsage;
use tracing::{debug, info};

use crate::limits::JobLimits;

/// Zero-initialized POD for Win32 info structures.
///
/// SAFETY: only instantiated for `Copy` POD structs without padding
/// sensitivities (Win32 info structs are fully defined by the ABI).
fn zeroed<T>() -> T {
    assert!(std::mem::size_of::<T>() > 0, "zeroed<T>: T must not be ZST");
    // SAFETY: POD Win32 structures; caller reads back what the kernel wrote.
    unsafe { std::mem::zeroed() }
}

/// Managed Job Object for one sandbox.
///
/// The raw handle is stored as `isize` so the type stays `Send`/`Sync`
/// without exposing pointer semantics; every API call casts back to
/// `windows_sys::Win32::Foundation::HANDLE`.
pub struct JobObject {
    handle: isize,
    limits: JobLimits,
    terminated: AtomicBool,
    closed: AtomicBool,
}

// SAFETY: Job handles from CreateJobObjectW are usable from any thread.
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

impl std::fmt::Debug for JobObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobObject")
            .field("handle", &self.handle)
            .field("limits", &self.limits)
            .field("terminated", &self.terminated.load(Ordering::SeqCst))
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl JobObject {
    /// Create the job object and apply limits (§11.3).
    pub fn create(limits: JobLimits) -> Result<Self, SandboxError> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
            JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_BASIC_LIMIT_INFORMATION,
            JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectCpuRateControlInformation,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };

        // SAFETY: CreateJobObjectW with default security and no name.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(SandboxError::ResourceLimit(format!(
                "CreateJobObjectW failed: {}",
                crate::token::last_error()
            )));
        }
        let handle = handle as isize;

        // SAFETY: handle is a valid job handle; the info struct matches the
        // documented layout for JobObjectExtendedLimitInformation.
        unsafe {
            let mut basic: JOBOBJECT_BASIC_LIMIT_INFORMATION = zeroed();
            let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Some(pids) = limits.max_processes {
                flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                basic.ActiveProcessLimit = pids;
            }
            // The memory limits below are only consulted by the kernel when
            // their flag bits are set — without them the commit caps are
            // silently ignored (§11.3).
            if limits.memory_bytes.is_some() {
                flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
            }
            basic.LimitFlags = flags;
            let ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: basic,
                IoInfo: zeroed(),
                ProcessMemoryLimit: limits.memory_bytes.unwrap_or(0) as usize,
                JobMemoryLimit: limits.memory_bytes.unwrap_or(0) as usize,
                PeakProcessMemoryUsed: 0,
                PeakJobMemoryUsed: 0,
            };
            let rc = SetInformationJobObject(
                handle as _,
                JobObjectExtendedLimitInformation,
                &ext as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if rc == 0 {
                let err = crate::token::last_error();
                CloseHandle(handle as _);
                return Err(SandboxError::ResourceLimit(format!(
                    "SetInformationJobObject(extended) failed: {err}"
                )));
            }

            if let Some(rate) = limits.cpu_rate {
                let cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                    ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                        | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: rate },
                };
                let rc = SetInformationJobObject(
                    handle as _,
                    JobObjectCpuRateControlInformation,
                    &cpu as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                );
                if rc == 0 {
                    let err = crate::token::last_error();
                    CloseHandle(handle as _);
                    return Err(SandboxError::ResourceLimit(format!(
                        "SetInformationJobObject(cpu-rate) failed: {err}"
                    )));
                }
            }

            if limits.ui_restrictions {
                if let Err(e) = apply_ui_restrictions(handle) {
                    CloseHandle(handle as _);
                    return Err(e);
                }
            }
        }

        debug!(limits = %limits.describe(), "job object created with limits");
        Ok(Self {
            handle,
            limits,
            terminated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    /// Assign a process to the job.
    ///
    /// # Safety
    /// `process_handle` must be a valid process handle with
    /// `PROCESS_SET_QUOTA | PROCESS_TERMINATE` access.
    pub unsafe fn assign(&self, process_handle: isize) -> Result<(), SandboxError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY: caller guarantees the handle is valid and owned.
        let rc = unsafe { AssignProcessToJobObject(self.handle as _, process_handle as _) };
        if rc == 0 {
            return Err(SandboxError::ResourceLimit(format!(
                "AssignProcessToJobObject failed: {}",
                crate::token::last_error()
            )));
        }
        Ok(())
    }

    /// Terminate every process in the job (§11.3 whole-tree kill). Must be
    /// idempotent. An empty job may fail harmlessly (treated as success).
    pub fn terminate(&self) -> Result<(), SandboxError> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if self.terminated.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // SAFETY: handle is a valid job handle.
        let rc = unsafe { TerminateJobObject(self.handle as _, 1) };
        if rc == 0 {
            self.terminated.store(false, Ordering::SeqCst);
            return Err(SandboxError::ResourceLimit(format!(
                "TerminateJobObject failed: {}",
                crate::token::last_error()
            )));
        }
        info!("job object terminated (whole tree)");
        Ok(())
    }

    /// Close the job handle (exactly once). With `KILL_ON_JOB_CLOSE` this
    /// is also the crash-safe cleanup backstop.
    pub fn close(&self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // SAFETY: single close guarded by the `closed` flag.
        unsafe { CloseHandle(self.handle as _) };
        debug!("job object handle closed");
    }

    /// Current usage from the job accounting structures (§7.2).
    pub fn observe_usage(&self) -> Result<ResourceUsage, SandboxError> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION,
            JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAndIoAccountingInformation, JobObjectBasicProcessIdList,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
        };

        let mut usage = ResourceUsage::default();

        // SAFETY: valid handle; struct layouts match the queried classes.
        unsafe {
            let mut io: JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION = zeroed();
            let rc = QueryInformationJobObject(
                self.handle as _,
                JobObjectBasicAndIoAccountingInformation,
                &mut io as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if rc != 0 {
                let JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION { BasicInfo, IoInfo } = io;
                let JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
                    TotalUserTime,
                    TotalKernelTime,
                    ..
                } = BasicInfo;
                usage.cpu_time = Some(std::time::Duration::from_nanos(
                    (TotalUserTime as u64).saturating_add(TotalKernelTime as u64) * 100,
                ));
                usage.disk_usage_bytes =
                    Some(IoInfo.ReadTransferCount as u64 + IoInfo.WriteTransferCount as u64);
            }

            let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            let rc = QueryInformationJobObject(
                self.handle as _,
                JobObjectExtendedLimitInformation,
                &mut ext as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if rc != 0 && ext.PeakJobMemoryUsed > 0 {
                usage.memory_peak_bytes = Some(ext.PeakJobMemoryUsed as u64);
            }

            // Process count: query with a small list first; grow once when
            // truncated. Never unbounded (§2.7 least privilege / safety).
            let mut n = 16usize;
            for _ in 0..4 {
                let mut buf = vec![
                    0u8;
                    std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
                        + n * std::mem::size_of::<usize>()
                ];
                let list = buf.as_mut_ptr() as *mut JOBOBJECT_BASIC_PROCESS_ID_LIST;
                let rc = QueryInformationJobObject(
                    self.handle as _,
                    JobObjectBasicProcessIdList,
                    list as *mut core::ffi::c_void,
                    buf.len() as u32,
                    std::ptr::null_mut(),
                );
                if rc == 0 {
                    break;
                }
                let assigned = (*list).NumberOfAssignedProcesses as usize;
                if (*list).NumberOfProcessIdsInList as usize >= assigned {
                    usage.process_count = Some(assigned as u32);
                    break;
                }
                n = assigned + 16;
            }
        }

        Ok(usage)
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        self.close();
    }
}

/// UI restrictions (§11.5-adjacent hardening): deny clipboard access,
/// system-parameter changes, exiting/shutting down the system, global atom
/// access and handle access outside the job.
fn apply_ui_restrictions(handle: isize) -> Result<(), SandboxError> {
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JobObjectBasicUIRestrictions, SetInformationJobObject,
    };
    // SAFETY: valid handle; layout matches the UI-restrictions class.
    unsafe {
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS,
        };
        let rc = SetInformationJobObject(
            handle as _,
            JobObjectBasicUIRestrictions,
            &ui as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        );
        if rc == 0 {
            return Err(SandboxError::ResourceLimit(format!(
                "SetInformationJobObject(ui) failed: {}",
                crate::token::last_error()
            )));
        }
    }
    Ok(())
}

/// Open a process by pid with job-assignment rights.
///
/// # Safety
/// The returned handle must be closed by the caller
/// ([`close_process_handle`]).
pub unsafe fn open_process_for_job(pid: u32) -> Result<isize, SandboxError> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };
    // SAFETY: documented OpenProcess call; the caller owns the handle.
    let handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return Err(SandboxError::ResourceLimit(format!(
            "OpenProcess({pid}) failed: {}",
            crate::token::last_error()
        )));
    }
    Ok(handle as isize)
}

/// Close a process handle opened by [`open_process_for_job`].
///
/// # Safety
/// The handle must have been returned by [`open_process_for_job`] and not
/// closed before.
pub unsafe fn close_process_handle(handle: isize) {
    use windows_sys::Win32::Foundation::CloseHandle;
    // SAFETY: caller guarantees single ownership per the contract.
    unsafe { CloseHandle(handle as _) };
}

/// Resume every thread of a suspended process (after job assignment).
///
/// The supervisor spawns the child with `CREATE_SUSPENDED` so the process
/// can be placed under the Job Object **before** its first instruction runs
/// (no escape window for grandchildren). Resumption walks the toolhelp
/// thread snapshot.
pub fn resume_process_threads(pid: u32) -> Result<usize, SandboxError> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    // SAFETY: snapshot + iteration per the documented toolhelp protocol;
    // every opened thread handle is closed on all paths.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return Err(SandboxError::ResourceLimit(format!(
                "CreateToolhelp32Snapshot failed: {}",
                crate::token::last_error()
            )));
        }

        let mut resumed = 0usize;
        let mut entry: THREADENTRY32 = zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut iter_rc = Thread32First(snapshot, &mut entry);
        while iter_rc != 0 {
            if entry.th32OwnerProcessID == pid {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                if !thread.is_null() {
                    ResumeThread(thread);
                    CloseHandle(thread);
                    resumed += 1;
                }
            }
            iter_rc = Thread32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);

        if resumed == 0 {
            return Err(SandboxError::ResourceLimit(format!(
                "no threads resumed for pid {pid}"
            )));
        }
        Ok(resumed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn job_object_lifecycle() {
        if !cfg!(windows) {
            return;
        }
        let job = JobObject::create(JobLimits::from_policy(64 * 1024 * 1024, 4, Some(0.5), true))
            .expect("job creation");
        let usage = job.observe_usage().expect("usage query");
        assert_eq!(usage.process_count, Some(0));
        job.terminate()
            .expect("terminate (empty job is ok or harmless)");
        job.terminate().expect("idempotent terminate");
        job.close();
        job.close();
        drop(job);
    }
}
