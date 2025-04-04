use super::{HandleError, SafeHandle};
use crate::processes::nt::NtProcessState;
use ntapi::winapi::shared::ntdef::LARGE_INTEGER;
use ntapi::winapi::um::winnt::CONTEXT_FULL;
use thiserror::Error;
use windows::core::Error;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FLAGS,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS,
};
use windows::Win32::{
    Foundation::HANDLE,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    },
};

#[derive(Error, Debug)]
pub enum ThreadError {
    #[error(transparent)]
    PermissionDenied(#[from] Error),
    #[error(transparent)]
    HandleError(#[from] HandleError),
    #[error("Could not suspend thread.")]
    CouldNotSuspendThread,
    #[error("Could not resume thread.")]
    CouldNotResumeThread,
}

type Result<T> = std::result::Result<T, ThreadError>;

pub struct Context(pub CONTEXT);

impl std::fmt::Debug for Context {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct("Context")
            .field("rip", &self.0.Rip)
            .field("rsp", &self.0.Rsp)
            .field("rbp", &self.0.Rbp)
            .field("rax", &self.0.Rax)
            .field("rbx", &self.0.Rbx)
            .field("rcx", &self.0.Rcx)
            .finish()
    }
}

// not gonna lie this might be a bit cooked.
pub trait ThreadOperations {
    fn get_handle(&self) -> Result<SafeHandle>;

    /// Stops the current thread from running
    fn suspend(&self) -> Result<()> {
        if unsafe { SuspendThread(self.get_handle()?.get()?) != u32::max_value() } {
            return Ok(());
        }
        Err(ThreadError::CouldNotSuspendThread)
    }

    /// Resumes the thread if it was suspended.
    fn resume(&self) -> Result<()> {
        if unsafe { ResumeThread(self.get_handle()?.get()?) != u32::max_value() } {
            return Ok(());
        }
        Err(ThreadError::CouldNotResumeThread)
    }

    /// Gets the CPU context of the lower level thread.
    fn get_context(&self) -> Result<Context> {
        // create a new context object, to be filled.
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_FLAGS(CONTEXT_FULL);

        unsafe {
            // fill in the context struct, according to windows.
            GetThreadContext(self.get_handle()?.get()?, &mut context)?;
        }
        Ok(Context(context))
    }

    fn set_context(&self, context: Context) -> Result<()> {
        unsafe { Ok(SetThreadContext(self.get_handle()?.get()?, &context.0)?) }
    }
}

pub struct Thread {
    pub usage_count: u32,
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub base_priority: i32,
    pub delta_priority: i32,
    pub flags: u32,
}

impl ThreadOperations for Thread {
    fn get_handle(&self) -> Result<SafeHandle> {
        unsafe {
            Ok(SafeHandle::new(OpenThread(
                THREAD_ALL_ACCESS,
                false,
                self.thread_id,
            )?))
        }
    }
}

pub struct ThreadIterator {
    process_id: u32,
    _snapshot: HANDLE,
}

impl ThreadIterator {
    pub fn new(process_id: u32) -> Self {
        Self {
            process_id,
            _snapshot: HANDLE(0 as _),
        }
    }
}

impl Iterator for ThreadIterator {
    type Item = Thread;

    fn next(&mut self) -> Option<Self::Item> {
        // create a mutable empty processentry32 struct so that it can be written to when iterating over processes.
        let mut thread_info = THREADENTRY32::default();

        // set the size of the structure before using it.
        thread_info.dwSize = std::mem::size_of::<THREADENTRY32>() as _;

        loop {
            unsafe {
                // this means that we haven't created the snapshot.
                if self._snapshot == HANDLE(0 as _) {
                    // if we can't create a handle then return none.
                    self._snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                        Ok(handle) => handle,
                        Err(_) => return None,
                    };

                    // write the information of the first process in the snapshot to `process_info`.
                    let _ = Thread32First(self._snapshot, &mut thread_info);
                } else {
                    // write the information of the next process o the process info struct.
                    if (!Thread32Next(self._snapshot, &mut thread_info).is_ok()).into() {
                        return None;
                    }
                }
            }

            // if this thread belongs to our target process then break.
            if thread_info.th32OwnerProcessID == self.process_id {
                break;
            }
        }

        Some(Thread {
            usage_count: thread_info.cntUsage,
            thread_id: thread_info.th32ThreadID,
            owner_process_id: thread_info.th32OwnerProcessID,
            base_priority: thread_info.tpBasePri,
            delta_priority: thread_info.tpDeltaPri,
            flags: thread_info.dwFlags,
        })
    }
}

#[allow(non_camel_case_types, unused)]
#[derive(Debug, PartialEq)]
pub enum WaitReason {
    EXECUTIVE,
    FREE_PAGE,
    PAGE_IN,
    POOL_ALLOCATION,
    DELAY_EXECUTION,
    SUSPENDED,
    USER_REQUEST,
    WR_EXECUTIVE,
    WR_FREE_PAGE,
    WR_PAGE_IN,
    WR_POOL_ALLOCATION,
    WR_DELAY_EXECUTION,
    WR_SUSPENDED,
    WR_USER_REQUEST,
    UNKNOWN,
    WR_QUEUE,
}

#[allow(non_camel_case_types, unused)]
#[derive(Debug, PartialEq)]
pub enum ThreadState {
    INITIALIZED,
    READY,
    RUNNING,
    STANDBY,
    TERMINATED,
    WAITING,
    TRANSITION,
    DEFERRED_READY,
    GATE_WAIT,
}

pub struct NtThread {
    pub kernel_time: LARGE_INTEGER,
    pub user_time: LARGE_INTEGER,
    pub create_time: LARGE_INTEGER,
    pub wait_time: u32,
    pub start_address: u64,
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub priority: i32,
    pub base_priority: i32,
    pub context_switches: u32,
    pub thread_state: ThreadState,
    pub wait_reason: WaitReason,
}

impl ThreadOperations for NtThread {
    fn get_handle(&self) -> Result<SafeHandle> {
        unsafe {
            Ok(SafeHandle::new(OpenThread(
                THREAD_ALL_ACCESS,
                false,
                self.thread_id,
            )?))
        }
    }
}

pub struct NtThreadIterator<'a> {
    nt_process_state: &'a NtProcessState,
    count: u32,
}

impl<'a> NtThreadIterator<'a> {
    pub fn new(nt_process_state: &'a NtProcessState) -> Self {
        Self {
            count: 0,
            nt_process_state,
        }
    }
}

impl<'a> Iterator for NtThreadIterator<'a> {
    type Item = NtThread;

    fn next(&mut self) -> Option<Self::Item> {
        // check if we've reached the limit of threads.
        if self.count >= self.nt_process_state.raw.NumberOfThreads {
            return None;
        }

        // get a pointer to the start of the threads array.
        let thread_ptr = unsafe {
            (*self.nt_process_state.get_pointer_to_slot())
                .Threads
                .as_ptr()
        };

        // dereference the current entry in the array.
        let thread_information = unsafe { *thread_ptr.add(self.count as usize) };

        // increase the count.
        self.count += 1;

        let thread_state = match thread_information.ThreadState {
            0 => ThreadState::INITIALIZED,
            1 => ThreadState::READY,
            2 => ThreadState::RUNNING,
            3 => ThreadState::STANDBY,
            4 => ThreadState::TERMINATED,
            5 => ThreadState::WAITING,
            6 => ThreadState::TRANSITION,
            7 => ThreadState::DEFERRED_READY,
            8 => ThreadState::GATE_WAIT,
            _ => panic!("invalid state during thread info parsing."),
        };

        let wait_reason = match thread_information.WaitReason {
            0 => WaitReason::EXECUTIVE,
            1 => WaitReason::FREE_PAGE,
            2 => WaitReason::PAGE_IN,
            3 => WaitReason::POOL_ALLOCATION,
            4 => WaitReason::DELAY_EXECUTION,
            5 => WaitReason::SUSPENDED,
            6 => WaitReason::USER_REQUEST,
            7 => WaitReason::WR_EXECUTIVE,
            8 => WaitReason::WR_FREE_PAGE,
            9 => WaitReason::WR_PAGE_IN,
            10 => WaitReason::WR_POOL_ALLOCATION,
            11 => WaitReason::WR_DELAY_EXECUTION,
            12 => WaitReason::WR_SUSPENDED,
            13 => WaitReason::WR_USER_REQUEST,
            15 => WaitReason::WR_QUEUE,
            _ => WaitReason::UNKNOWN,
        };

        Some(NtThread {
            kernel_time: thread_information.KernelTime,
            user_time: thread_information.UserTime,
            create_time: thread_information.CreateTime,
            wait_time: thread_information.WaitTime,
            start_address: thread_information.StartAddress as _,
            thread_id: thread_information.ClientId.UniqueThread as _,
            owner_process_id: thread_information.ClientId.UniqueProcess as _,
            priority: thread_information.Priority,
            base_priority: thread_information.BasePriority,
            context_switches: thread_information.ContextSwitches,
            thread_state,
            wait_reason,
        })
    }
}
