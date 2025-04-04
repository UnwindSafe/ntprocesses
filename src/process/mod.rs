pub mod build;
pub mod module;
pub mod thread;

use crate::processes::nt::{NtIteratorError, NtProcessState};
use crate::WindowsString;
use crate::{processes, safe_handle::*};

use module::{Module, ModuleIterator};
use ntapi::ntpsapi::{NtResumeProcess, NtSuspendProcess};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use thiserror::Error;
use thread::{NtThread, NtThreadIterator, ThreadError, ThreadIterator};
use windows::core::s;
use windows::core::{Error, PCSTR};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_RESERVE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    CreateProcessA, CreateRemoteThread, GetCurrentProcessId, OpenProcess, TerminateProcess,
    CREATE_SUSPENDED, PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTUPINFOA,
};

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Could not find the process searched for.")]
    NoProcessFound,
    #[error("Permission denied.")]
    PermissionDenied(#[from] Error),
    #[error(transparent)]
    NtIteratorError(#[from] NtIteratorError),
    #[error(transparent)]
    HandleError(#[from] HandleError),
    #[error("{0}")]
    ProcessError(String),
    #[error(transparent)]
    ThreadError(#[from] ThreadError),
}

type Result<T> = std::result::Result<T, ProcessError>;

/// Marker struct for process type.
pub struct Snapshot;
/// Marker struct for process type.
pub struct NT;
/// Marker struct for process type.
pub struct Created;

pub struct Process<Method> {
    handle: SafeHandle,
    pub name: String,
    pub process_id: u32,
    /// This holds extra process information, depending on source.
    extensions: HashMap<TypeId, Box<dyn Any>>,
    _marker: std::marker::PhantomData<Method>,
}

impl Process<Snapshot> {
    pub fn from_name(name: &str, access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        // find our process through a snapshot of the process list.
        let target = processes::get_from_snapshot()
            .find(|p| p.get_name() == name)
            .ok_or(ProcessError::NoProcessFound)?;

        // get a handle to the process.
        let handle = unsafe {
            OpenProcess(access, false, target.process_id).map_err(ProcessError::PermissionDenied)?
        };

        // create the process object here so we can do stuff to it.
        let mut process = Self {
            handle: SafeHandle::new(handle),
            name: target.get_name(),
            process_id: target.process_id,
            extensions: HashMap::new(),
            _marker: std::marker::PhantomData,
        };

        process.insert(target);

        Ok(process)
    }

    pub fn from_pid(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        // find our process through a snapshot of the process list.
        let target = processes::get_from_snapshot()
            .find(|p| p.process_id == pid)
            .ok_or(ProcessError::NoProcessFound)?;

        // get a handle to the process.
        let handle = unsafe {
            OpenProcess(access, false, target.process_id).map_err(ProcessError::PermissionDenied)?
        };

        // create the process object here so we can do stuff to it.
        let mut process = Self {
            handle: SafeHandle::new(handle),
            name: target.get_name(),
            process_id: target.process_id,
            extensions: HashMap::new(),
            _marker: std::marker::PhantomData,
        };

        process.insert(target);

        Ok(process)
    }

    pub fn get_threads(&self) -> ThreadIterator {
        ThreadIterator::new(self.process_id)
    }
}

impl Process<NT> {
    pub fn from_name(name: &str, access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        // find our process from querying the system.
        let target = processes::get_from_nt()?
            .find(|p| p.get_name() == name)
            .ok_or(ProcessError::NoProcessFound)?;

        // get a handle to the process.
        let handle = unsafe {
            OpenProcess(access, false, target.raw.UniqueProcessId as _)
                .map_err(ProcessError::PermissionDenied)?
        };

        // create the process object here so we can do stuff to it.
        let mut process = Self {
            handle: SafeHandle::new(handle),
            name: target.get_name(),
            process_id: target.raw.UniqueProcessId as _,
            extensions: HashMap::new(),
            _marker: std::marker::PhantomData,
        };

        process.insert(target);

        Ok(process)
    }

    pub fn from_pid(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        // find our process from querying the system.
        let target = processes::get_from_nt()?
            .find(|p| p.raw.UniqueProcessId as u32 == pid)
            .ok_or(ProcessError::NoProcessFound)?;

        // get a handle to the process.
        let handle = unsafe {
            OpenProcess(access, false, target.raw.UniqueProcessId as _)
                .map_err(ProcessError::PermissionDenied)?
        };

        // create the process object here so we can do stuff to it.
        let mut process = Self {
            handle: SafeHandle::new(handle),
            name: target.get_name(),
            process_id: target.raw.UniqueProcessId as _,
            extensions: HashMap::new(),
            _marker: std::marker::PhantomData,
        };

        process.insert(target);

        Ok(process)
    }

    pub fn get_threads(&self) -> NtThreadIterator {
        // TODO: real error handling, even though this *should* never fail.
        let state = self
            .get::<NtProcessState>()
            .expect("couldn't find process state using NT type.");

        NtThreadIterator::new(&state)
    }
}

impl Process<Created> {
    pub fn from_path(
        path: PathBuf,
        args: &str,
        creation_flags: PROCESS_CREATION_FLAGS,
    ) -> Result<Self> {
        let mut startup_info: STARTUPINFOA = STARTUPINFOA::default();
        // set the size of the start up info to be the size of the struct.
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as _;

        let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();

        unsafe {
            // path to the target file that we create suspended.
            let path_cstring = std::ffi::CString::new(path.to_string_lossy().to_string()).unwrap();

            // basically a place holder since we can't use s!() macro here.
            let args = std::ffi::CString::new(args).unwrap();

            CreateProcessA(
                PCSTR::from_raw(path_cstring.as_ptr() as _),
                Some(windows::core::PSTR::from_raw(args.as_ptr() as _)),
                None,
                None,
                false,
                creation_flags,
                None,
                s!("C:\\"),
                &startup_info,
                &mut process_info,
            )?;
        }

        Ok(Self {
            handle: SafeHandle::new(process_info.hProcess),
            name: path.file_name().unwrap().to_string_lossy().to_string(),
            process_id: process_info.dwProcessId,
            extensions: HashMap::new(),
            _marker: std::marker::PhantomData,
        })
    }
}

impl<T> Process<T> {
    fn insert<U: 'static>(&mut self, value: U) {
        let type_id = TypeId::of::<U>();
        self.extensions.insert(type_id, Box::new(value));
    }

    pub fn get<U: 'static>(&self) -> Option<&U> {
        let type_id = TypeId::of::<U>();
        self.extensions
            .get(&type_id)
            .and_then(|boxed| boxed.downcast_ref::<U>())
    }

    /// Gets process id of the calling process.
    fn get_current_process_id() -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    /// Gets the full path of the process' binary, located on disk.
    pub fn get_full_path(&self) -> Result<PathBuf> {
        unsafe {
            // a buffer that holds the file location of the module.
            let mut module_path_buf: [u16; 4096] = [0; 4096];
            // copy the file name into the path buffer.
            GetModuleFileNameExW(Some(self.handle.get()?), None, &mut module_path_buf);
            // convert the path buffer into a String.
            let module_path = module_path_buf.to_string_null();

            // return the full path of the process.
            Ok(std::path::PathBuf::from(module_path))
        }
    }

    /// Kills the process, simple really.
    pub fn kill(self) -> Result<()> {
        unsafe {
            TerminateProcess(self.handle.get()?, 0)?;
        }
        std::mem::forget(self);
        Ok(())
    }

    pub fn suspend_process(&self) -> Result<()> {
        unsafe {
            NtSuspendProcess(self.handle.get()?.0 as _);
        }

        Ok(())
    }

    pub fn resume_process(&self) -> Result<()> {
        unsafe {
            NtResumeProcess(self.handle.get()?.0 as _);
        }
        Ok(())
    }

    /// Creates an allocation in the target process.
    pub fn virtual_alloc(
        &self,
        addr: Option<usize>,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<u64> {
        unsafe {
            // allocate virtual memory in the target address.
            // NOTE: the reason I use 'map' on `addr` is because I want to change the type of `Some(usize)` to `Some(*mut cvoid)`.
            let address = VirtualAllocEx(
                self.handle.get()?,
                addr.map(|v| v as _),
                size,
                MEM_RESERVE | MEM_COMMIT,
                protection,
            ) as usize;
            // if address is '0' (NULL), then virtual alloc failed.
            if address as *mut c_void == std::ptr::null_mut() {
                return Err(ProcessError::ProcessError(
                    "Failed to allocate memory.".to_string(),
                ));
            }
            Ok(address as u64)
        }
    }

    /// Set protection value to some place in target process memory.
    pub fn set_protection(
        &self,
        address: u64,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        unsafe {
            // old protection flags.
            let mut old_protection: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

            // set the protection values at a particular address to be a new value.
            VirtualProtectEx(
                self.handle.get()?,
                address as _,
                size as _,
                protection,
                &mut old_protection as _,
            )?;

            Ok(old_protection)
        }
    }

    /// Gets the memory regions allocated for a process.
    pub fn get_memory_regions(
        &self,
        mask: PAGE_PROTECTION_FLAGS,
    ) -> Result<Vec<MEMORY_BASIC_INFORMATION>> {
        // this will hold information about the current region.
        let mut info = MEMORY_BASIC_INFORMATION::default();
        // this will be the total regions found.
        let mut regions: Vec<MEMORY_BASIC_INFORMATION> = Vec::new();

        loop {
            // add the base address and the region size to base, so the next iteration will be another region.
            let base_addr = unsafe { info.BaseAddress.add(info.RegionSize) };

            let bytes_written = unsafe {
                VirtualQueryEx(
                    self.handle.get()?,
                    Some(base_addr),
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            // in this case there are no more regions.
            if bytes_written == 0 {
                break;
            }

            if (info.Protect & mask).0 != 0 {
                regions.push(info);
            }
        }

        Ok(regions)
    }

    /// Write a value `T` to an address in the target process.
    #[allow(unused)]
    pub fn write<U>(&self, addr: u64, value: U) -> Result<()> {
        unsafe {
            // NOTE: this uses the value `T`'s address as the buffer for writing.
            // NOTE: maybe you should check the length that was written and verify it's the sizeof `T`.
            WriteProcessMemory(
                self.handle.get()?,
                addr as _,
                &value as *const U as *const c_void,
                std::mem::size_of::<U>(),
                None,
            )?;

            Ok(())
        }
    }

    /// Write bytes to an address in the target process.
    pub fn write_bytes(&self, addr: u64, value: &[u8]) -> Result<()> {
        unsafe {
            // pointer to the buffer we want to write to the process.
            let buffer_pointer = value.as_ptr() as *const c_void;
            // NOTE: maybe you should check the length that was written and verify it's the sizeof `T`.
            WriteProcessMemory(
                self.handle.get()?,
                addr as _,
                buffer_pointer,
                std::mem::size_of_val(value),
                None,
            )?;

            Ok(())
        }
    }

    /// Reads, `len`, amount of bytes from the target process, stores it inside of a vector and returns it.
    pub fn read_bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        unsafe {
            // the buffer where we'll put the read contents.
            let mut buffer = vec![0; len as usize];
            // use readprocessmemory to read the contents of the processes memory.
            ReadProcessMemory(
                self.handle.get()?,
                addr as _,
                buffer.as_mut_ptr() as _,
                len as usize,
                None,
            )?;
            Ok(buffer)
        }
    }

    pub fn read<U>(&self, addr: u64) -> Result<U> {
        let bytes = self.read_bytes(addr, std::mem::size_of::<U>() as _)?;
        // turn the buffer of bytes into a T.
        Ok(unsafe { std::ptr::read(bytes.as_ptr() as *const _) })
    }

    pub fn create_remote_thread(
        &self,
        address: usize,
        creation_flags: Option<u32>,
        param: Option<*const c_void>,
    ) -> Result<SafeHandle> {
        unsafe {
            let handle = CreateRemoteThread(
                self.handle.get()?,
                None,
                0,
                Some(std::mem::transmute(address as usize)),
                param,
                creation_flags.unwrap_or(0),
                None,
            )?;

            Ok(SafeHandle::new(handle))
        }
    }

    pub fn get_modules(&self) -> ModuleIterator {
        ModuleIterator::new(self.process_id)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use pretty_assertions::assert_eq;
    use processes::snapshot::SnapshotState;
    use thread::ThreadOperations;
    use windows::Win32::System::{
        Memory::{
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
        },
        Threading::PROCESS_ALL_ACCESS,
    };

    #[test]
    fn process_handle_check() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        assert_eq!(process.handle.is_valid(), true);

        Ok(())
    }

    #[test]
    fn process_created_handle_check() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Created>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        assert_eq!(process.handle.is_valid(), true);

        Ok(())
    }

    #[test]
    fn process_attach_bespoke_data() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        // this is extra data added depending on the method.
        let bespoke = process.get::<SnapshotState>();

        assert_eq!(bespoke.is_some(), true);

        let threads = bespoke.unwrap().thread_count;

        assert_eq!(threads > 0, true);

        Ok(())
    }

    #[test]
    fn process_get_memory_regions() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        // just do some basic test here.
        let regions = process
            .get_memory_regions(PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE)?;

        assert_eq!(regions.len() > 0, true);

        Ok(())
    }

    #[test]
    fn process_get_process_path() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        // just do some basic test here.
        let path = process.get_full_path()?;

        assert_eq!(path.to_string_lossy().contains(".exe"), true);

        Ok(())
    }

    #[test]
    fn process_memory_methods_test() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        // this will actually allocate an entire page, read only.
        let addr = process.virtual_alloc(None, 1, PAGE_READONLY)?;

        // this will set the page to be able to be read and written to.
        process.set_protection(addr, 1, PAGE_READWRITE)?;

        process.write(addr, 1337 as usize)?;

        assert_eq!(process.read::<usize>(addr)?, 1337 as usize);

        Ok(())
    }

    #[test]
    fn process_find_module() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        // just do some basic test here.
        let module = process
            .get_modules()
            .find(|m| m.get_name().to_lowercase() == "kernel32.dll");

        assert_eq!(module.is_some(), true);

        Ok(())
    }

    #[test]
    fn process_snapshot_threads() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        // create the process object.
        let process = Process::<Snapshot>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        assert_eq!(
            process
                .get_threads()
                .all(|t| t.owner_process_id == process.process_id),
            true
        );

        Ok(())
    }

    #[test]
    fn process_nt_threads() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<NT>::get_current_process_id();

        // create the process object.
        let process = Process::<NT>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        assert_eq!(
            process
                .get_threads()
                .all(|t| t.owner_process_id == process.process_id),
            true
        );

        Ok(())
    }

    fn process_nt_thread_context() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<NT>::get_current_process_id();

        // create the process object.
        let process = Process::<NT>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

        // should always be at least one thread.
        let thread = process.get_threads().next().unwrap();

        // get the context of the thread.
        let context = thread.get_context()?;

        assert_eq!(context.0.Rsp > 0, true);

        Ok(())
    }
}
