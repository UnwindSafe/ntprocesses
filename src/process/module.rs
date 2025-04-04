use crate::WindowsString;
use std::path::PathBuf;

use windows::Win32::{
    Foundation::HANDLE,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    },
};

/// Represents a loaded module in a process.
#[derive(Debug, Clone)]
pub struct Module {
    pub module_id: u32,
    pub process_id: u32,
    pub global_usage_count: u32,
    pub process_usage_count: u32,
    pub address: u64,
    pub size: u32,
    pub module_name: [u16; 256],
    pub executable_path: [u16; 260],
}

impl Module {
    pub fn get_name(&self) -> String {
        self.module_name.to_string_null()
    }

    pub fn get_path(&self) -> PathBuf {
        PathBuf::from(self.executable_path.to_string_null())
    }
}

pub struct ModuleIterator {
    _snapshot: HANDLE,
    process_id: u32,
}

impl ModuleIterator {
    pub fn new(process_id: u32) -> Self {
        Self {
            _snapshot: HANDLE(0 as _),
            process_id,
        }
    }
}

impl Iterator for ModuleIterator {
    type Item = Module;

    fn next(&mut self) -> Option<Self::Item> {
        // create a mutable empty processentry32 struct so that it can be written to when iterating over processes.
        let mut module_info = MODULEENTRY32W::default();

        // set the size of the structure before using it.
        module_info.dwSize = std::mem::size_of::<MODULEENTRY32W>() as _;

        unsafe {
            // this means that we haven't created the snapshot.
            if self._snapshot == HANDLE(0 as _) {
                // if we can't create a handle then return none.
                self._snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.process_id)
                {
                    Ok(handle) => handle,
                    Err(_) => return None,
                };

                // write the information of the first process in the snapshot to `process_info`.
                let _ = Module32FirstW(self._snapshot, &mut module_info);
            } else {
                // write the information of the next process o the process info struct.
                if (!Module32NextW(self._snapshot, &mut module_info).is_ok()).into() {
                    return None;
                }
            }
        }

        Some(Module {
            module_id: module_info.th32ModuleID,
            process_id: module_info.th32ProcessID,
            global_usage_count: module_info.GlblcntUsage,
            process_usage_count: module_info.ProccntUsage,
            address: module_info.modBaseAddr as _,
            size: module_info.modBaseSize,
            module_name: module_info.szModule,
            executable_path: module_info.szExePath,
        })
    }
}
