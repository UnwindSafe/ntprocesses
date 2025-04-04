use windows::Win32::{
    Foundation::HANDLE,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    },
};

#[derive(Debug, PartialEq)]
/// Wrapper for native windows process.
pub struct SnapshotState {
    pub process_id: u32,
    pub thread_count: u32,
    pub parent_process_id: u32,
    pub base_priority_level: i32,
    file_name_buffer: [u16; 260],
    _snapshot: HANDLE,
}

impl SnapshotState {
    /// This is only here so we can utilize the iterator.
    pub fn iter() -> Self {
        Self {
            process_id: 0,
            thread_count: 0,
            parent_process_id: 0,
            base_priority_level: 0,
            file_name_buffer: [0; 260],
            _snapshot: HANDLE(0 as _),
        }
    }

    /// Gets the name of the process.
    pub fn get_name(&self) -> String {
        // find the position of the first null character.
        let null_pos = self
            .file_name_buffer
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.file_name_buffer.len());

        // Take the slice up to (but not including) the null terminator
        let string_data = &self.file_name_buffer[0..null_pos];

        // Convert the UTF-16 data to a String
        String::from_utf16_lossy(string_data)
    }
}

impl Iterator for SnapshotState {
    type Item = Self;

    fn next(&mut self) -> Option<Self::Item> {
        // create a mutable empty processentry32 struct so that it can be written to when iterating over processes.
        let mut process_info = PROCESSENTRY32W::default();

        // set the size of the structure before using it.
        process_info.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as _;

        unsafe {
            // this means that we haven't created the snapshot.
            if self._snapshot == HANDLE(0 as _) {
                // if we can't create a handle then return none.
                self._snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(handle) => handle,
                    Err(_) => return None,
                };

                // write the information of the first process in the snapshot to `process_info`.
                let _ = Process32FirstW(self._snapshot, &mut process_info);
            } else {
                // write the information of the next process o the process info struct.
                if (!Process32NextW(self._snapshot, &mut process_info).is_ok()).into() {
                    return None;
                }
            }
        }

        Some(Self {
            process_id: process_info.th32ProcessID,
            thread_count: process_info.cntThreads,
            parent_process_id: process_info.th32ParentProcessID,
            base_priority_level: process_info.pcPriClassBase,
            file_name_buffer: process_info.szExeFile,
            _snapshot: HANDLE(0 as _),
        })
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use pretty_assertions::assert_eq;
    use windows::Win32::System::Threading::GetCurrentProcessId;

    #[test]
    fn find_current_process() -> () {
        // get the current process id.
        let current_pid = unsafe { GetCurrentProcessId() };

        // find our process through querying the system.
        let target = SnapshotState::iter().find(|p| p.process_id as u32 == current_pid);

        assert_eq!(target.is_some(), true);
    }
}
