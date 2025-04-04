use ntapi::ntexapi::{
    NtQuerySystemInformation, SystemProcessInformation, SYSTEM_PROCESS_INFORMATION,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NtIteratorError {
    #[error("NtQuerySystemInformation has failed (Error: {0:X?}).")]
    QuerySystemError(i32),
}

/// Wrapper for native windows process.
pub struct NtProcessState {
    pub raw: SYSTEM_PROCESS_INFORMATION,
    _buffer: Vec<u8>,
    _ptr: *const SYSTEM_PROCESS_INFORMATION,
    _old_ptr: *const SYSTEM_PROCESS_INFORMATION,
    // not strictly needed but is nice.
    _final: bool,
}

impl NtProcessState {
    /// This is only here so we can utilize the iterator.
    pub fn iter() -> Result<Self, NtIteratorError> {
        // the size needed in total for every process and thread.
        let mut size_required = 0;

        // buffer for the process information structs.
        let mut buffer: Vec<u8> = Vec::new();

        unsafe {
            // get the size required.
            // NOTE: there need not be error checking, because if this fails the second one will
            // fail, so we'll just check if that fails, though checking here'll be more granular.
            NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_ptr() as _,
                size_required,
                &mut size_required as _,
            );
        }

        // resize the buffer to fit the requirements.
        // I add extra bytes to the end just because of the way we iterate.
        buffer.resize(size_required as usize + 1, 0);

        // this time the return value of this function is important to us.
        let query_system_status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_ptr() as _,
                buffer.len() as _,
                &mut size_required as _,
            )
        };

        if query_system_status != 0 {
            return Err(NtIteratorError::QuerySystemError(query_system_status));
        }

        // cast the buffer address as a pointer to a `SYSTEM_PROCESS_INFORMATION`.
        let process_information_ptr: *const SYSTEM_PROCESS_INFORMATION =
            unsafe { std::mem::transmute(buffer.as_ptr()) };

        Ok(Self {
            _buffer: buffer,
            _ptr: process_information_ptr,
            _final: false,
            _old_ptr: process_information_ptr,
            raw: unsafe { *process_information_ptr },
        })
    }

    /// Gets the name of the process.
    pub fn get_name(&self) -> String {
        // get the unicode string.
        let unicode_string = self.raw.ImageName;

        if unicode_string.Buffer == std::ptr::null_mut() {
            return String::new();
        }

        let byte_slice = unsafe {
            std::slice::from_raw_parts(
                unicode_string.Buffer as *const u8,
                unicode_string.Length as usize,
            )
        };

        // realign the list of u8s to a list of u16s.
        let (_, slice, _) = unsafe { byte_slice.align_to::<u16>() };

        String::from_utf16(slice).unwrap_or_default()
    }

    /// gets the pointer that points to the current process obj in the buffer.
    pub fn get_pointer_to_slot(&self) -> *const SYSTEM_PROCESS_INFORMATION {
        self._old_ptr
    }
}

impl Iterator for NtProcessState {
    type Item = Self;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            // The reason we need this is that if we don't have this when we can't know whether or
            // not we are on the last process, of course there's other things we could like check
            // whether or not certain values are 0 but this feels a bit more "canonical".
            if self._final == true {
                return None;
            }

            // iterate through each entry, stop if the next entry is NULL.
            if (*self._ptr).NextEntryOffset == 0 {
                // this indicates that we are on the final entry.
                self._final = true;
            }

            // deref the system process info pointer so we can access the struct.
            let process_information: SYSTEM_PROCESS_INFORMATION = *self._ptr;

            // save the current pointer so we can reference the raw process object later.
            self._old_ptr = self._ptr.clone();

            // set the process information pointer to an offset in the buffer, where the next entry is located.
            self._ptr =
                (self._ptr as *const u8).offset(process_information.NextEntryOffset as _) as _;

            Some(Self {
                _buffer: self._buffer.clone(),
                _ptr: self._ptr,
                _old_ptr: self._old_ptr,
                _final: self._final,
                raw: process_information,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use pretty_assertions::assert_eq;
    use windows::Win32::System::Threading::GetCurrentProcessId;

    #[test]
    fn find_current_process() -> Result<(), NtIteratorError> {
        // get the current process id.
        let current_pid = unsafe { GetCurrentProcessId() };

        // find our process through querying the system.
        let target = NtProcessState::iter()?.find(|p| p.raw.UniqueProcessId as u32 == current_pid);

        assert_eq!(target.is_some(), true);

        Ok(())
    }
}
