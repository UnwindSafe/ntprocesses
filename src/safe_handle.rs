use thiserror::Error;
use windows::Win32::Foundation::{GetHandleInformation, HANDLE};

#[derive(Error, Debug)]
pub enum HandleError {
    #[error("Handle ({0:X?}) has either become invalid or was always invalid. ")]
    Invalid(u64),
}

pub struct SafeHandle {
    raw_handle: HANDLE,
}

impl SafeHandle {
    /// Create a new safe handle from a raw handle.
    /// This handle can only be used if it's valid.
    pub fn new(raw_handle: HANDLE) -> Self {
        Self { raw_handle }
    }

    /// This will call a winapi function on our current handle.
    /// If the function succeeds it means our handle must be valid.
    pub fn is_valid(&self) -> bool {
        // check here before doing anything heavier.
        if self.raw_handle.is_invalid() {
            return false;
        }

        unsafe {
            let mut flags: u32 = 0;
            match GetHandleInformation(self.raw_handle, &mut flags) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
    }

    /// Access the interior handle after it's been verified.
    ///
    /// Anything that can touch the handle can be sure that it's valid.
    pub fn get(&self) -> Result<HANDLE, HandleError> {
        if !self.is_valid() {
            return Err(HandleError::Invalid(self.raw_handle.0 as _));
        }

        Ok(self.raw_handle)
    }
}

// Allow any u64 value to turn into a handle.
impl From<u64> for SafeHandle {
    fn from(value: u64) -> Self {
        SafeHandle::new(HANDLE(value as _))
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn handle_valid() {
        // this handle should always fail.
        let safe_handle_1 = SafeHandle::new(HANDLE(0x0 as _));

        // this handle should always fail.
        let safe_handle_2 = SafeHandle::new(HANDLE(0x1337 as _));

        assert_eq!(safe_handle_1.is_valid(), false);
        assert_eq!(safe_handle_2.is_valid(), false);
    }
}
