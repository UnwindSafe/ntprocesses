pub mod process;
pub mod processes;
pub mod safe_handle;

pub trait WindowsString {
    fn to_string_null(&self) -> String;
}

impl WindowsString for [u16] {
    fn to_string_null(&self) -> String {
        // find the position of the first null character.
        let null_pos = self.iter().position(|&c| c == 0).unwrap_or(self.len());

        // Take the slice up to (but not including) the null terminator
        let string_data = &self[0..null_pos];

        // Convert the UTF-16 data to a String
        String::from_utf16_lossy(string_data)
    }
}
