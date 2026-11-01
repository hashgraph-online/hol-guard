//! Bounded reads of another process's image path and raw command line, for
//! the daemon ownership checks in `windows-process-command-lines --stdin`.

use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::QueryFullProcessImageNameW;
use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;

const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
/// The most one command-line query may ask Windows to fill.
const COMMAND_LINE_BUFFER_LIMIT_BYTES: usize = 128 * 1024;
const IMAGE_PATH_CHARS: usize = 32_768;

/// `UNICODE_STRING`, the header `ProcessCommandLineInformation` writes
/// ahead of the text it points into.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// Every process id in one snapshot of the process table, the idle
/// process's id 0 included.
pub fn process_ids() -> io::Result<Vec<u32>> {
    // SAFETY: Plain flag values; the returned handle is wrapped exactly once.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateToolhelp32Snapshot returned this handle exactly once.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as RawHandle) };
    // SAFETY: PROCESSENTRY32W is plain data; zero is a valid starting value.
    let mut entry = unsafe { zeroed::<PROCESSENTRY32W>() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as DWORD;
    let mut ids = Vec::new();
    // SAFETY: `snapshot` is live and `entry` carries its own size.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    while more != FALSE {
        ids.push(entry.th32ProcessID);
        // SAFETY: As above.
        more = unsafe { Process32NextW(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    }
    Ok(ids)
}

/// One process opened for limited queries only, the access a standard user
/// holds over its own processes.
pub struct ProcessQuery {
    process: OwnedHandle,
}

impl ProcessQuery {
    pub fn open(process_id: u32) -> io::Result<Self> {
        let process = super::open_process(process_id, PROCESS_QUERY_LIMITED_INFORMATION)?;
        Ok(Self { process })
    }

    /// The full path of the process's image, up to its first NUL.
    pub fn image_path(&self) -> Option<String> {
        let mut buffer = vec![0u16; IMAGE_PATH_CHARS];
        let mut size = buffer.len() as DWORD;
        // SAFETY: `process` owns a valid process handle, `buffer` holds `size`
        // writable UTF-16 units and `size` is initialized writable storage.
        if unsafe {
            QueryFullProcessImageNameW(
                self.process.as_raw_handle() as HANDLE,
                0,
                buffer.as_mut_ptr(),
                &mut size,
            )
        } == FALSE
        {
            return None;
        }
        buffer.truncate((size as usize).min(IMAGE_PATH_CHARS));
        if let Some(end) = buffer.iter().position(|unit| *unit == 0) {
            buffer.truncate(end);
        }
        Some(String::from_utf16_lossy(&buffer))
    }

    /// The raw command line as Windows records it, unstripped. `None` when
    /// it cannot be read, when Windows would need more than the bound
    /// `max_command_line_bytes` implies, when the header it writes does not
    /// describe text inside the buffer, or when the text is not UTF-16.
    pub fn command_line(&self, max_command_line_bytes: usize) -> Option<String> {
        let header_size = size_of::<UnicodeString>();
        let query_limit = COMMAND_LINE_BUFFER_LIMIT_BYTES.min(
            max_command_line_bytes
                .saturating_mul(2)
                .saturating_add(header_size + 2)
                .max(header_size),
        );
        let handle = self.process.as_raw_handle() as HANDLE;
        let mut required = 0u32;
        // SAFETY: A zero-length query with a null buffer only reports the
        // size it needs through `required`, which is writable storage.
        let _ = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        let required_bytes = required as usize;
        if !(header_size..=query_limit).contains(&required_bytes) {
            return None;
        }
        // Whole words keep the header Windows writes at the start aligned.
        let mut words = vec![0u64; required_bytes.div_ceil(size_of::<u64>())];
        // SAFETY: `words` holds at least `required_bytes` writable bytes for
        // the duration of the call and `required` is writable storage.
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                words.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        };
        if status != 0 {
            return None;
        }
        let raw_start = words.as_ptr() as usize;
        // SAFETY: The allocation is aligned for `UnicodeString`, at least
        // `header_size` bytes long and was initialized above.
        let header = unsafe { std::ptr::read(words.as_ptr().cast::<UnicodeString>()) };
        // SAFETY: The first `required_bytes` bytes of `words` are initialized
        // and stay borrowed only while `words` lives.
        let raw =
            unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), required_bytes) };
        command_line_text(raw, raw_start, &header)
    }
}

/// The text `header` describes, read from `raw` only when the header points
/// wholly inside it.
fn command_line_text(raw: &[u8], raw_start: usize, header: &UnicodeString) -> Option<String> {
    let length = usize::from(header.length);
    if length == 0 || length % 2 != 0 || length > usize::from(header.maximum_length) {
        return None;
    }
    let offset = (header.buffer as usize).checked_sub(raw_start)?;
    let text = raw.get(offset..offset.checked_add(length)?)?;
    let units: Vec<u16> = text
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_over(raw: &[u8], offset: usize, length: u16, maximum_length: u16) -> UnicodeString {
        UnicodeString {
            length,
            maximum_length,
            buffer: raw.as_ptr().wrapping_add(offset).cast(),
        }
    }

    fn utf16_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_ne_bytes).collect()
    }

    #[test]
    fn command_line_text_reads_only_inside_the_buffer() {
        let mut raw = vec![0u8; 16];
        raw.extend(utf16_bytes("py.exe -m x"));
        let start = raw.as_ptr() as usize;
        let length = (raw.len() - 16) as u16;
        let header = header_over(&raw, 16, length, length);
        assert_eq!(
            command_line_text(&raw, start, &header).as_deref(),
            Some("py.exe -m x")
        );
        let past_end = header_over(&raw, 18, length, length);
        assert_eq!(command_line_text(&raw, start, &past_end), None);
        let odd = header_over(&raw, 16, length - 1, length);
        assert_eq!(command_line_text(&raw, start, &odd), None);
        let over_maximum = header_over(&raw, 16, length, length - 2);
        assert_eq!(command_line_text(&raw, start, &over_maximum), None);
        let empty = header_over(&raw, 16, 0, length);
        assert_eq!(command_line_text(&raw, start, &empty), None);
        let before = UnicodeString {
            length,
            maximum_length: length,
            buffer: std::ptr::null(),
        };
        assert_eq!(command_line_text(&raw, start, &before), None);
    }

    #[test]
    fn command_line_text_refuses_unpaired_surrogates() {
        let mut raw = vec![0u8; 16];
        raw.extend(0xD800u16.to_ne_bytes());
        let start = raw.as_ptr() as usize;
        let header = header_over(&raw, 16, 2, 2);
        assert_eq!(command_line_text(&raw, start, &header), None);
    }

    #[test]
    fn reads_the_current_process() {
        let own = std::process::id();
        assert!(process_ids().unwrap().contains(&own));
        let query = ProcessQuery::open(own).unwrap();
        let image = query.image_path().unwrap();
        let exe = std::env::current_exe().unwrap();
        let exe_name = exe.file_name().unwrap().to_string_lossy().to_lowercase();
        assert!(image.to_lowercase().ends_with(&exe_name));
        let command_line = query.command_line(1024 * 1024).unwrap();
        assert!(!command_line.trim().is_empty());
        assert_eq!(query.command_line(1), None);
    }
}
