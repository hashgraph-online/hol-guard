use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;

use winapi::shared::winerror::ERROR_MORE_DATA;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::sysinfoapi::{ComputerNamePhysicalDnsHostname, GetComputerNameExW};

/// Return the computer's DNS host name the way Python's `socket.gethostname()`
/// (and so `platform.node()`) reads it: the physical DNS host name, not the
/// upper-cased, 15-character NetBIOS name `COMPUTERNAME` holds.
pub fn dns_host_name() -> Option<OsString> {
    let mut size: u32 = 0;
    // SAFETY: A null buffer with a zero size only asks for the required size,
    // which is written to `size`.
    let sized =
        unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, null_mut(), &mut size) };
    // SAFETY: GetLastError has no preconditions.
    if sized != 0 || unsafe { GetLastError() } != ERROR_MORE_DATA || size == 0 {
        return None;
    }
    let mut buffer = vec![0u16; usize::try_from(size).ok()?];
    // SAFETY: `buffer` holds `size` UTF-16 units, the size the first call
    // asked for, including the terminator.
    let read = unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if read == 0 {
        return None;
    }
    // On success `size` counts the units written, without the terminator.
    buffer.truncate(usize::try_from(size).ok()?);
    Some(OsString::from_wide(&buffer))
}

#[cfg(test)]
mod tests {
    use super::dns_host_name;

    #[test]
    fn the_dns_host_name_is_read_whole() {
        let name = dns_host_name().expect("the computer has a DNS host name");
        let name = name.to_string_lossy();
        assert!(!name.is_empty());
        assert!(!name.contains('\0'));
    }
}
