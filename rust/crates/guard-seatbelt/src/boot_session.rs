//! The boot session and continuous uptime the installation continuity record
//! compares leases against (`mdm/continuity.py` read them with ctypes).

use std::ffi::{c_char, c_int, c_void};
use std::ptr::null_mut;

const MAX_BOOT_SESSION_BYTES: usize = 256;

#[repr(C)]
#[derive(Default)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
    fn mach_continuous_time() -> u64;
}

/// `kern.bootsessionuuid` up to its terminator, or `None` when the kernel
/// does not answer or answers with more than 256 bytes.
pub fn boot_session_uuid() -> Option<Vec<u8>> {
    let name = c"kern.bootsessionuuid";
    let mut size = 0usize;
    // SAFETY: A null buffer only asks for the value's size, written to `size`.
    let sized = unsafe { sysctlbyname(name.as_ptr(), null_mut(), &mut size, null_mut(), 0) };
    if sized != 0 || size > MAX_BOOT_SESSION_BYTES {
        return None;
    }
    let mut buffer = vec![0u8; size];
    // SAFETY: `buffer` holds `size` writable bytes, the size passed in.
    let read = unsafe {
        sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut size,
            null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    buffer.truncate(size);
    if let Some(end) = buffer.iter().position(|byte| *byte == 0) {
        buffer.truncate(end);
    }
    Some(buffer)
}

/// `mach_continuous_time` in nanoseconds: it keeps counting while the
/// machine sleeps, so it only falls when the machine reboots.
pub fn continuous_uptime_ns() -> Option<u64> {
    let mut timebase = MachTimebaseInfo::default();
    // SAFETY: `timebase` is a writable `mach_timebase_info_data_t`.
    if unsafe { mach_timebase_info(&mut timebase) } != 0 || timebase.denom == 0 {
        return None;
    }
    // SAFETY: mach_continuous_time has no preconditions.
    let ticks = unsafe { mach_continuous_time() };
    u64::try_from(u128::from(ticks) * u128::from(timebase.numer) / u128::from(timebase.denom)).ok()
}
