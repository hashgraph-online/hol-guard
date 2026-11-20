//! The firmware boot identifier and tick count the installation continuity
//! record compares leases against (`mdm/continuity.py` read them with ctypes).

use std::ffi::c_void;
use std::mem::size_of;

use winapi::um::sysinfoapi::GetTickCount64;

/// `SystemBootEnvironmentInformation`.
const SYSTEM_BOOT_ENVIRONMENT_INFORMATION: u32 = 90;

/// `SYSTEM_BOOT_ENVIRONMENT_INFORMATION`: the identifier GUID's raw bytes,
/// then the firmware type and boot flags this crate never reads.
#[repr(C)]
#[derive(Default)]
struct BootEnvironment {
    identifier: [u8; 16],
    _firmware_type: u32,
    _boot_flags: u64,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// The boot identifier GUID as its 16 in-memory (little-endian) bytes, or
/// `None` when the kernel refuses the query.
pub fn boot_identifier() -> Option<[u8; 16]> {
    let mut information = BootEnvironment::default();
    let mut returned = 0u32;
    // SAFETY: `information` is a writable SYSTEM_BOOT_ENVIRONMENT_INFORMATION
    // of exactly the length passed.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION,
            (&mut information as *mut BootEnvironment).cast(),
            size_of::<BootEnvironment>() as u32,
            &mut returned,
        )
    };
    (status == 0).then_some(information.identifier)
}

/// Milliseconds since boot, sleep included.
pub fn tick_count_ms() -> u64 {
    // SAFETY: GetTickCount64 has no preconditions.
    unsafe { GetTickCount64() }
}
