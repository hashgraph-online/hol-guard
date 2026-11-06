//! A private window station and desktop for each AppContainer launch.
//!
//! An LPAC token cannot open the session's window station, so an image that
//! links user32 (node.exe does, python.exe does not) fails to start with
//! STATUS_DLL_INIT_FAILED. The child instead gets a new window station holding
//! one desktop that only this user and the run's container SID can open, so it
//! never reaches the user's desktop, clipboard or global atoms.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;

const GENERIC_ALL: u32 = 0x1000_0000;
// Window station: enumerate, read/write attributes, clipboard, create
// desktops, global atoms and read screen; never exit windows, delete or
// rewrite the security descriptor.
const STATION_RIGHTS: u32 = 0x0002_033f;
// Desktop: every desktop-specific right plus read control.
const DESKTOP_RIGHTS: u32 = 0x0002_01ff;

// CreateDesktopW places the desktop on the calling process's window station,
// so creation briefly switches it. Serialize that switch within the process.
static SWITCH: Mutex<()> = Mutex::new(());
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[link(name = "user32")]
unsafe extern "system" {
    fn CreateWindowStationW(
        name: *const u16,
        flags: u32,
        access: u32,
        attributes: *mut SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    fn CreateDesktopW(
        name: *const u16,
        device: *const u16,
        mode: *mut std::ffi::c_void,
        flags: u32,
        access: u32,
        attributes: *mut SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    fn GetProcessWindowStation() -> HANDLE;
    fn SetProcessWindowStation(station: HANDLE) -> i32;
    fn CloseWindowStation(station: HANDLE) -> i32;
    fn CloseDesktop(desktop: HANDLE) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: PSID, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut PSECURITY_DESCRIPTOR,
        size: *mut u32,
    ) -> i32;
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    fn GetTokenInformation(
        token: HANDLE,
        class: u32,
        information: *mut std::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> HANDLE;
}

struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) struct PrivateDesktop {
    station: HANDLE,
    desktop: HANDLE,
    /// `station\desktop`, NUL-terminated, for `STARTUPINFO.lpDesktop`.
    pub(super) path: Vec<u16>,
}

impl PrivateDesktop {
    pub(super) fn create(container: PSID) -> io::Result<Self> {
        let user = user_sid()?;
        let container = sid_string(container)?;
        let station_name = format!(
            "HolGuard-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let station_security = descriptor(&user, &container, STATION_RIGHTS)?;
        let desktop_security = descriptor(&user, &container, DESKTOP_RIGHTS)?;
        let mut station_attributes = attributes(&station_security);
        let mut desktop_attributes = attributes(&desktop_security);
        let station_wide = wide(OsStr::new(&station_name))?;
        let station = unsafe {
            CreateWindowStationW(
                station_wide.as_ptr(),
                0,
                GENERIC_ALL,
                &mut station_attributes,
            )
        };
        if station.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut created = Self {
            station,
            desktop: null_mut(),
            path: wide(OsStr::new(&format!("{station_name}\\Default")))?,
        };
        let desktop_name = wide(OsStr::new("Default"))?;
        let _switch = SWITCH.lock().unwrap_or_else(PoisonError::into_inner);
        let original = unsafe { GetProcessWindowStation() };
        if original.is_null() || unsafe { SetProcessWindowStation(station) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Dropping `created` closes the private station, and that fails while
        // the process is still standing on it. Declared after `created`, this
        // drops first and so hands the process back its own station on every
        // path out. The explicit restoration below still runs first, so its
        // error stays the one reported.
        let mut restored = Restored {
            station: original,
            done: false,
        };
        created.desktop = unsafe {
            CreateDesktopW(
                desktop_name.as_ptr(),
                null_mut(),
                null_mut(),
                0,
                GENERIC_ALL,
                &mut desktop_attributes,
            )
        };
        let desktop_error = io::Error::last_os_error();
        if unsafe { SetProcessWindowStation(original) } == 0 {
            return Err(io::Error::last_os_error());
        }
        restored.done = true;
        if created.desktop.is_null() {
            return Err(desktop_error);
        }
        Ok(created)
    }
}

/// The process's own window station, put back when creation returns early.
/// Creation switches the process onto the private station so `CreateDesktopW`
/// places the desktop there; leaving it switched would both close the user's
/// own station out of reach and keep the private one open.
struct Restored {
    station: HANDLE,
    done: bool,
}

impl Drop for Restored {
    fn drop(&mut self) {
        if !self.done {
            unsafe { SetProcessWindowStation(self.station) };
        }
    }
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        unsafe {
            if !self.desktop.is_null() {
                CloseDesktop(self.desktop);
            }
            CloseWindowStation(self.station);
        }
    }
}

fn attributes(descriptor: &Local) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

/// Owner and full control for this user, the listed rights for the container
/// (an AppContainer access check needs both), nothing inherited, and a low
/// label so the low-integrity child is not denied write access.
fn descriptor(user: &str, container: &str, rights: u32) -> io::Result<Local> {
    let text = format!(
        "O:{user}D:P(A;;GA;;;SY)(A;;GA;;;{user})(A;;{rights:#x};;;{container})S:(ML;;NW;;;LW)"
    );
    let text = wide(OsStr::new(&text))?;
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Local(descriptor))
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _text = Local(text.cast());
    let length = (0..)
        .take_while(|&index| unsafe { *text.add(index) } != 0)
        .count();
    let value = unsafe { std::slice::from_raw_parts(text, length) };
    Ok(String::from_utf16_lossy(value))
}

fn user_sid() -> io::Result<String> {
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER: u32 = 1;
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut buffer = vec![0usize; 64];
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TOKEN_USER,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * size_of::<usize>()) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_USER begins with the user's SID_AND_ATTRIBUTES.
    sid_string(buffer[0] as PSID)
}
