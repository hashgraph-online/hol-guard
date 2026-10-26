use std::ffi::c_void;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const CS_VALID: u32 = 0x0000_0001;
const CS_HARD: u32 = 0x0000_0100;
const CS_KILL: u32 = 0x0000_0200;
const CS_ENFORCEMENT: u32 = 0x0000_1000;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_INVALID_ALLOWED: u32 = 0x0000_0020;
const CS_DEBUGGED: u32 = 0x1000_0000;
const REQUIRED_DYNAMIC: u32 = CS_VALID | CS_HARD | CS_KILL | CS_ENFORCEMENT | CS_RUNTIME;
const FORBIDDEN_DYNAMIC: u32 = CS_INVALID_ALLOWED | CS_DEBUGGED;
const CS_EXEC_SET_HARD: u32 = 0x0010_0000;
const CS_EXEC_SET_KILL: u32 = 0x0020_0000;
const CS_EXEC_SET_ENFORCEMENT: u32 = 0x0040_0000;
const CS_OPS_SET_STATUS: u32 = 9;

const SEC_CHECK_ALL_ARCHITECTURES: u32 = 1 << 0;
const SEC_STRICT_VALIDATE: u32 = 1 << 4;
const SEC_NO_NETWORK_ACCESS: u32 = 1 << 29;
const CF_NUMBER_SINT64: isize = 4;

type CfType = *const c_void;
type CfDictionary = *const c_void;
type SecStaticCode = *mut c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        is_directory: u8,
    ) -> *const c_void;
    fn CFRelease(value: CfType);
    fn CFGetTypeID(value: CfType) -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFDataGetLength(value: *const c_void) -> isize;
    fn CFDataGetBytePtr(value: *const c_void) -> *const u8;
    fn CFNumberGetTypeID() -> usize;
    fn CFNumberGetValue(value: *const c_void, kind: isize, output: *mut c_void) -> u8;
    fn CFDictionaryContainsKey(dictionary: CfDictionary, key: *const c_void) -> u8;
    fn CFDictionaryGetValue(dictionary: CfDictionary, key: *const c_void) -> *const c_void;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoUnique: *const c_void;
    static kSecCodeInfoFlags: *const c_void;
    static kSecCodeInfoEntitlements: *const c_void;
    static kSecCodeInfoEntitlementsDict: *const c_void;
    fn SecStaticCodeCreateWithPath(
        path: *const c_void,
        flags: u32,
        code: *mut SecStaticCode,
    ) -> i32;
    fn SecStaticCodeCheckValidity(
        code: SecStaticCode,
        flags: u32,
        requirement: *const c_void,
    ) -> i32;
    fn SecCodeCopySigningInformation(
        code: SecStaticCode,
        flags: u32,
        information: *mut CfDictionary,
    ) -> i32;
    fn csops(pid: libc::pid_t, operation: u32, address: *mut c_void, size: usize) -> i32;
}

#[derive(Clone, Copy)]
pub(crate) struct Binding {
    pub(crate) cdhash: [u8; 20],
}

fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "macOS hardened code-image binding unavailable",
    )
}

pub(crate) fn static_binding(path: &Path) -> io::Result<Binding> {
    let bytes = path.as_os_str().as_bytes();
    let length = isize::try_from(bytes.len()).map_err(|_| rejected())?;
    let url = unsafe {
        CFURLCreateFromFileSystemRepresentation(std::ptr::null(), bytes.as_ptr(), length, 0)
    };
    if url.is_null() {
        return Err(rejected());
    }
    let mut code = std::ptr::null_mut();
    let created = unsafe { SecStaticCodeCreateWithPath(url, 0, &mut code) };
    unsafe { CFRelease(url) };
    if created != 0 || code.is_null() {
        return Err(rejected());
    }
    let validity = unsafe {
        SecStaticCodeCheckValidity(
            code,
            SEC_CHECK_ALL_ARCHITECTURES | SEC_STRICT_VALIDATE | SEC_NO_NETWORK_ACCESS,
            std::ptr::null(),
        )
    };
    let mut information = std::ptr::null();
    let copied = if validity == 0 {
        unsafe { SecCodeCopySigningInformation(code, 0, &mut information) }
    } else {
        -1
    };
    unsafe { CFRelease(code) };
    if copied != 0 || information.is_null() {
        return Err(rejected());
    }
    let result = unsafe { read_binding(information) };
    unsafe { CFRelease(information) };
    result
}

unsafe fn read_binding(information: CfDictionary) -> io::Result<Binding> {
    if unsafe { CFDictionaryContainsKey(information, kSecCodeInfoEntitlements) } != 0
        || unsafe { CFDictionaryContainsKey(information, kSecCodeInfoEntitlementsDict) } != 0
    {
        return Err(rejected());
    }
    let unique = unsafe { CFDictionaryGetValue(information, kSecCodeInfoUnique) };
    let number = unsafe { CFDictionaryGetValue(information, kSecCodeInfoFlags) };
    let mut flags = 0i64;
    if unique.is_null()
        || number.is_null()
        || unsafe { CFGetTypeID(unique) } != unsafe { CFDataGetTypeID() }
        || unsafe { CFDataGetLength(unique) } != 20
        || unsafe { CFGetTypeID(number) } != unsafe { CFNumberGetTypeID() }
        || unsafe { CFNumberGetValue(number, CF_NUMBER_SINT64, (&mut flags as *mut i64).cast()) }
            == 0
        || flags < 0
        || flags > i64::from(u32::MAX)
        || flags as u32 & CS_RUNTIME == 0
    {
        return Err(rejected());
    }
    let mut cdhash = [0u8; 20];
    let source = unsafe { CFDataGetBytePtr(unique) };
    if source.is_null() {
        return Err(rejected());
    }
    unsafe { std::ptr::copy_nonoverlapping(source, cdhash.as_mut_ptr(), cdhash.len()) };
    Ok(Binding { cdhash })
}

/// Asks the kernel to mark every image this process executes from now on as
/// hard, kill and enforced. Newer macOS releases already apply these to a
/// hardened-runtime image, but macOS 14 leaves them off unless the spawning
/// process requests them. The call only adds restrictions, and
/// [`dynamic_mismatch`] still decides whether the child may run, so a refused
/// request just leaves that check to reject the image. Makes only a system
/// call, so it is safe in a forked child.
pub(crate) unsafe fn harden_next_exec() {
    let mut flags = CS_EXEC_SET_HARD | CS_EXEC_SET_KILL | CS_EXEC_SET_ENFORCEMENT;
    unsafe {
        csops(
            0,
            CS_OPS_SET_STATUS,
            (&mut flags as *mut u32).cast(),
            size_of::<u32>(),
        );
    }
}

pub(crate) unsafe fn dynamic_matches(pid: libc::pid_t, binding: Binding) -> bool {
    unsafe { dynamic_mismatch(pid, binding) == 0 }
}

/// Zero when the running image still matches `binding`. Otherwise a code naming
/// the failed check: `2000 + errno` or `3000 + errno` when reading the flags or
/// the cdhash fails, `0x4000_0000 | flags` when the signing flags are wrong,
/// and 15 when the cdhash differs. Makes only system calls, so it is safe in a
/// forked child.
pub(crate) unsafe fn dynamic_mismatch(pid: libc::pid_t, binding: Binding) -> i32 {
    let mut flags = 0u32;
    let mut cdhash = [0u8; 20];
    if unsafe { csops(pid, 0, (&mut flags as *mut u32).cast(), size_of::<u32>()) } != 0 {
        return 2000 + unsafe { *libc::__error() };
    }
    if unsafe { csops(pid, 5, cdhash.as_mut_ptr().cast(), cdhash.len()) } != 0 {
        return 3000 + unsafe { *libc::__error() };
    }
    if flags & REQUIRED_DYNAMIC != REQUIRED_DYNAMIC || flags & FORBIDDEN_DYNAMIC != 0 {
        return 0x4000_0000 | (flags & 0x3fff_ffff) as i32;
    }
    if cdhash != binding.cdhash {
        return 15;
    }
    0
}
