use super::*;

pub(super) fn system_shared_cache(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        if !path.starts_with("/usr/lib") && !path.starts_with("/System/Library") {
            return false;
        }
        let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // Query dyld's actual cache, not a pathname prefix. Resolve the symbol
        // dynamically so older supported macOS releases retain disk lookup.
        type ContainsPath = unsafe extern "C" fn(*const libc::c_char) -> bool;
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"_dyld_shared_cache_contains_path".as_ptr(),
            )
        };
        if symbol.is_null() {
            return false;
        }
        // SAFETY: Apple's dyld.h declares precisely this C signature. The
        // process-owned symbol and the NUL-terminated path outlive the call.
        let contains: ContainsPath = unsafe { std::mem::transmute(symbol) };
        unsafe { contains(path.as_ptr()) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

pub(super) fn system_library(path: &Path) -> bool {
    #[cfg(windows)]
    return crate::windows::system_directory().is_ok_and(|root| path.starts_with(root));
    #[cfg(not(windows))]
    system_shared_cache(path)
}
