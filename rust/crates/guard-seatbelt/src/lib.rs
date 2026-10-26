//! Minimal macOS seatbelt binding for Guard's native containment workers.
//!
//! A `sandbox-exec` profile can deny `network*`, but it cannot deny
//! `process-exec`: the wrapper applies the profile to itself and then calls
//! `execvp`, so any profile that denied exec would prevent the target binary
//! from starting at all. Applying seatbelt inside the already-running worker
//! removes that limitation — this crate exists so the FFI stays small, single
//! purpose, and outside the `unsafe_code = "forbid"` workspace lints that keep
//! the decision crates auditable.
//!
//! `sandbox_init` refuses to nest: inside an existing sandbox it fails with
//! `EPERM`, so callers must invoke the worker unwrapped and let this profile
//! be the only seatbelt application in the process.

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    extern "C" {
        /// `sandbox_init(profile, flags, errorbuf)` from libSystem. With
        /// `flags == 0` the profile argument is an SBPL string (a named
        /// profile would need `SANDBOX_NAMED`). Deprecated by Apple but ABI
        /// stable and still the mechanism `sandbox-exec` itself uses.
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    /// Apply an SBPL profile to the current process. Returns false when the
    /// kernel/libsandbox rejects the profile; the caller must then fail
    /// closed rather than run unconfined.
    pub fn apply(profile: &str) -> bool {
        let Ok(profile) = CString::new(profile) else {
            return false;
        };
        unsafe {
            let mut error: *mut c_char = std::ptr::null_mut();
            let applied = sandbox_init(profile.as_ptr(), 0, &mut error) == 0;
            if !error.is_null() {
                sandbox_free_error(error);
            }
            applied
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    /// Seatbelt is a Darwin mechanism; other platforms must provide their own
    /// containment layer (Linux uses seccomp) or refuse the operation.
    pub fn apply(_profile: &str) -> bool {
        false
    }
}

pub use imp::apply;
