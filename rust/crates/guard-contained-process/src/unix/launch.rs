use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub(super) fn cstring(bytes: impl Into<Vec<u8>>) -> io::Result<CString> {
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in process argument"))
}

pub(super) fn environment(entries: &[(OsString, OsString)]) -> io::Result<Vec<CString>> {
    entries
        .iter()
        .map(|(key, value)| {
            if key.as_bytes().is_empty() || key.as_bytes().contains(&b'=') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid environment key",
                ));
            }
            let mut bytes = Vec::with_capacity(key.len() + value.len() + 2);
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            cstring(bytes)
        })
        .collect()
}

// Everything in the post-fork branch is prepared beforehand or is an
// async-signal-safe syscall. No Rust allocation, lock, formatting or Drop runs.
unsafe fn child_failure(error_fd: i32, code: i32) -> ! {
    let bytes = code.to_ne_bytes();
    unsafe {
        libc::write(error_fd, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(126);
    }
}

pub(super) struct RequestWindow<'a> {
    pub(super) deadline: Instant,
    pub(super) cancel: &'a AtomicBool,
}

impl RequestWindow<'_> {
    pub(super) fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }

    pub(super) fn require_launch(&self) -> io::Result<()> {
        if self.stopped() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process deadline or cancellation before launch",
            ));
        }
        Ok(())
    }
}

pub(super) struct LaunchDeadline(libc::timespec);

impl LaunchDeadline {
    pub(super) fn prepare(deadline: Instant) -> io::Result<Self> {
        let mut cutoff: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut cutoff) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Read the native clock first, so calibration can only shorten the
        // original deadline. The post-fork branch never calls Rust's clock API.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let overflow = || io::Error::new(io::ErrorKind::InvalidInput, "process deadline overflow");
        let seconds = libc::time_t::try_from(remaining.as_secs()).map_err(|_| overflow())?;
        cutoff.tv_sec = cutoff.tv_sec.checked_add(seconds).ok_or_else(overflow)?;
        cutoff.tv_nsec += remaining.subsec_nanos() as libc::c_long;
        if cutoff.tv_nsec >= 1_000_000_000 {
            cutoff.tv_nsec -= 1_000_000_000;
            cutoff.tv_sec = cutoff.tv_sec.checked_add(1).ok_or_else(overflow)?;
        }
        Ok(Self(cutoff))
    }

    pub(super) unsafe fn expired(&self) -> bool {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        (unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) }) != 0
            || now.tv_sec > self.0.tv_sec
            || now.tv_sec == self.0.tv_sec && now.tv_nsec >= self.0.tv_nsec
    }
}

pub(super) unsafe fn await_launch(gate: i32, error: i32, deadline: &LaunchDeadline) {
    let mut permission = 0u8;
    loop {
        if unsafe { deadline.expired() } {
            unsafe { child_failure(error, 10) };
        }
        let count = unsafe { libc::read(gate, (&mut permission as *mut u8).cast(), 1) };
        if count == 1 && permission == 1 {
            break;
        }
        if count < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        unsafe { child_failure(error, 10) };
    }
    // Parent approval is based on its current cancellation state, not the
    // AtomicBool snapshot inherited by fork. Check the native deadline again
    // immediately before exec; a racing cancellation after approval is not an
    // atomic cancellation-versus-exec guarantee.
    if unsafe { deadline.expired() } {
        unsafe { child_failure(error, 10) };
    }
}

/// Stack-only launch inputs; all owning handles and storage were prepared in
/// the daemon. Execution never returns or runs Rust destructors after fork.
pub(super) struct ChildSetup<'a> {
    pub(super) parent: libc::pid_t,
    pub(super) cwd: i32,
    pub(super) stdin: i32,
    pub(super) stdout: i32,
    pub(super) stderr: i32,
    pub(super) executable: i32,
    pub(super) error: i32,
    pub(super) launch: i32,
    pub(super) completion: Option<i32>,
    pub(super) resources: Option<&'a super::resources::Limits>,
    pub(super) profile: Option<&'a std::ffi::CString>,
    pub(super) argv: &'a [*const libc::c_char],
    pub(super) env: &'a [*const libc::c_char],
    pub(super) deadline: &'a LaunchDeadline,
    #[cfg(target_os = "linux")]
    pub(super) inherited: &'a [std::os::fd::OwnedFd],
    #[cfg(target_os = "macos")]
    pub(super) descriptors: &'a mut super::supervisor::DescriptorTable,
    #[cfg(target_os = "macos")]
    pub(super) report: i32,
    #[cfg(target_os = "macos")]
    pub(super) image_path: &'a std::ffi::CString,
}

#[cfg(target_os = "macos")]
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, error: *mut *mut libc::c_char)
        -> i32;
}

impl ChildSetup<'_> {
    pub(super) unsafe fn exec(self) -> ! {
        #[cfg(target_os = "linux")]
        use std::os::fd::AsRawFd;
        let err = self.error;
        if unsafe { self.deadline.expired() } || !unsafe { super::owner::reset_child_sigchld() } {
            unsafe {
                child_failure(err, 10);
            }
        }
        #[cfg(target_os = "macos")]
        unsafe {
            super::supervisor::enter(
                self.parent,
                err,
                self.report,
                self.descriptors,
                self.deadline,
            );
        }
        #[cfg(not(target_os = "macos"))]
        if unsafe { libc::setsid() } < 0 {
            unsafe {
                child_failure(err, 1);
            }
        }
        if unsafe { libc::fchdir(self.cwd) } != 0 {
            unsafe {
                child_failure(err, 1);
            }
        }
        if self
            .resources
            .is_some_and(|limits| !unsafe { super::resources::apply(limits) })
        {
            unsafe {
                child_failure(err, 8);
            }
        }
        #[cfg(target_os = "linux")]
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
            || unsafe { libc::getppid() } != self.parent
        {
            unsafe {
                child_failure(err, 2);
            }
        }
        if unsafe { libc::dup2(self.stdin, 0) } < 0
            || unsafe { libc::dup2(self.stdout, 1) } < 0
            || unsafe { libc::dup2(self.stderr, 2) } < 0
        {
            unsafe {
                child_failure(err, 3);
            }
        }
        // dup2(source, source) preserves FD_CLOEXEC, including a pipe that
        // occupied a closed parent stdin. Explicitly make all stdio survive.
        for target in 0..3 {
            if unsafe { libc::fcntl(target, libc::F_SETFD, 0) } != 0 {
                unsafe {
                    child_failure(err, 3);
                }
            }
        }
        if unsafe { libc::dup2(self.executable, 3) } < 0 || unsafe { libc::dup2(err, 4) } < 0 {
            unsafe {
                child_failure(err, 4);
            }
        }
        if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
            || unsafe { libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
        {
            unsafe {
                child_failure(4, 4);
            }
        }
        if let Some(completion) = self.completion {
            if unsafe { libc::dup2(completion, 5) } < 0 {
                unsafe {
                    child_failure(4, 8);
                }
            }
        } else {
            unsafe {
                libc::close(5);
            }
        }
        #[cfg(target_os = "linux")]
        {
            for (index, file) in self.inherited.iter().enumerate() {
                if unsafe { libc::dup2(file.as_raw_fd(), 6 + index as i32) } < 0 {
                    unsafe {
                        child_failure(4, 9);
                    }
                }
            }
            let first = 6 + self.inherited.len() as u32;
            let gate = self.launch as u32;
            // Keep the already-open CLOEXEC gate above the reserved targets.
            // Duplicating it into a new low target would raise the existing
            // minimum RLIMIT_NOFILE required for initialization.
            if gate < first
                || first < gate
                    && unsafe { libc::syscall(libc::SYS_close_range, first, gate - 1, 0u32) } != 0
                || unsafe { libc::syscall(libc::SYS_close_range, gate + 1, u32::MAX, 0u32) } != 0
            {
                // No soft/hard-limit fallback: existing descriptors may remain
                // above either limit after it has been lowered.
                unsafe {
                    child_failure(4, 9);
                }
            }
        }
        #[cfg(target_os = "macos")]
        if !unsafe {
            self.descriptors
                .close_except(&[0, 1, 2, 3, 4, 5, self.launch])
        } {
            unsafe {
                child_failure(4, 9);
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(profile) = self.profile {
            let mut error = std::ptr::null_mut();
            if unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) } != 0 {
                unsafe {
                    child_failure(4, 6);
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        if self.profile.is_some() {
            unsafe {
                child_failure(4, 6);
            }
        }
        // Only the child's disposition changes, never the daemon's.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        if unsafe { self.deadline.expired() } {
            unsafe {
                child_failure(4, 10);
            }
        }
        let initialized = 0i32.to_ne_bytes();
        if unsafe { libc::write(4, initialized.as_ptr().cast(), initialized.len()) }
            != initialized.len() as isize
        {
            unsafe {
                libc::_exit(126);
            }
        }
        unsafe {
            await_launch(self.launch, 4, self.deadline);
        }
        #[cfg(target_os = "linux")]
        unsafe {
            libc::fexecve(3, self.argv.as_ptr(), self.env.as_ptr());
        }
        #[cfg(target_os = "macos")]
        unsafe {
            libc::execve(
                self.image_path.as_ptr(),
                self.argv.as_ptr(),
                self.env.as_ptr(),
            );
        }
        unsafe {
            child_failure(4, 7);
        }
    }
}
