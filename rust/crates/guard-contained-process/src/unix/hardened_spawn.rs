use crate::{macos_code_image::Binding, PinnedCommand};
use std::ffi::CString;
use std::io;

#[cfg(test)]
thread_local! {
    static RESUME_PROBE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn enable_resume_probe() {
    RESUME_PROBE.with(|enabled| {
        assert!(
            !enabled.replace(true),
            "hardened resume probe already enabled"
        );
    });
}

struct Attributes(libc::posix_spawnattr_t);

impl Attributes {
    fn prepare() -> io::Result<Self> {
        let mut attributes = std::ptr::null_mut();
        let initialized = unsafe { libc::posix_spawnattr_init(&mut attributes) };
        if initialized != 0 {
            return Err(io::Error::from_raw_os_error(initialized));
        }
        let result = unsafe {
            libc::posix_spawnattr_setflags(
                &mut attributes,
                libc::POSIX_SPAWN_START_SUSPENDED as libc::c_short,
            )
        };
        if result != 0 {
            unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(Self(attributes))
    }

    fn raw(&self) -> &libc::posix_spawnattr_t {
        &self.0
    }
}

pub(super) struct Prepared {
    binding: Binding,
    attributes: Attributes,
    #[cfg(test)]
    resume_probe: bool,
}

impl Prepared {
    pub(super) fn prepare(command: &PinnedCommand) -> io::Result<Self> {
        #[cfg(test)]
        let resume_probe = RESUME_PROBE.with(|enabled| enabled.replace(false));
        Ok(Self {
            binding: command.hardened_binding()?,
            attributes: Attributes::prepare()?,
            #[cfg(test)]
            resume_probe,
        })
    }

    pub(super) fn binding(&self) -> Binding {
        self.binding
    }

    pub(super) fn attributes(&self) -> &libc::posix_spawnattr_t {
        self.attributes.raw()
    }

    #[cfg(test)]
    pub(super) fn resume_probe(&self) -> bool {
        self.resume_probe
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

unsafe fn fail(error_fd: i32, child: libc::pid_t, code: i32) -> ! {
    if child > 0 {
        unsafe {
            libc::kill(child, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(child, &mut status, 0) < 0 && *libc::__error() == libc::EINTR {}
        }
    }
    let bytes = code.to_ne_bytes();
    unsafe {
        libc::write(error_fd, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(126);
    }
}

unsafe fn propagate(status: i32) -> ! {
    if libc::WIFEXITED(status) {
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
    }
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, signal);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::kill(libc::getpid(), signal);
            libc::_exit(128 + signal);
        }
    }
    unsafe { libc::_exit(126) }
}

/// The caller is already the sandboxed foreign child with its final cwd,
/// descriptors, limits and output files. It becomes a small native owner for
/// one suspended hardened image and mirrors that image's terminal status.
///
/// Returns the suspended child, or the negated failure code: `1000 + errno`
/// when `posix_spawn` fails, 12 when the deadline passes, and otherwise the
/// [`dynamic_mismatch`](crate::macos_code_image::dynamic_mismatch) code.
pub(super) unsafe fn spawn(
    path: &CString,
    argv: &[*const libc::c_char],
    env: &[*const libc::c_char],
    attributes: &libc::posix_spawnattr_t,
    binding: Binding,
    deadline: &super::launch::LaunchDeadline,
) -> libc::pid_t {
    // This process exits with the child, so the request reaches nothing else.
    unsafe { crate::macos_code_image::harden_next_exec() };
    let mut child = 0;
    let spawned = unsafe {
        libc::posix_spawn(
            &mut child,
            path.as_ptr(),
            std::ptr::null(),
            attributes,
            argv.as_ptr().cast(),
            env.as_ptr().cast(),
        )
    };
    if spawned != 0 {
        return -(1000 + spawned);
    }
    let mismatch = if unsafe { deadline.expired() } {
        12
    } else {
        unsafe { crate::macos_code_image::dynamic_mismatch(child, binding) }
    };
    if mismatch != 0 {
        unsafe {
            libc::kill(child, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(child, &mut status, 0) < 0 && *libc::__error() == libc::EINTR {}
        }
        return -mismatch;
    }
    child
}

pub(super) unsafe fn release_and_wait(
    child: libc::pid_t,
    gate: i32,
    error_fd: i32,
    deadline: &super::launch::LaunchDeadline,
    binding: Binding,
    #[cfg(test)] resume_probe: bool,
) -> ! {
    if child <= 0 {
        // Report the failed check so a refused launch names its cause.
        unsafe { fail(error_fd, 0, if child < 0 { -child } else { 12 }) };
    }
    let initialized = 0i32.to_ne_bytes();
    if unsafe { libc::write(error_fd, initialized.as_ptr().cast(), initialized.len()) }
        != initialized.len() as isize
    {
        unsafe { fail(error_fd, child, 13) };
    }
    let mut permission = 0u8;
    loop {
        if unsafe { deadline.expired() } {
            unsafe { fail(error_fd, child, 13) };
        }
        let count = unsafe { libc::read(gate, (&mut permission as *mut u8).cast(), 1) };
        if count == 1 && permission == 1 {
            break;
        }
        if count < 0 && unsafe { *libc::__error() } == libc::EINTR {
            continue;
        }
        unsafe { fail(error_fd, child, 13) };
    }
    if unsafe { deadline.expired() }
        || !unsafe { crate::macos_code_image::dynamic_matches(child, binding) }
    {
        unsafe { fail(error_fd, child, 14) };
    }
    #[cfg(test)]
    if resume_probe {
        let marker = [1u8];
        let mut released = [0u8];
        if unsafe { libc::write(6, marker.as_ptr().cast(), marker.len()) } != 1
            || unsafe { libc::read(6, released.as_mut_ptr().cast(), released.len()) } != 1
            || released != marker
        {
            unsafe { fail(error_fd, child, 14) };
        }
    }
    if unsafe { libc::kill(child, libc::SIGCONT) } != 0 {
        unsafe { fail(error_fd, child, 14) };
    }
    unsafe { libc::close(error_fd) };
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            if libc::WIFSTOPPED(status) {
                unsafe {
                    libc::ptrace(libc::PT_KILL, child, std::ptr::null_mut(), 0);
                    libc::kill(child, libc::SIGKILL);
                    libc::kill(child, libc::SIGCONT);
                }
                continue;
            }
            unsafe { propagate(status) };
        }
        if waited < 0 && unsafe { *libc::__error() } == libc::EINTR {
            continue;
        }
        unsafe { libc::_exit(126) };
    }
}
