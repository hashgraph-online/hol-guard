//! Native session/group leader. Foreign code is only the child; it cannot
//! signal this parent or change its inherited group under the child profile.
//! The requesting daemon kills the still-live leader before reaping it.

use super::launch::LaunchDeadline;
use std::io;
use std::mem::{size_of, MaybeUninit};

/// Allocated and the libproc syscall wrapper resolved before the daemon forks.
/// The child refreshes its own single-threaded table; concurrent parent opens
/// therefore cannot silently escape an earlier parent snapshot.
pub(super) struct DescriptorTable {
    buffer: Vec<MaybeUninit<libc::proc_fdinfo>>,
    bytes: i32,
}

impl DescriptorTable {
    pub(super) fn prepare() -> io::Result<Self> {
        let bytes = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if bytes <= 0 {
            return Err(io::Error::last_os_error());
        }
        let entry_size = size_of::<libc::proc_fdinfo>();
        let entries = (bytes as usize)
            .checked_div(entry_size)
            .and_then(|count| count.checked_add(16))
            .ok_or_else(crate::bound_fs::changed)?;
        let bytes = entries
            .checked_mul(entry_size)
            .and_then(|bytes| i32::try_from(bytes).ok())
            .ok_or_else(crate::bound_fs::changed)?;
        let mut table = Self {
            buffer: Vec::with_capacity(entries),
            bytes,
        };
        if unsafe { table.snapshot() }.is_none() {
            return Err(io::Error::other("incomplete native descriptor enumeration"));
        }
        Ok(table)
    }

    unsafe fn snapshot(&mut self) -> Option<usize> {
        // proc_pidinfo's warmed wrapper only invokes __proc_info and handles
        // errno. No allocation, directory iteration or limit lookup after fork.
        let bytes = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                self.buffer.as_mut_ptr().cast(),
                self.bytes,
            )
        };
        let entry_size = size_of::<libc::proc_fdinfo>();
        if bytes <= 0 || bytes >= self.bytes || bytes as usize % entry_size != 0 {
            return None;
        }
        Some(bytes as usize / entry_size)
    }

    unsafe fn close_snapshot(&self, count: usize, keep: &[i32]) -> bool {
        let entries = unsafe {
            std::slice::from_raw_parts(self.buffer.as_ptr().cast::<libc::proc_fdinfo>(), count)
        };
        for entry in entries {
            if entry.proc_fd < 0 {
                return false;
            }
            if !keep.contains(&entry.proc_fd) && unsafe { libc::close(entry.proc_fd) } != 0 {
                return false;
            }
        }
        true
    }

    pub(super) unsafe fn close_except(&mut self, keep: &[i32]) -> bool {
        let Some(count) = (unsafe { self.snapshot() }) else {
            return false;
        };
        unsafe { self.close_snapshot(count, keep) }
    }
}

unsafe fn terminate_group() -> ! {
    // The supervisor itself is the live group leader, so no recycled PID or
    // request-supplied process identity selects the group to kill.
    unsafe {
        libc::kill(0, libc::SIGKILL);
        libc::_exit(126);
    }
}
unsafe fn failure(error: i32, code: i32) -> ! {
    let bytes = code.to_ne_bytes();
    unsafe {
        libc::write(error, bytes.as_ptr().cast(), bytes.len());
        terminate_group();
    }
}
unsafe fn complete(child: libc::pid_t, report: i32) {
    let mut status = 0i32;
    loop {
        let result = unsafe { libc::waitpid(child, &mut status, 0) };
        if result == child {
            break;
        }
        if result < 0 && unsafe { *libc::__error() } == libc::EINTR {
            continue;
        }
        unsafe {
            terminate_group();
        }
    }
    let bytes = status.to_ne_bytes();
    // Keep the leader live until the daemon kills the group. Killing ourselves
    // here leaves a zombie-only Darwin group which cannot be signalled.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        if libc::write(report, bytes.as_ptr().cast(), bytes.len()) != bytes.len() as isize {
            terminate_group();
        }
    }
}

/// Called after the daemon's fork, before any foreign code. Returns only in the
/// foreign child. Uses stack values and syscalls only; never runs Rust Drop.
pub(super) unsafe fn enter(
    parent: libc::pid_t,
    error: i32,
    report: i32,
    descriptors: &mut DescriptorTable,
    deadline: &LaunchDeadline,
) {
    if unsafe { libc::setsid() } < 0 {
        unsafe {
            failure(error, 5);
        }
    }
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        unsafe {
            failure(error, 5);
        }
    }
    let mut event: libc::kevent = unsafe { std::mem::zeroed() };
    event.ident = parent as libc::uintptr_t;
    event.filter = libc::EVFILT_PROC;
    event.flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT;
    event.fflags = libc::NOTE_EXIT;
    if unsafe { libc::kevent(queue, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } != 0
        || unsafe { libc::getppid() } != parent
    {
        unsafe {
            failure(error, 5);
        }
    }
    let Some(descriptor_count) = (unsafe { descriptors.snapshot() }) else {
        unsafe {
            failure(error, 9);
        }
    };
    if unsafe { deadline.expired() } {
        unsafe {
            failure(error, 10);
        }
    }
    let child = unsafe { libc::fork() };
    if child < 0 {
        unsafe {
            failure(error, 5);
        }
    }
    if child == 0 {
        unsafe {
            libc::close(queue);
            libc::close(report);
        }
        return;
    }
    // The supervisor must not keep foreign stdio/initialization/executable pins
    // alive. Its sole private evidence channel cannot be written by foreign code.
    if !unsafe { descriptors.close_snapshot(descriptor_count, &[queue, report]) } {
        unsafe {
            failure(error, 9);
        }
    }
    event.ident = child as libc::uintptr_t;
    if unsafe { libc::kevent(queue, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } != 0 {
        let mut status = 0;
        if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
            let bytes = status.to_ne_bytes();
            unsafe {
                libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                if libc::write(report, bytes.as_ptr().cast(), bytes.len()) != bytes.len() as isize {
                    terminate_group();
                }
            }
        } else {
            unsafe {
                terminate_group();
            }
        }
    }
    loop {
        let result =
            unsafe { libc::kevent(queue, std::ptr::null(), 0, &mut event, 1, std::ptr::null()) };
        if result > 0 {
            if event.ident == parent as libc::uintptr_t {
                unsafe {
                    terminate_group();
                }
            }
            if event.ident == child as libc::uintptr_t {
                unsafe {
                    complete(child, report);
                }
            }
        } else if result < 0 && unsafe { *libc::__error() } != libc::EINTR {
            unsafe {
                terminate_group();
            }
        }
    }
}
