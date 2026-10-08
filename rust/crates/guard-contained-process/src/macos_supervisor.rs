//! Native session/group leader. Foreign code is only the child; it cannot
//! signal this parent or change its inherited group under the child profile.
//! The requesting daemon kills the still-live leader before reaping it.

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
pub(super) unsafe fn enter(parent: libc::pid_t, error: i32, report: i32, max_fd: i32) {
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
    for fd in 0..max_fd {
        if fd != queue && fd != report {
            unsafe {
                libc::close(fd);
            }
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
