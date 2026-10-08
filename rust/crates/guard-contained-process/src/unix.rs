use crate::{CapturedOutput, Isolation, PinnedCommand};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[path = "unix_image.rs"]
mod image;
#[cfg(target_os = "linux")]
pub(crate) use image::seal_bytes;
pub(crate) use image::seal_executable;
#[cfg(target_os = "macos")]
pub(crate) use image::PinnedImage;
#[path = "unix_resources.rs"]
pub(crate) mod resources;
pub(crate) use resources::process_ceiling;
#[cfg(target_os = "macos")]
#[path = "macos_supervisor.rs"]
mod supervisor;

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in process argument"))
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    #[cfg(not(target_os = "linux"))]
    for fd in [&read, &write] {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct ChildOwner {
    pid: libc::pid_t,
    reaped: bool,
}
impl ChildOwner {
    fn wait(&mut self) -> io::Result<Option<i32>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(io::Error::new(
                    error.kind(),
                    format!("waitid for native child: {error}"),
                ))
            };
        }
        #[cfg(target_os = "linux")]
        let (pid, status) = unsafe { (info.si_pid(), info.si_status()) };
        #[cfg(target_os = "macos")]
        let (pid, status) = (info.si_pid, info.si_status);
        if pid == 0 {
            return Ok(None);
        }
        Ok(Some(if info.si_code == libc::CLD_EXITED {
            status << 8
        } else {
            status & 0x7f
        }))
    }
    fn kill_tree(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let result = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("kill native process group: {error}"),
            ));
        }
        if !self.reaped {
            // Before setsid has completed the leader may not yet own a group.
            let result = unsafe { libc::kill(self.pid, libc::SIGKILL) };
            if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!("kill native child leader: {error}"),
                ));
            }
        }
        Ok(())
    }
    fn reap(&mut self) -> io::Result<i32> {
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                return Ok(status);
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_tree();
            let _ = self.reap();
        }
    }
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

#[cfg(target_os = "macos")]
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, error: *mut *mut libc::c_char)
        -> i32;
}

pub(crate) fn capture(
    command: PinnedCommand,
    input: &[u8],
    cap: usize,
    deadline: Instant,
    cancel: &AtomicBool,
    isolation: Isolation,
) -> io::Result<CapturedOutput> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "process deadline before launch",
        ));
    }
    command.verify_bindings()?;
    let argv: Vec<CString> = std::iter::once(command.executable_path.as_os_str())
        .chain(command.arguments.iter().map(|arg| arg.as_os_str()))
        .map(|arg| cstring(arg.as_bytes()))
        .collect::<io::Result<_>>()?;
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());
    let env: Vec<CString> = command
        .environment
        .iter()
        .map(|(key, value)| {
            if key.as_bytes().is_empty() || key.as_bytes().contains(&b'=') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid environment key",
                ));
            }
            let mut bytes = Vec::with_capacity(key.len() + value.len() + 1);
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            cstring(&bytes)
        })
        .collect::<io::Result<_>>()?;
    #[cfg(target_os = "macos")]
    let image_path = cstring(command.image.path.as_os_str().as_bytes())?;
    let mut env_ptr: Vec<*const libc::c_char> = env.iter().map(|entry| entry.as_ptr()).collect();
    env_ptr.push(std::ptr::null());
    let profile = isolation
        .seatbelt
        .as_ref()
        .map(|profile| cstring(profile.as_bytes()))
        .transpose()?;
    let resources = isolation
        .resources
        .map(|limits| resources::prepare(limits, isolation.node_virtual_address_space, false))
        .transpose()?;
    let (stdin_read, stdin_write) = pipe()?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    let (error_read, error_write) = pipe()?;
    let (completion_read, completion_write) = pipe()?;
    #[cfg(target_os = "macos")]
    let (foreign_report_read, foreign_report_write) = pipe()?;
    #[cfg(target_os = "macos")]
    nonblocking(&foreign_report_read)?;
    nonblocking(&completion_read)?;
    for fd in [&stdin_write, &stdout_read, &stderr_read, &error_read] {
        nonblocking(fd)?;
    }
    // Duplicate above the reserved child descriptors before dup2: inherited
    // descriptors can otherwise collide with the exec/status descriptors.
    #[cfg(target_os = "linux")]
    let reserved = i32::try_from(isolation.inherited_files.len())
        .map_err(|_| crate::bound_fs::changed())?
        .checked_add(6)
        .ok_or_else(crate::bound_fs::changed)?
        .max(10);
    #[cfg(not(target_os = "linux"))]
    let reserved = 10;
    let exe_fd = unsafe {
        libc::fcntl(
            command.executable.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            reserved,
        )
    };
    if exe_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let exe_fd = unsafe { OwnedFd::from_raw_fd(exe_fd) };
    let error_fd = unsafe { libc::fcntl(error_write.as_raw_fd(), libc::F_DUPFD_CLOEXEC, reserved) };
    if error_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let error_fd = unsafe { OwnedFd::from_raw_fd(error_fd) };
    #[cfg(target_os = "linux")]
    let inherited = isolation
        .inherited_files
        .iter()
        .map(|file| {
            let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, reserved) };
            if raw < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(raw) })
            }
        })
        .collect::<io::Result<Vec<_>>>()?;
    let parent = unsafe { libc::getpid() };
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(1024, i32::MAX as i64) as i32;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let err = error_fd.as_raw_fd();
        #[cfg(target_os = "macos")]
        unsafe {
            supervisor::enter(parent, err, foreign_report_write.as_raw_fd(), max_fd);
        }
        #[cfg(not(target_os = "macos"))]
        if unsafe { libc::setsid() } < 0 {
            unsafe {
                child_failure(err, 1);
            }
        }
        if unsafe { libc::fchdir(command.cwd.handle().as_raw_fd()) } != 0 {
            unsafe {
                child_failure(err, 1);
            }
        }
        if resources
            .as_ref()
            .is_some_and(|limits| !unsafe { resources::apply(limits) })
        {
            unsafe {
                child_failure(err, 8);
            }
        }
        #[cfg(target_os = "linux")]
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
            || unsafe { libc::getppid() } != parent
        {
            unsafe {
                child_failure(err, 2);
            }
        }
        if unsafe { libc::dup2(stdin_read.as_raw_fd(), 0) } < 0
            || unsafe { libc::dup2(stdout_write.as_raw_fd(), 1) } < 0
            || unsafe { libc::dup2(stderr_write.as_raw_fd(), 2) } < 0
        {
            unsafe {
                child_failure(err, 3);
            }
        }
        if unsafe { libc::dup2(exe_fd.as_raw_fd(), 3) } < 0 || unsafe { libc::dup2(err, 4) } < 0 {
            unsafe {
                child_failure(err, 4);
            }
        }
        unsafe {
            libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        if isolation.completion_report {
            if unsafe { libc::dup2(completion_write.as_raw_fd(), 5) } < 0 {
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
            for (index, file) in inherited.iter().enumerate() {
                if unsafe { libc::dup2(file.as_raw_fd(), 6 + index as i32) } < 0 {
                    unsafe {
                        child_failure(4, 9);
                    }
                }
            }
            let first = 6 + inherited.len() as u32;
            let result = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) };
            if result != 0 {
                for fd in first as i32..max_fd {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        for fd in 6..max_fd {
            unsafe {
                libc::close(fd);
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(profile) = &profile {
                let mut error = std::ptr::null_mut();
                if unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) } != 0 {
                    unsafe {
                        child_failure(4, 6);
                    }
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        if profile.is_some() {
            unsafe {
                child_failure(4, 6);
            }
        }
        // SIGPIPE is restored only in the child. Native daemon cancellation and
        // concurrent callers never mutate the parent's signal dispositions.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        let initialized = 0i32.to_ne_bytes();
        if unsafe { libc::write(4, initialized.as_ptr().cast(), initialized.len()) }
            != initialized.len() as isize
        {
            unsafe {
                libc::_exit(126);
            }
        }
        #[cfg(target_os = "linux")]
        unsafe {
            libc::fexecve(3, argv_ptr.as_ptr(), env_ptr.as_ptr());
        }
        #[cfg(target_os = "macos")]
        unsafe {
            libc::execve(image_path.as_ptr(), argv_ptr.as_ptr(), env_ptr.as_ptr());
        }
        unsafe {
            child_failure(4, 7);
        }
    }
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);
    drop(error_write);
    drop(error_fd);
    drop(exe_fd);
    drop(completion_write);
    #[cfg(target_os = "macos")]
    drop(foreign_report_write);
    let mut owner = ChildOwner { pid, reaped: false };
    let mut stdin = Some(stdin_write);
    let mut stdout_fd = Some(stdout_read);
    let mut stderr_fd = Some(stderr_read);
    let mut error_fd = Some(error_read);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut error_bytes = Vec::new();
    let mut completion_fd = Some(completion_read);
    let mut completion = Vec::new();
    #[cfg(target_os = "macos")]
    let mut foreign_report_fd = Some(foreign_report_read);
    #[cfg(target_os = "macos")]
    let mut foreign_report = [0u8; 4];
    #[cfg(target_os = "macos")]
    let mut foreign_report_size = 0usize;
    let mut offset = 0usize;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut output_limited = false;
    let mut status = None;
    loop {
        cancelled |= cancel.load(Ordering::Acquire);
        timed_out |= Instant::now() >= deadline;
        if cancelled || timed_out || output_limited {
            owner.kill_tree()?;
            if status.is_none() {
                status = Some(owner.reap()?);
            }
            stdin.take();
        }
        if status.is_none() {
            status = owner.wait()?;
            if status.is_some() {
                owner.kill_tree()?;
                stdin.take();
            }
        }
        #[cfg(target_os = "macos")]
        {
            drain_report(
                &mut foreign_report_fd,
                &mut foreign_report,
                &mut foreign_report_size,
            )?;
            if foreign_report_size == 4 && status.is_none() {
                owner.kill_tree()?;
                status = Some(owner.reap()?);
                stdin.take();
            }
        }
        if stdout_fd.is_none()
            && stderr_fd.is_none()
            && error_fd.is_none()
            && completion_fd.is_none()
            && status.is_some()
        {
            break;
        }
        if status.is_some() && (cancelled || timed_out || output_limited) {
            // Drain already-buffered bytes once after kill, never wait on an
            // escaped inherited pipe owner.
            drain(
                &mut stdout_fd,
                &mut stdout,
                if isolation.output_per_stream {
                    cap
                } else {
                    cap.saturating_sub(stderr.len())
                },
                &mut output_limited,
            )?;
            drain(
                &mut stderr_fd,
                &mut stderr,
                if isolation.output_per_stream {
                    cap
                } else {
                    cap.saturating_sub(stdout.len())
                },
                &mut output_limited,
            )?;
            drain(&mut error_fd, &mut error_bytes, 16, &mut output_limited)?;
            drain(
                &mut completion_fd,
                &mut completion,
                8192,
                &mut output_limited,
            )?;
            break;
        }
        let mut pollfds = [
            libc::pollfd {
                fd: stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: stdout_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: error_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: completion_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            #[cfg(target_os = "macos")]
            libc::pollfd {
                fd: foreign_report_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let remaining = deadline.saturating_duration_since(Instant::now());
        let milliseconds = remaining.as_millis().min(10) as i32;
        let result = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                milliseconds,
            )
        };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
        if offset == input.len() {
            stdin.take();
        }
        if let Some(fd) = &stdin {
            // Block SIGPIPE on this thread for the one write; no process-wide
            // signal changes. EPIPE is an ordinary child-closed-input outcome.
            let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGPIPE);
                libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous);
            }
            let length = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    input[offset..].as_ptr().cast(),
                    input.len() - offset,
                )
            };
            let error = io::Error::last_os_error();
            if length < 0 && error.raw_os_error() == Some(libc::EPIPE) {
                let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::sigpending(&mut pending);
                }
                if unsafe { libc::sigismember(&pending, libc::SIGPIPE) } == 1 {
                    let mut received = 0;
                    unsafe {
                        libc::sigwait(&mask, &mut received);
                    }
                }
            }
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
            if length >= 0 {
                offset += length as usize;
            } else if error.raw_os_error() == Some(libc::EPIPE) {
                stdin.take();
            } else if error.kind() != io::ErrorKind::WouldBlock
                && error.kind() != io::ErrorKind::Interrupted
            {
                return Err(error);
            }
        }
        drain(
            &mut stdout_fd,
            &mut stdout,
            if isolation.output_per_stream {
                cap
            } else {
                cap.saturating_sub(stderr.len())
            },
            &mut output_limited,
        )?;
        drain(
            &mut stderr_fd,
            &mut stderr,
            if isolation.output_per_stream {
                cap
            } else {
                cap.saturating_sub(stdout.len())
            },
            &mut output_limited,
        )?;
        drain(&mut error_fd, &mut error_bytes, 16, &mut output_limited)?;
        drain(
            &mut completion_fd,
            &mut completion,
            8192,
            &mut output_limited,
        )?;
        #[cfg(target_os = "macos")]
        drain_report(
            &mut foreign_report_fd,
            &mut foreign_report,
            &mut foreign_report_size,
        )?;
        if error_bytes.len() > 4
            || !error_bytes.is_empty()
                && error_bytes[..error_bytes.len().min(4)]
                    .iter()
                    .any(|byte| *byte != 0)
        {
            owner.kill_tree()?;
            if !owner.reaped {
                owner.reap()?;
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native child initialization or execution failed",
            ));
        }
    }
    owner.kill_tree()?;
    if !owner.reaped {
        owner.reap()?;
    }
    if error_bytes != [0, 0, 0, 0] && !cancelled && !timed_out {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native child did not confirm initialization",
        ));
    }
    #[cfg(target_os = "macos")]
    let status = if foreign_report_size == 4 {
        Some(i32::from_ne_bytes(foreign_report))
    } else if cancelled || timed_out || output_limited {
        None
    } else {
        return Err(io::Error::other(
            "native supervisor did not report foreign completion",
        ));
    };
    let code = status.and_then(|status| {
        if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Some(-libc::WTERMSIG(status))
        } else {
            None
        }
    });
    Ok(CapturedOutput {
        exit_code: code,
        stdout,
        stderr,
        timed_out,
        output_limited,
        cancelled,
        completion,
    })
}

#[cfg(target_os = "macos")]
fn drain_report(fd: &mut Option<OwnedFd>, bytes: &mut [u8; 4], used: &mut usize) -> io::Result<()> {
    let mut buffer = [0u8; 8];
    loop {
        let Some(handle) = fd.as_ref() else {
            return Ok(());
        };
        let count =
            unsafe { libc::read(handle.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count == 0 {
            fd.take();
            return Ok(());
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count as usize > bytes.len().saturating_sub(*used) {
            return Err(io::Error::other("invalid native foreign completion"));
        }
        bytes[*used..*used + count as usize].copy_from_slice(&buffer[..count as usize]);
        *used += count as usize;
    }
}

fn drain(
    fd: &mut Option<OwnedFd>,
    output: &mut Vec<u8>,
    cap: usize,
    limited: &mut bool,
) -> io::Result<()> {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let Some(handle) = fd.as_ref() else {
            break;
        };
        let length =
            unsafe { libc::read(handle.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if length == 0 {
            fd.take();
            break;
        }
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let keep = (length as usize).min(cap.saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..keep]);
        if keep < length as usize {
            *limited = true;
            break;
        }
    }
    Ok(())
}
