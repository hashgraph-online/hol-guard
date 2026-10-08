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

mod launch;
mod owner;
#[path = "unix/io.rs"]
mod process_io;
use launch::{cstring, ChildSetup, LaunchDeadline, RequestWindow};
use owner::{require_wait_custody, ChildOwner};
#[cfg(target_os = "macos")]
use process_io::drain_report;
use process_io::{check_protocol_budget, drain, nonblocking, pipe, write_without_sigpipe};
#[cfg(test)]
#[path = "unix/process_regressions.rs"]
mod process_regressions;

pub(crate) fn capture(
    command: PinnedCommand,
    input: &[u8],
    cap: usize,
    deadline: Instant,
    cancel: &AtomicBool,
    isolation: Isolation,
) -> io::Result<CapturedOutput> {
    let window = RequestWindow { deadline, cancel };
    window.require_launch()?;
    command.verify_bindings()?;
    let argv: Vec<CString> = std::iter::once(command.executable_path.as_os_str())
        .chain(command.arguments.iter().map(|arg| arg.as_os_str()))
        .map(|arg| cstring(arg.as_bytes()))
        .collect::<io::Result<_>>()?;
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());
    let env = launch::environment(&command.environment)?;
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
    let (launch_read, launch_write) = pipe()?;
    nonblocking(&launch_write)?;
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
    let launch_fd =
        unsafe { libc::fcntl(launch_read.as_raw_fd(), libc::F_DUPFD_CLOEXEC, reserved) };
    if launch_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let launch_fd = unsafe { OwnedFd::from_raw_fd(launch_fd) };
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
    #[cfg(target_os = "macos")]
    let mut descriptors = supervisor::DescriptorTable::prepare()?;
    let launch_deadline = LaunchDeadline::prepare(deadline)?;
    #[cfg(test)]
    process_regressions::before_fork();
    require_wait_custody()?;
    window.require_launch()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let setup = ChildSetup {
            parent,
            cwd: command.cwd.handle().as_raw_fd(),
            stdin: stdin_read.as_raw_fd(),
            stdout: stdout_write.as_raw_fd(),
            stderr: stderr_write.as_raw_fd(),
            executable: exe_fd.as_raw_fd(),
            error: error_fd.as_raw_fd(),
            launch: launch_fd.as_raw_fd(),
            completion: if isolation.completion_report {
                Some(completion_write.as_raw_fd())
            } else {
                None
            },
            resources: resources.as_ref(),
            profile: profile.as_ref(),
            argv: &argv_ptr,
            env: &env_ptr,
            deadline: &launch_deadline,
            #[cfg(target_os = "linux")]
            inherited: &inherited,
            #[cfg(target_os = "macos")]
            descriptors: &mut descriptors,
            #[cfg(target_os = "macos")]
            report: foreign_report_write.as_raw_fd(),
            #[cfg(target_os = "macos")]
            image_path: &image_path,
        };
        unsafe {
            setup.exec();
        }
    }
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);
    drop(error_write);
    drop(error_fd);
    drop(exe_fd);
    drop(completion_write);
    drop(launch_read);
    drop(launch_fd);
    #[cfg(target_os = "macos")]
    drop(foreign_report_write);
    let mut owner = ChildOwner::new(pid);
    let mut launch_write = Some(launch_write);
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
    let mut protocol_limited = false;
    let mut status = None;
    loop {
        check_protocol_budget(protocol_limited)?;
        cancelled |= cancel.load(Ordering::Acquire);
        timed_out |= Instant::now() >= deadline;
        if cancelled || timed_out || output_limited {
            owner.kill_tree()?;
            if status.is_none() {
                status = Some(owner.reap()?);
            }
            stdin.take();
            launch_write.take();
        }
        if status.is_none() {
            status = owner.wait()?;
            if status.is_some() {
                owner.kill_tree()?;
                stdin.take();
                launch_write.take();
            }
        }
        #[cfg(target_os = "macos")]
        {
            drain_report(
                &mut foreign_report_fd,
                &mut foreign_report,
                &mut foreign_report_size,
                if status.is_some() {
                    None
                } else {
                    Some(&window)
                },
            )?;
            if foreign_report_size == 4 && status.is_none() {
                owner.kill_tree()?;
                status = Some(owner.reap()?);
                stdin.take();
                launch_write.take();
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
                None,
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
                None,
            )?;
            drain(
                &mut error_fd,
                &mut error_bytes,
                16,
                &mut protocol_limited,
                None,
            )?;
            drain(
                &mut completion_fd,
                &mut completion,
                8192,
                &mut protocol_limited,
                None,
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
        if window.stopped() {
            continue;
        }
        if offset == input.len() {
            stdin.take();
        }
        if let Some(fd) = &stdin {
            match write_without_sigpipe(fd.as_raw_fd(), &input[offset..]) {
                Ok(length) => offset += length,
                Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
                    stdin.take();
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
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
            Some(&window),
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
            Some(&window),
        )?;
        drain(
            &mut error_fd,
            &mut error_bytes,
            16,
            &mut protocol_limited,
            Some(&window),
        )?;
        drain(
            &mut completion_fd,
            &mut completion,
            8192,
            &mut protocol_limited,
            Some(&window),
        )?;
        #[cfg(target_os = "macos")]
        drain_report(
            &mut foreign_report_fd,
            &mut foreign_report,
            &mut foreign_report_size,
            Some(&window),
        )?;
        cancelled |= cancel.load(Ordering::Acquire);
        timed_out |= Instant::now() >= deadline;
        if cancelled || timed_out {
            continue;
        }
        if error_bytes.len() > 4
            || !error_bytes.is_empty()
                && error_bytes[..error_bytes.len().min(4)]
                    .iter()
                    .any(|byte| *byte != 0)
        {
            owner.kill_tree()?;
            if owner.has_custody() {
                owner.reap()?;
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native child initialization or execution failed",
            ));
        }
        if error_bytes == [0, 0, 0, 0] && !output_limited && status.is_none() {
            if let Some(fd) = &launch_write {
                #[cfg(test)]
                process_regressions::initialized();
                // Initialization may have consumed the request window. Never
                // approve execution using the cancellation snapshot from fork.
                if window.stopped() {
                    continue;
                }
                match write_without_sigpipe(fd.as_raw_fd(), &[1]) {
                    Ok(1) => {
                        launch_write.take();
                    }
                    Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                    Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
                        launch_write.take();
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    owner.kill_tree()?;
    if owner.has_custody() {
        owner.reap()?;
    }
    check_protocol_budget(protocol_limited)?;
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
    let code = code.filter(|_| !cancelled && !timed_out && !output_limited);
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

#[cfg(test)]
mod result_tests;
