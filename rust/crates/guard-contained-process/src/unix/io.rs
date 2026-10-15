use super::launch::RequestWindow;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(super) fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
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

pub(super) fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn write_without_sigpipe(fd: i32, input: &[u8]) -> io::Result<usize> {
    // Only this thread's mask changes; the daemon's signal dispositions do not.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGPIPE);
    }
    let blocked = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous) };
    if blocked != 0 {
        return Err(io::Error::from_raw_os_error(blocked));
    }
    let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
    let pending_result = unsafe { libc::sigpending(&mut pending) };
    let pending_error = io::Error::last_os_error();
    let already_pending = unsafe { libc::sigismember(&pending, libc::SIGPIPE) } == 1;
    let result = if pending_result != 0 {
        Err(pending_error)
    } else {
        let length = unsafe { libc::write(fd, input.as_ptr().cast(), input.len()) };
        if length >= 0 {
            Ok(length as usize)
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPIPE) && !already_pending {
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
            Err(error)
        }
    };
    let restored =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    if restored != 0 {
        return Err(io::Error::from_raw_os_error(restored));
    }
    result
}

#[cfg(target_os = "macos")]
pub(super) fn drain_report(
    fd: &mut Option<OwnedFd>,
    bytes: &mut [u8; 4],
    used: &mut usize,
    window: Option<&RequestWindow<'_>>,
) -> io::Result<()> {
    let mut buffer = [0u8; 8];
    for _ in 0..4 {
        if window.is_some_and(RequestWindow::stopped) {
            break;
        }
        let Some(handle) = fd.as_ref() else {
            break;
        };
        let count =
            unsafe { libc::read(handle.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count == 0 {
            fd.take();
            break;
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                break;
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
    Ok(())
}

pub(super) fn drain(
    fd: &mut Option<OwnedFd>,
    output: &mut Vec<u8>,
    cap: usize,
    limited: &mut bool,
    window: Option<&RequestWindow<'_>>,
) -> io::Result<()> {
    let mut buffer = [0u8; 16 * 1024];
    // A continuously ready stream (or repeated EINTR) cannot monopolize one
    // turn: at most four reads / 64 KiB before the owner checks all streams.
    for _ in 0..4 {
        if window.is_some_and(RequestWindow::stopped) {
            break;
        }
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

pub(super) fn check_protocol_budget(exceeded: bool) -> std::io::Result<()> {
    if exceeded {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native process protocol byte budget exceeded",
        ))
    } else {
        Ok(())
    }
}
