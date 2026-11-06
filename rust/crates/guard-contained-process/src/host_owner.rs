//! Ephemeral host supervision, deliberately outside stable consent identity.

use std::cell::Cell;
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

const INVALID: &str = "host_process_owner_unavailable";

#[derive(PartialEq, Eq)]
struct Identity {
    pid: u32,
    started: (u64, u64),
    image: PathBuf,
}

pub struct HostOwner {
    queue: OwnedFd,
    lost: Cell<bool>,
}

fn process(pid: u32) -> Result<libc::proc_bsdinfo, String> {
    let pid = i32::try_from(pid).map_err(|_| INVALID)?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return Err(INVALID.into());
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid as u32
        || info.pbi_status == libc::SZOMB
        || info.pbi_uid != unsafe { libc::geteuid() }
    {
        return Err(INVALID.into());
    }
    Ok(info)
}

fn image(pid: u32) -> Result<PathBuf, String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let read =
        unsafe { libc::proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if read <= 0 || read as usize >= buffer.len() {
        return Err(INVALID.into());
    }
    buffer.truncate(read as usize);
    if let Some(end) = buffer.iter().position(|byte| *byte == 0) {
        buffer.truncate(end);
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buffer)))
}

fn nearest_host(names: &[&str]) -> Result<Identity, String> {
    let mut pid = unsafe { libc::getppid() } as u32;
    for _ in 0..32 {
        if pid <= 1 {
            break;
        }
        let info = process(pid)?;
        let image = image(pid)?;
        if image
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| names.contains(&name))
        {
            return Ok(Identity {
                pid,
                image,
                started: (info.pbi_start_tvsec, info.pbi_start_tvusec),
            });
        }
        if info.pbi_ppid == pid {
            break;
        }
        pid = info.pbi_ppid;
    }
    Err(INVALID.into())
}

impl HostOwner {
    /// Observe the nearest matching current ancestor, independently of consent.
    pub fn observe(pid: u32, names: &[&str]) -> Result<Self, String> {
        if pid <= 1
            || pid > i32::MAX as u32
            || pid == std::process::id()
            || names.is_empty()
            || names.len() > 8
            || names.iter().any(|name| name.is_empty() || name.len() > 80)
        {
            return Err(INVALID.into());
        }
        // The helper's PID is only a locator. Native ancestry/image inspection
        // selects the nearest host; an immortal or unrelated PID cannot win.
        let identity = nearest_host(names)?;
        if identity.pid != pid {
            return Err(INVALID.into());
        }
        let owner = Self::arm(pid)?;
        // Arm before rechecking identity/ancestry, closing the exit/PID-reuse
        // window. Later exit or exec is a kernel event, not kill(pid, 0).
        if nearest_host(names)? != identity || !owner.is_alive() {
            return Err(INVALID.into());
        }
        Ok(owner)
    }

    fn arm(pid: u32) -> Result<Self, String> {
        let descriptor = unsafe { libc::kqueue() };
        if descriptor < 0 {
            return Err(INVALID.into());
        }
        let queue = unsafe { OwnedFd::from_raw_fd(descriptor) };
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(INVALID.into());
        }
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        event.ident = pid as libc::uintptr_t;
        event.filter = libc::EVFILT_PROC;
        event.flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT;
        event.fflags = libc::NOTE_EXIT | libc::NOTE_EXEC;
        if unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(INVALID.into());
        }
        Ok(Self {
            queue,
            lost: Cell::new(false),
        })
    }

    /// Exit, exec and observation failure are terminal for this watch.
    pub fn is_alive(&self) -> bool {
        if self.lost.get() {
            return false;
        }
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                std::ptr::null(),
                0,
                &mut event,
                1,
                &timeout,
            )
        };
        let alive = result == 0
            || (result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR));
        self.lost.set(!alive);
        alive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_self_and_unrelated_processes_cannot_be_host_owners() {
        for pid in [0, 1, u32::MAX, std::process::id()] {
            assert!(HostOwner::observe(pid, &["bun", "node"]).is_err());
        }
        let mut unrelated = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert!(HostOwner::observe(unrelated.id(), &["bun", "node"]).is_err());
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }

    #[test]
    fn kernel_exit_observation_remains_lost_after_the_event_is_consumed() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let owner = HostOwner::arm(child.id()).unwrap();
        assert!(owner.is_alive());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!owner.is_alive());
        assert!(!owner.is_alive());
    }

    #[test]
    fn kernel_exec_observation_cancels_while_the_pid_is_still_running() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read token; exec /bin/sleep 30"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let owner = HostOwner::arm(child.id()).unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.is_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let observed_exec = !owner.is_alive();
        let still_running = child.try_wait().unwrap().is_none();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(observed_exec);
        assert!(still_running);
        assert!(!owner.is_alive());
    }
}
