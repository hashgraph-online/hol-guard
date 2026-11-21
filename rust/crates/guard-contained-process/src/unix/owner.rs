use std::io;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Custody {
    Owned,
    Reaped,
    Lost,
}

pub(super) struct ChildOwner {
    pid: libc::pid_t,
    custody: Custody,
}

impl ChildOwner {
    pub(super) fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            custody: Custody::Owned,
        }
    }

    pub(super) fn has_custody(&self) -> bool {
        self.custody == Custody::Owned
    }

    pub(super) fn wait(&mut self) -> io::Result<Option<i32>> {
        if !self.has_custody() {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
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
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.custody = Custody::Lost;
            }
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(error)
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

    pub(super) fn kill_tree(&mut self) -> io::Result<()> {
        if !self.has_custody() {
            return Ok(());
        }
        // Notice custody already lost before signalling. This check cannot
        // prevent a concurrent external reaper: callers must exclusively own
        // waits and keep SIGCHLD non-autoreaping for the entire capture.
        self.wait()?;
        let result = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        // Before setsid has completed the leader may not yet own a group.
        let result = unsafe { libc::kill(self.pid, libc::SIGKILL) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn reap(&mut self) -> io::Result<i32> {
        if !self.has_custody() {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.custody = Custody::Reaped;
                return Ok(status);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.custody = Custody::Lost;
                }
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.has_custody() {
            let _ = self.kill_tree();
            if self.has_custody() {
                let _ = self.reap();
            }
        }
    }
}

pub(super) fn require_wait_custody() -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native process capture requires exclusive, non-autoreaping child waits",
        ));
    }
    Ok(())
}

pub(super) unsafe fn reset_child_sigchld() -> bool {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) == 0
    }
}
