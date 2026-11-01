//! The live process table and signals behind `orphaned-worker-reap`.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::{getpgid, Pid};

use super::{Host, Stop};

const TRUSTED_PS_PATHS: [&str; 2] = ["/bin/ps", "/usr/bin/ps"];
const LISTING_LIMIT: u64 = 1024 * 1024;
const COMMAND_LIMIT: u64 = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) struct SystemHost;

/// `ps` resolved only from fixed operating-system locations.
fn trusted_ps_path() -> Option<std::path::PathBuf> {
    TRUSTED_PS_PATHS.iter().find_map(|raw| {
        let resolved = std::fs::canonicalize(raw).ok()?;
        let regular = std::fs::metadata(&resolved).ok()?.file_type().is_file();
        let executable = nix::unistd::access(&resolved, nix::unistd::AccessFlags::X_OK).is_ok();
        (regular && executable).then_some(resolved)
    })
}

/// Strict UTF-8 stdout of one bounded `ps` run, or `None` after failure,
/// timeout or overflow.
fn run_ps(arguments: &[&str], timeout: Duration, limit: u64) -> Option<String> {
    let mut child = Command::new(trusted_ps_path()?)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(limit + 1).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let bytes = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?;
    if !status.success() || bytes.len() as u64 > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

impl Host for SystemHost {
    fn listing(&self, timeout: Duration) -> Option<String> {
        run_ps(
            &["-axww", "-o", "pid=,ppid=,state=,command="],
            timeout,
            LISTING_LIMIT,
        )
    }

    fn command(&self, pid: u32) -> Option<String> {
        let output = run_ps(
            &["-p", &pid.to_string(), "-ww", "-o", "command="],
            COMMAND_TIMEOUT,
            COMMAND_LIMIT,
        )?;
        let command = super::py_strip(&output);
        (!command.is_empty()).then(|| command.to_owned())
    }

    fn start_token(&self, pid: u32) -> Option<String> {
        crate::resident_process_identity::process_start_marker(pid).ok()
    }

    fn signal(&self, pid: u32, stop: Stop) {
        let Ok(raw) = i32::try_from(pid) else {
            return;
        };
        let target = Pid::from_raw(raw);
        let signal = match stop {
            Stop::Terminate => Signal::SIGTERM,
            Stop::Kill => Signal::SIGKILL,
        };
        super::deliver(
            || getpgid(Some(target)).ok().map(|group| group == target),
            || killpg(target, signal).is_ok(),
            || {
                let _ = kill(target, signal);
            },
        );
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
