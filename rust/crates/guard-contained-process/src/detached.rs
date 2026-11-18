//! A long-lived helper process started in a session of its own.
//!
//! The caller owns what to run; this module owns the one `setsid` call that detaches the child from the
//! caller's terminal session, so the helper survives the session that asked for it, and a reaper thread that
//! collects its exit status so it never lingers as a zombie while the caller stays alive.

use std::ffi::OsString;
use std::io;
use std::path::Path;

/// Start `program` with exactly `env`, no standard streams and a new session; returns its pid.
///
/// A process that cannot start is an `Err`; the helper's own later exit is nobody's concern.
#[cfg(unix)]
pub fn spawn_detached(
    program: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> io::Result<u32> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure runs between fork and exec and only calls `setsid`, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

/// Windows has no session to leave and no Unix control socket for the server this starts.
#[cfg(not(unix))]
pub fn spawn_detached(
    _program: &Path,
    _args: &[OsString],
    _env: &[(OsString, OsString)],
) -> io::Result<u32> {
    Err(io::ErrorKind::Unsupported.into())
}
