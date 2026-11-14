//! The `isolated_hook_python` kind: the system interpreter a stdlib hook
//! client runs under, probed in isolation.
//!
//! Only `/usr/bin/python3` on macOS and Linux is considered. It must be a
//! regular executable file nobody else can write, and it must import the
//! modules the client needs under `-I` with a bare `PATH` within 1.5 seconds.
//! The request is `{"system_root": text | null}`, the caller's `SYSTEMROOT`;
//! the answer is `{"interpreter": path | null}`.

use std::path::Path;
#[cfg(unix)]
use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{json, Map, Value};

use super::{path_text, Failure, Step};

#[cfg(unix)]
const PROBE: &str =
    "import hmac, json, sys, urllib.request; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)";
#[cfg(unix)]
const TIMEOUT: Duration = Duration::from_millis(1500);
const CANDIDATES: &[&str] = if cfg!(any(target_os = "macos", target_os = "linux")) {
    &["/usr/bin/python3"]
} else {
    &[]
};

pub(super) fn dispatch(fields: &Map<String, Value>) -> Step<Value> {
    if fields.keys().any(|key| key != "system_root") {
        return Err(Failure::Invalid);
    }
    let system_root = match fields.get("system_root") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if !text.contains('\0') => Some(text.as_str()),
        _ => return Err(Failure::Invalid),
    };
    let interpreter = CANDIDATES
        .iter()
        .map(Path::new)
        .find(|path| usable(path, system_root));
    Ok(json!({ "interpreter": interpreter.map(path_text) }))
}

/// `_isolated_python_is_usable`: a regular executable file nobody else can
/// write, whose probe exits 0 in time.
#[cfg(unix)]
fn usable(path: &Path, system_root: Option<&str>) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file()
        || nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_err()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return false;
    }
    let mut command = Command::new(path);
    command
        .args(["-I", "-c", PROBE])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(root) = system_root.filter(|root| !root.is_empty()) {
        command.env("SYSTEMROOT", root);
    }
    succeeds_in_time(command)
}

/// Python names no candidate off macOS and Linux.
#[cfg(not(unix))]
fn usable(_path: &Path, _system_root: Option<&str>) -> bool {
    false
}

/// Exit status 0 before the deadline; a probe still running is killed.
#[cfg(unix)]
fn succeeds_in_time(mut command: Command) -> bool {
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_requests_are_refused() {
        for request in [json!({"extra": 1}), json!({"system_root": 3})] {
            let Value::Object(fields) = request else {
                unreachable!()
            };
            assert!(matches!(dispatch(&fields), Err(Failure::Invalid)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_probe_that_fails_or_hangs_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str, mode: u32| {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.path().join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        assert!(usable(&write("ok", "#!/bin/sh\nexit 0\n", 0o755), None));
        assert!(!usable(&write("fails", "#!/bin/sh\nexit 1\n", 0o755), None));
        assert!(!usable(
            &write("shared", "#!/bin/sh\nexit 0\n", 0o775),
            None
        ));
        assert!(!usable(&write("plain", "#!/bin/sh\nexit 0\n", 0o644), None));
        let started = Instant::now();
        assert!(!usable(
            &write("hangs", "#!/bin/sh\nexec sleep 5\n", 0o755),
            None
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(!usable(dir.path(), None));
    }
}
