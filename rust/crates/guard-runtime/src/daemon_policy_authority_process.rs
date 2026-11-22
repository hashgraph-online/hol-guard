use super::*;

// ---------------------------------------------------------------------------
// Process liveness + command binding
//
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) fn daemon_pid_is_running(pid: i64) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), None).is_ok()
}
#[cfg(windows)]
pub(crate) fn daemon_pid_is_running(pid: i64) -> bool {
    if pid <= 0 || pid > i64::from(u32::MAX) {
        return false;
    }
    guard_runtime_windows_process::wait_for_process_exit(pid as u32, Duration::ZERO)
        .map(|exited| !exited)
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn daemon_pid_is_running(_pid: i64) -> bool {
    false
}

/// `_guard_daemon_pid_matches_command`.
pub(crate) fn daemon_pid_matches_command(pid: i64, guard_home: &Path) -> bool {
    let Some(command) = daemon_command_for_pid(pid) else {
        return false;
    };
    let Some(parts) = split_process_command(&command) else {
        return false;
    };
    if !guard_daemon_command_parts_match(&parts) {
        return false;
    }
    let command_home = command_guard_home(&parts).or_else(implicit_daemon_guard_home);
    match command_home {
        Some(home) => paths_equal_resolved(&home, guard_home),
        None => false,
    }
}

/// `_APPROVAL_CENTER_LOCATOR_FILE`.
const APPROVAL_CENTER_LOCATOR_FILE: &str = "approval-center-locator.json";
/// The locator records six short fields; anything larger is not one.
const APPROVAL_CENTER_LOCATOR_MAX_BYTES: u64 = 64 * 1024;

/// `read_approval_center_locator(guard_home).daemon_url`
///, which Python writes without private
/// permissions, so this read does not require them either.
///
/// The shape gates are `locator_shape`: a live, positive `pid` and the five
/// string fields. A process whose command does not prove this guard home is
/// accepted only when the authenticated daemon state vouches for it, which
/// is `locator_binding`.
pub(crate) fn approval_center_daemon_url(guard_home: &Path) -> Option<String> {
    let path = guard_home.join(APPROVAL_CENTER_LOCATOR_FILE);
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > APPROVAL_CENTER_LOCATOR_MAX_BYTES {
        return None;
    }
    let payload: Value = serde_json::from_str(&fs::read_to_string(&path).ok()?).ok()?;
    let payload = payload.as_object()?;
    let pid = payload
        .get("pid")
        .and_then(Value::as_i64)
        .filter(|pid| *pid > 0)?;
    if !daemon_pid_is_running(pid) {
        return None;
    }
    let text = |key: &str| payload.get(key).and_then(Value::as_str);
    let daemon_url = text("daemon_url")?;
    for key in [
        "approval_url_base",
        "started_at",
        "state_path",
        "guard_home",
    ] {
        text(key)?;
    }
    if !daemon_pid_matches_command(pid, guard_home)
        && !locator_state_binds(guard_home, pid, daemon_url)
    {
        return None;
    }
    Some(daemon_url.to_owned())
}

/// `locator_binding`: the authenticated state names the same process and the
/// loopback port the locator URL carries.
fn locator_state_binds(guard_home: &Path, pid: i64, daemon_url: &str) -> bool {
    let Some(state) = load_authenticated_daemon_state(guard_home) else {
        return false;
    };
    if state.get("pid").and_then(Value::as_i64) != Some(pid) {
        return false;
    }
    state
        .get("port")
        .and_then(Value::as_i64)
        .is_some_and(|port| daemon_url == format!("http://127.0.0.1:{port}"))
}

/// `ps -p <pid> -o command=`.
#[cfg(unix)]
fn daemon_command_for_pid(pid: i64) -> Option<String> {
    let ps_path = trusted_posix_ps_path()?;
    let pid_arg = pid.to_string();
    let output =
        bounded_process_query_stdout(&[ps_path.to_str()?, "-p", &pid_arg, "-o", "command="])?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

#[cfg(not(unix))]
fn daemon_command_for_pid(_pid: i64) -> Option<String> {
    None
}

#[cfg(unix)]
fn trusted_posix_ps_path() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for raw in POSIX_PS_PATHS {
        let candidate = Path::new(raw);
        let Ok(resolved) = fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(metadata) = fs::metadata(&resolved) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Some(resolved);
        }
    }
    None
}

/// `_bounded_process_query_stdout`.
#[cfg(unix)]
fn bounded_process_query_stdout(args: &[&str]) -> Option<String> {
    let mut child: Child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let result = stdout
            .take((PROCESS_QUERY_MAX_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map(|_| buf);
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + PROCESS_QUERY_TIMEOUT;
    let output = loop {
        match child.try_wait() {
            Ok(Some(_)) => match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(buf)) => break Some(buf),
                _ => break None,
            },
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break None,
        }
    };
    let output = output?;
    if output.len() > PROCESS_QUERY_MAX_BYTES {
        return None;
    }
    String::from_utf8(output).ok()
}

/// `_split_process_command` — `shlex.split` POSIX
/// parity for the bounded subset used here. Returns None on unbalanced
/// quoting (malformed).
fn split_process_command(command_line: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = command_line.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut have = false;
    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\' {
                match chars.next() {
                    Some(next @ ('"' | '\\')) => current.push(next),
                    Some(next) => {
                        current.push('\\');
                        current.push(next);
                    }
                    None => return None,
                }
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => match chars.next() {
                Some(next) => current.push(next),
                None => return None,
            },
            c if c.is_whitespace() => {
                if have {
                    parts.push(std::mem::take(&mut current));
                    have = false;
                }
            }
            c => {
                current.push(c);
                have = true;
            }
        }
    }
    if in_single || in_double {
        return None;
    }
    if have {
        parts.push(current);
    }
    Some(parts)
}

/// `_guard_daemon_command_parts_match`.
fn guard_daemon_command_parts_match(parts: &[String]) -> bool {
    if parts
        .iter()
        .any(|part| HOOK_LAUNCHER_ARGS.contains(&part.as_str()))
    {
        return false;
    }
    if frozen_daemon_serve_context(parts).is_some() {
        return true;
    }
    for index in 0..parts.len().saturating_sub(1) {
        let window2 = matches!(
            parts.get(index..index + 2),
            Some(w) if w[0] == "daemon" && w[1] == "--serve"
        );
        let window3 = matches!(
            parts.get(index..index + 3),
            Some(w) if w[0] == "guard" && w[1] == "daemon" && w[2] == "--serve"
        );
        if !window2 && !window3 {
            continue;
        }
        let prefix = &parts[..index];
        if prefix.iter().any(|part| part == "codex_plugin_scanner.cli") {
            return true;
        }
        if index > 0 {
            let launcher_name = path_basename_lower(&parts[index - 1]);
            if RECOGNIZED_LAUNCHERS.contains(&launcher_name.as_str()) {
                return true;
            }
        }
    }
    false
}

/// `_guard_home_from_command_parts`.
fn command_guard_home(parts: &[String]) -> Option<PathBuf> {
    if let Some((guard_home, _home_dir, _port)) = frozen_daemon_serve_context(parts) {
        return Some(guard_home);
    }
    for (index, part) in parts.iter().enumerate() {
        if part == "--guard-home" {
            match parts.get(index + 1) {
                Some(value) if !value.is_empty() => return Some(PathBuf::from(value)),
                _ => return None,
            }
        }
        if let Some(value) = part.strip_prefix("--guard-home=") {
            if value.is_empty() {
                return None;
            }
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// `_frozen_daemon_serve_context` +
/// `decode_frozen_daemon_serve_payload` (frozen_runtime_commands.py:136-:163).
fn frozen_daemon_serve_context(parts: &[String]) -> Option<(PathBuf, PathBuf, i64)> {
    if parts.len() != 3 || parts[1] != FROZEN_DAEMON_SERVE_ARG {
        return None;
    }
    let launcher_name = path_basename_lower(&parts[0]);
    if !RECOGNIZED_LAUNCHERS.contains(&launcher_name.as_str()) {
        return None;
    }
    let payload: Value = serde_json::from_str(&parts[2]).ok()?;
    let map = payload.as_object()?;
    if map.len() != 3 {
        return None;
    }
    let guard_home = map.get("guard_home")?.as_str()?;
    let home_dir = map.get("home_dir")?.as_str()?;
    let port = map.get("port")?.as_i64()?;
    if !(1..=65535).contains(&port) {
        return None;
    }
    let guard_home = PathBuf::from(guard_home);
    let home_dir = PathBuf::from(home_dir);
    if !guard_home.is_absolute() || !home_dir.is_absolute() {
        return None;
    }
    Some((guard_home, home_dir, port))
}

/// `_implicit_daemon_guard_home` →
/// `resolve_guard_home` (config.py:463-:481). No override: CWD
/// `.hol-guard`, then `$HOME/.hol-guard`, then the POSIX/Windows fallbacks.
fn implicit_daemon_guard_home() -> Option<PathBuf> {
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join(".hol-guard");
        if fs::canonicalize(&candidate)
            .map(|p| p.is_dir())
            .unwrap_or(false)
        {
            return fs::canonicalize(&candidate).ok();
        }
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let resolved = home.join(".hol-guard");
        if resolved.is_dir() {
            return Some(resolved);
        }
    }
    #[cfg(not(windows))]
    {
        for raw_root in [".", "/var", "/private/var"] {
            let resolved = Path::new(raw_root).join(".hol-guard");
            if resolved.is_dir() {
                return Some(resolved);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            let resolved = appdata.join("hol-guard");
            if resolved.is_dir() {
                return Some(resolved);
            }
        }
    }
    None
}

fn path_basename_lower(raw: &str) -> String {
    let trimmed = raw.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_lowercase()
}
