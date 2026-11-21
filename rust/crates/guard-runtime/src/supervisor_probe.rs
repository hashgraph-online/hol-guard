//! `supervisor-verdict`'s `macos-verify` and `windows-verify` ops gather the
//! evidence themselves, as `mdm/supervisor.py` did before them. They read the
//! LaunchDaemon property list without following a leaf link and run
//! `launchctl` or `schtasks` by a pinned path with a fixed environment and
//! bounded output, then decide with the same rules as the `macos` and
//! `windows` ops. A probe that cannot run, overruns its time or output, or
//! dies by a signal is a failed probe, never a healthy supervisor.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use roxmltree::{Document, Node, ParsingOptions};
use serde_json::{Map, Number, Value};

use super::{
    macos, verdict, windows, Probe, Request, Verdict, LABEL, PROBE_FAILED, WINDOWS_TASK_NAME,
};

const MAX_REGISTRATION_BYTES: usize = 256 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_POLL: Duration = Duration::from_millis(5);
const MAX_PLIST_DEPTH: usize = 64;
const ABSENT: Verdict = ("absent", "supervisor_absent");
const LAUNCHCTL: &str = "/bin/launchctl";
const LAUNCHCTL_ENVIRONMENT: [(&str, &str); 4] = [
    ("HOME", "/var/root"),
    ("LC_ALL", "C"),
    ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
    ("TMPDIR", "/var/tmp"),
];

/// Runs one probe program; tests stand in for the real `launchctl` and
/// `schtasks`.
pub(super) trait Runner {
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Probe>;
}

pub(super) struct SystemRunner;

impl Runner for SystemRunner {
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Probe> {
        run_bounded(program, arguments, cwd, environment, PROBE_TIMEOUT)
    }
}

/// Whether the request carries only what a `*-verify` op reads, so no
/// evidence the caller gathered can stand in for a probe this op runs.
fn carries_no_evidence(request: &Request) -> bool {
    request.plist.is_null()
        && request.disabled.is_none()
        && request.loaded.is_none()
        && request.task.is_none()
}

pub(super) fn macos_verify(mut request: Request, runner: &mut impl Runner) -> Option<Value> {
    if !carries_no_evidence(&request)
        || request.windows_directory.is_some()
        || request.state_root.is_some()
        || request.plist_path.is_none()
        || request.stdout_log.is_none()
        || request.stderr_log.is_none()
    {
        return None;
    }
    let plist_file = request.plist_file.take()?;
    request.plist = match read_registration(Path::new(&plist_file)) {
        Ok(Some(plist)) => plist,
        Ok(None) => return Some(verdict(ABSENT)),
        Err(()) => return Some(verdict(PROBE_FAILED)),
    };
    let loaded_target = format!("system/{LABEL}");
    loop {
        let answer = macos(&request)?;
        let Some(next) = answer
            .get("next")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Some(answer);
        };
        let arguments = match next.as_str() {
            "disabled" => ["print-disabled", "system"],
            "loaded" => ["print", loaded_target.as_str()],
            _ => return Some(verdict(PROBE_FAILED)),
        };
        let Ok(probe) = runner.run(LAUNCHCTL, &arguments, "/", &LAUNCHCTL_ENVIRONMENT) else {
            return Some(verdict(PROBE_FAILED));
        };
        if next == "disabled" {
            request.disabled = Some(probe);
        } else {
            request.loaded = Some(probe);
        }
    }
}

pub(super) fn windows_verify(request: &Request, runner: &mut impl Runner) -> Option<Value> {
    if !carries_no_evidence(request)
        || request.state_root.is_some()
        || request.plist_file.is_some()
        || request.plist_path.is_some()
        || request.stdout_log.is_some()
        || request.stderr_log.is_some()
    {
        return None;
    }
    let windows_directory = request.windows_directory.as_deref()?;
    let Some((system_directory, environment)) = windows_context(windows_directory) else {
        return Some(verdict(PROBE_FAILED));
    };
    let schtasks = nt_join(&system_directory, "schtasks.exe");
    let environment: Vec<(&str, &str)> = environment
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let arguments = ["/Query", "/TN", WINDOWS_TASK_NAME, "/XML", "/HRESULT"];
    Some(
        match runner.run(&schtasks, &arguments, &system_directory, &environment) {
            Ok(task) => verdict(windows(&task, &request.executable)),
            Err(_) => verdict(PROBE_FAILED),
        },
    )
}

/// `System32` under the Windows directory and the only environment
/// `schtasks` runs with. The Windows directory comes from the kernel by way
/// of the caller and must start with a drive letter.
pub(super) fn windows_context(
    windows_directory: &str,
) -> Option<(String, [(&'static str, String); 4])> {
    let mut chars = windows_directory.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next() != Some(':') {
        return None;
    }
    let system_drive = format!("{letter}:");
    let system_directory = nt_join(windows_directory, "System32");
    let environment = [
        ("ComSpec", nt_join(&system_directory, "cmd.exe")),
        ("SystemDrive", system_drive),
        ("SystemRoot", windows_directory.to_owned()),
        ("WINDIR", windows_directory.to_owned()),
    ];
    Some((system_directory, environment))
}

/// `ntpath.join(base, name)` for a drive-rooted `base` and a plain `name`.
pub(super) fn nt_join(base: &str, name: &str) -> String {
    if base.ends_with(['\\', '/']) || base.len() == 2 {
        format!("{base}{name}")
    } else {
        format!("{base}\\{name}")
    }
}

/// The property list at `path`: `Ok(None)` when nothing is there, `Err` when
/// it is a link, changes while read, is too large or is not one `plistlib`
/// would read.
fn read_registration(path: &Path) -> Result<Option<Value>, ()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    }
    let read = guard_secure_fs::read_stable(path, MAX_REGISTRATION_BYTES, false).map_err(|_| ())?;
    parse_plist(&read.bytes).map(Some).ok_or(())
}

/// `plistlib.loads` for the XML property list Guard installs, in UTF-8 or,
/// as `plistlib` also reads it, UTF-16. A binary property list, an entity
/// declaration or an element `plistlib` would refuse reads as `None`; `data`
/// and `date` values, which the JSON evidence never carried, become `null`,
/// which no checked key accepts.
pub(super) fn parse_plist(bytes: &[u8]) -> Option<Value> {
    let text = plist_text_of(bytes)?;
    let text = text.as_str();
    if text.contains("<!ENTITY") {
        return None;
    }
    let options = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    let document =
        Document::parse_with_options(text.trim_start_matches('\u{feff}'), options).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "plist" || root.tag_name().namespace().is_some() {
        return None;
    }
    let mut values = root.children().filter(Node::is_element);
    let value = match values.next() {
        Some(node) => plist_value(node, 0)?,
        None => Value::Null,
    };
    values.next().is_none().then_some(value)
}

/// The document's text: UTF-16 when it opens with a UTF-16 byte order mark
/// or a `<` in UTF-16, the way the XML parser under `plistlib` detects it,
/// and UTF-8 otherwise.
fn plist_text_of(bytes: &[u8]) -> Option<String> {
    let from_units = |big_endian: bool, body: &[u8]| -> Option<String> {
        if !body.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| {
                if big_endian {
                    u16::from_be_bytes([pair[0], pair[1]])
                } else {
                    u16::from_le_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        String::from_utf16(&units).ok()
    };
    match bytes {
        [0xFF, 0xFE, body @ ..] => from_units(false, body),
        [0xFE, 0xFF, body @ ..] => from_units(true, body),
        [b'<', 0, ..] => from_units(false, bytes),
        [0, b'<', ..] => from_units(true, bytes),
        _ => std::str::from_utf8(bytes).ok().map(str::to_owned),
    }
}

fn plist_value(node: Node, depth: usize) -> Option<Value> {
    if depth > MAX_PLIST_DEPTH || node.tag_name().namespace().is_some() {
        return None;
    }
    match node.tag_name().name() {
        "dict" => {
            let mut map = Map::new();
            let mut items = node.children().filter(Node::is_element);
            while let Some(key) = items.next() {
                if key.tag_name().name() != "key" || key.tag_name().namespace().is_some() {
                    return None;
                }
                let name = plist_text(key)?;
                let value = plist_value(items.next()?, depth + 1)?;
                map.insert(name, value);
            }
            Some(Value::Object(map))
        }
        "array" => node
            .children()
            .filter(Node::is_element)
            .map(|item| plist_value(item, depth + 1))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        "string" => plist_text(node).map(Value::String),
        "integer" => {
            let text = plist_text(node)?;
            let text = text.trim();
            let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(hex) => i64::from_str_radix(hex, 16).ok(),
                None => text.parse::<i64>().ok(),
            };
            parsed.map(Value::from)
        }
        "real" => {
            let parsed = plist_text(node)?.trim().parse::<f64>().ok()?;
            Number::from_f64(parsed).map(Value::Number)
        }
        "true" | "false" if node.children().all(|child| !child.is_element()) => {
            Some(Value::Bool(node.tag_name().name() == "true"))
        }
        "data" | "date" => Some(Value::Null),
        _ => None,
    }
}

/// The character data of a leaf element, the way `plistlib` joins it.
fn plist_text(node: Node) -> Option<String> {
    if node.children().any(|child| child.is_element()) {
        return None;
    }
    Some(
        node.children()
            .filter(Node::is_text)
            .filter_map(|child| child.text())
            .collect(),
    )
}

/// One probe run with no shell, null standard input and error, a wall clock
/// (10 s outside tests) and at most the registration bound of standard output.
fn run_bounded(
    program: &str,
    arguments: &[&str],
    cwd: &str,
    environment: &[(&str, &str)],
    timeout: Duration,
) -> io::Result<Probe> {
    let mut child = Command::new(program)
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("probe stdout unavailable"));
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(MAX_REGISTRATION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(PROBE_POLL);
    };
    // A descendant may hold the pipe open; wait only for what is left of the
    // budget and leave the reader behind after that.
    let bytes = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if bytes.len() > MAX_REGISTRATION_BYTES {
        return Err(io::Error::other("probe output exceeded"));
    }
    let returncode = status
        .code()
        .ok_or_else(|| io::Error::other("probe ended by a signal"))?;
    Ok(Probe {
        returncode: i64::from(returncode),
        stdout: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[cfg(test)]
#[path = "supervisor_probe_tests.rs"]
mod tests;
