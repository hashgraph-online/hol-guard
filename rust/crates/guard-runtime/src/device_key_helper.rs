//! `device-key-helper --stdin`: run the platform device-key helper for one
//! operation and check its answer (`mdm/device_key_native.py` before it moved
//! here).
//!
//! - On macOS the helper is `hol-guard-device-key` in the runtime root.
//! - On Windows it is `device-key-helper.ps1`, run by the PowerShell under the
//!   Windows directory the system reports, never the one the environment
//!   names.
//!
//! The helper runs with a fixed environment, a fixed working directory and a
//! 15 second limit. Its stdout is bounded to 16 KiB and its stderr to 4 KiB.
//! An answer that breaks the helper contract in any way is
//! `device_key_probe_failed`; the caller never sees the helper's own output.
//!
//! The signing operations take the canonical payload the caller already
//! validated and pass it to the helper on stdin. A signature must be one
//! canonical ASN.1 DER ECDSA P-256 signature whose `r` and `s` are both in
//! range.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Map, Value};

const SCHEMA: &str = "device-key-helper.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 4096;
const MAX_STDOUT_BYTES: usize = 16 * 1024;
const MAX_STDERR_BYTES: usize = 4096;
const MAX_PUBLIC_KEY_TEXT: usize = 256;
const MAX_SIGNATURE_TEXT: usize = 128;
const HELPER_TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(5);

const PROBE_FAILED: &str = "device_key_probe_failed";
const PROBE_VERBS: [&str; 3] = ["create", "inspect", "delete"];
const SIGN_VERBS: [&str; 3] = [
    "sign-health-lease",
    "sign-protection-lease",
    "sign-health-key-registration",
];
const STATES: [&str; 4] = ["active", "absent", "unknown", "tampered"];
const PROTECTION_LEVELS: [&str; 3] = ["hardware-backed", "os-protected", "unknown"];
const REASON_CODES: [&str; 8] = [
    "device_key_active",
    "device_key_absent",
    "device_key_generation_collision",
    "device_key_system_context_required",
    "device_key_request_invalid",
    "device_key_provider_unavailable",
    "device_key_unusable",
    "device_key_probe_failed",
];
/// The order of the P-256 group, big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    platform: String,
    runtime_root: String,
    verb: String,
    generation: String,
    #[serde(default)]
    payload: Option<String>,
}

/// One helper run: no shell, the given stdin, stdout and stderr captured up
/// to one byte past their bounds.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    program: String,
    arguments: Vec<String>,
    cwd: String,
    environment: Vec<(String, String)>,
    input: String,
}

struct Ran {
    /// `None` when the helper ended without an exit code.
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait Runner {
    /// The finished helper, or an error when it could not start or outlived
    /// its timeout.
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran>;
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "device-key-helper"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "device_key_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("device_key_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "device_key_request_invalid".to_owned())?;
    let answer = answer(&request, &mut SystemRunner, system_windows_directory)?;
    serde_json::to_vec(&answer).map_err(|_| "device_key_response_encode_failed".to_owned())
}

/// The runtime's answer, or an error for a request no helper may run.
fn answer(
    request: &Request,
    runner: &mut impl Runner,
    windows_directory: impl FnOnce() -> Option<String>,
) -> Result<Value, String> {
    let signing = SIGN_VERBS.contains(&request.verb.as_str());
    let probing = PROBE_VERBS.contains(&request.verb.as_str());
    let payload_fits = match &request.payload {
        Some(payload) => signing && !payload.is_empty() && payload.len() <= MAX_PAYLOAD_BYTES,
        None => probing,
    };
    if request.schema != SCHEMA || !payload_fits || !is_generation(&request.generation) {
        return Err("device_key_request_invalid".to_owned());
    }
    let Some(invocation) = invocation(request, windows_directory) else {
        return Ok(refused(PROBE_FAILED));
    };
    let Some(ran) = runner
        .run(&invocation)
        .ok()
        .filter(|ran| ran.stdout.len() <= MAX_STDOUT_BYTES && ran.stderr.len() <= MAX_STDERR_BYTES)
    else {
        return Ok(refused(PROBE_FAILED));
    };
    let checked = if signing {
        signature_answer(&ran)
    } else {
        probe_answer(&request.verb, &ran)
    };
    Ok(checked.unwrap_or_else(|| refused(PROBE_FAILED)))
}

fn refused(reason_code: &str) -> Value {
    json!({"ok": false, "reason_code": reason_code})
}

/// A key generation: 32 lowercase hex digits.
fn is_generation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The helper run for this platform, or `None` when the platform has no
/// helper or the Windows directory is unknown.
fn invocation(
    request: &Request,
    windows_directory: impl FnOnce() -> Option<String>,
) -> Option<Invocation> {
    let input = request.payload.clone().unwrap_or_default();
    match request.platform.as_str() {
        "macos" => Some(Invocation {
            program: format!(
                "{}/hol-guard-device-key",
                request.runtime_root.trim_end_matches('/')
            ),
            arguments: vec![request.verb.clone(), request.generation.clone()],
            cwd: "/".to_owned(),
            environment: [
                ("HOME", "/var/root"),
                ("LC_ALL", "C"),
                ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
                ("TMPDIR", "/var/tmp"),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
            input,
        }),
        "windows" => {
            let system_root = windows_directory()?;
            let drive = windows_drive(&system_root)?;
            let system_directory = nt_join(&system_root, "System32");
            let powershell = nt_join(&system_directory, r"WindowsPowerShell\v1.0\powershell.exe");
            let script = nt_join(&request.runtime_root, r"hol-guard\device-key-helper.ps1");
            Some(Invocation {
                program: powershell,
                arguments: [
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    &script,
                    "-Verb",
                    &request.verb,
                    "-Generation",
                    &request.generation,
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                environment: vec![
                    ("ComSpec".to_owned(), nt_join(&system_directory, "cmd.exe")),
                    ("SystemDrive".to_owned(), drive),
                    ("SystemRoot".to_owned(), system_root.clone()),
                    ("WINDIR".to_owned(), system_root),
                ],
                cwd: system_directory,
                input,
            })
        }
        _ => None,
    }
}

/// `C:` for `C:\Windows`; `None` for a path without a drive letter.
fn windows_drive(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        .then(|| path[..2].to_owned())
}

fn nt_join(base: &str, name: &str) -> String {
    format!("{}\\{}", base.trim_end_matches(['\\', '/']), name)
}

#[cfg(windows)]
pub(crate) fn system_windows_directory() -> Option<String> {
    guard_runtime_windows_process::windows_directory()?
        .into_os_string()
        .into_string()
        .ok()
}

#[cfg(not(windows))]
pub(crate) fn system_windows_directory() -> Option<String> {
    None
}

/// The helper's object when its keys are exactly `keys`.
fn helper_object(stdout: &[u8], keys: &[&str]) -> Option<Map<String, Value>> {
    let Value::Object(object) = serde_json::from_slice(stdout).ok()? else {
        return None;
    };
    (object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
        .then_some(object)
}

fn one_of(value: Option<&Value>, allowed: &[&str]) -> Option<String> {
    let text = value?.as_str()?;
    allowed.contains(&text).then(|| text.to_owned())
}

/// The key evidence for `create`, `inspect` or `delete`. The exit code and
/// the `ok` marker must agree with the state the operation produced.
fn probe_answer(verb: &str, ran: &Ran) -> Option<Value> {
    let object = helper_object(
        &ran.stdout,
        &[
            "ok",
            "state",
            "protectionLevel",
            "publicKeyX963",
            "reasonCode",
        ],
    )?;
    let ok = object.get("ok")?.as_bool()?;
    let state = one_of(object.get("state"), &STATES)?;
    let level = one_of(object.get("protectionLevel"), &PROTECTION_LEVELS)?;
    let reason = one_of(object.get("reasonCode"), &REASON_CODES)?;
    let public_key = match object.get("publicKeyX963")? {
        Value::Null => None,
        Value::String(text) if text.len() <= MAX_PUBLIC_KEY_TEXT => {
            let key = STANDARD.decode(text).ok()?;
            if key.len() != 65 || key[0] != 4 {
                return None;
            }
            Some(STANDARD.encode(key))
        }
        _ => return None,
    };
    let successful =
        (verb != "delete" && state == "active") || (verb == "delete" && state == "absent");
    let expected_code = if successful {
        0
    } else if verb == "inspect" && state == "absent" {
        1
    } else {
        2
    };
    if ran.code != Some(expected_code) || ok != successful {
        return None;
    }
    Some(json!({
        "ok": true,
        "state": state,
        "protection_level": level,
        "public_key_x963": public_key,
        "reason_code": reason,
    }))
}

/// The signature from a signing run that exited cleanly.
fn signature_answer(ran: &Ran) -> Option<Value> {
    if ran.code != Some(0) {
        return None;
    }
    let object = helper_object(
        &ran.stdout,
        &["ok", "signature", "signatureAlgorithm", "signatureEncoding"],
    )?;
    if object.get("ok") != Some(&Value::Bool(true))
        || object.get("signatureAlgorithm")?.as_str()? != "ecdsa-p256-sha256"
        || object.get("signatureEncoding")?.as_str()? != "asn1-der"
    {
        return None;
    }
    let text = object.get("signature")?.as_str()?;
    if text.len() > MAX_SIGNATURE_TEXT {
        return None;
    }
    let signature = STANDARD.decode(text).ok()?;
    is_canonical_p256_signature(&signature)
        .then(|| json!({"ok": true, "signature": STANDARD.encode(signature)}))
}

/// Whether `der` is exactly `SEQUENCE { INTEGER r, INTEGER s }` in minimal
/// DER with `0 < r, s < n`, so re-encoding it gives the same bytes.
fn is_canonical_p256_signature(der: &[u8]) -> bool {
    let [0x30, length, rest @ ..] = der else {
        return false;
    };
    if *length >= 0x80 || usize::from(*length) != rest.len() {
        return false;
    }
    let Some(after_r) = scalar_in_range(rest) else {
        return false;
    };
    scalar_in_range(after_r).is_some_and(<[u8]>::is_empty)
}

/// The bytes after one minimal DER INTEGER in `1..n`, or `None`.
fn scalar_in_range(der: &[u8]) -> Option<&[u8]> {
    let [0x02, length, rest @ ..] = der else {
        return None;
    };
    let length = usize::from(*length);
    if length == 0 || length >= 0x80 || length > rest.len() {
        return None;
    }
    let (content, after) = rest.split_at(length);
    // Negative, or a leading zero the value does not need.
    if content[0] & 0x80 != 0 || (content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0) {
        return None;
    }
    let magnitude = match content {
        [0, tail @ ..] => tail,
        all => all,
    };
    if magnitude.is_empty() || magnitude.len() > P256_ORDER.len() {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[P256_ORDER.len() - magnitude.len()..].copy_from_slice(magnitude);
    (padded != [0u8; 32] && padded < P256_ORDER).then_some(after)
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.arguments)
            .current_dir(&invocation.cwd)
            .env_clear()
            .envs(invocation.environment.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let deadline = Instant::now() + HELPER_TIMEOUT;
        let mut child = command.spawn()?;
        let (Some(mut stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            if child.kill().is_ok() {
                let _ = child.wait();
            }
            return Err(io::Error::other("helper pipes unavailable"));
        };
        let input = invocation.input.clone();
        thread::spawn(move || {
            let _ = stdin.write_all(input.as_bytes());
        });
        let stdout = read_detached(stdout, MAX_STDOUT_BYTES);
        let stderr = read_detached(stderr, MAX_STDERR_BYTES);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                // Reap only a child that was killed; if the kill is refused,
                // waiting could block past the deadline.
                if child.kill().is_ok() {
                    let _ = child.wait();
                }
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(POLL);
        };
        // A descendant may keep a pipe open after the helper exits; wait
        // only for the remaining budget and leave the reader behind.
        let collect = |receiver: mpsc::Receiver<Vec<u8>>| {
            receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| io::Error::other("helper output unreadable"))
        };
        Ok(Ran {
            code: status.code(),
            stdout: collect(stdout)?,
            stderr: collect(stderr)?,
        })
    }
}

/// Read up to one byte past `limit`, so an overrun is visible to the caller.
fn read_detached(stream: impl Read + Send + 'static, limit: usize) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if stream
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .is_ok()
        {
            let _ = sender.send(bytes);
        }
    });
    receiver
}

#[cfg(test)]
#[path = "device_key_helper_tests.rs"]
mod tests;
