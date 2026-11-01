//! `native-install-verdict --stdin`: check the managed machine package's
//! identity and publisher signature (`mdm/native.py` before it moved here).
//!
//! - On macOS the package receipt comes from the pinned `pkgutil`, and the
//!   pinned `codesign` checks the runtime executable's signature and reads its
//!   Team ID, which must equal the configured pin.
//! - On Windows the pinned PowerShell reads the runtime executable's
//!   Authenticode state, signer thumbprint and product version. The
//!   thumbprint pins belong to the HOLGuardMachine package, not to Desktop
//!   Artifact Signing: those leaves are short-lived, so a Desktop MSI signer
//!   thumbprint is not a valid pin for this HOLGuardMachine identity.
//!
//! A missing pin never reports health, and a probe that cannot run reports
//! the package as absent.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use pep440_rs::Version;
use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "native-install-verdict.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const POLL: Duration = Duration::from_millis(5);

const MACOS_IDENTITY: &str = "org.hol.guard";
const WINDOWS_IDENTITY: &str = "HOLGuardMachine";
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNATURE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTHENTICODE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    platform: String,
    runtime_root: String,
    #[serde(default)]
    macos_team_id: Option<String>,
    #[serde(default)]
    windows_signer_thumbprints: Vec<String>,
    #[serde(default)]
    windows_directory: Option<String>,
}

/// One child process to run: no shell, stdin closed, stdout and stderr
/// captured up to [`MAX_OUTPUT_BYTES`] each.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    program: String,
    arguments: Vec<String>,
    /// `None` keeps the runtime's working directory and environment.
    context: Option<WindowsContext>,
    timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
struct WindowsContext {
    cwd: String,
    environment: Vec<(String, String)>,
}

struct Ran {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait Runner {
    /// The finished child, or an error when it could not start, outlived its
    /// timeout or wrote more than the output bound.
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran>;
}

struct Verdict {
    status: &'static str,
    reason_code: &'static str,
    package_identity: &'static str,
    signature_state: &'static str,
    version: Option<String>,
}

fn verdict(
    status: &'static str,
    reason_code: &'static str,
    package_identity: &'static str,
    signature_state: &'static str,
) -> Verdict {
    Verdict {
        status,
        reason_code,
        package_identity,
        signature_state,
        version: None,
    }
}

impl Verdict {
    fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    fn to_json(&self) -> Value {
        json!({
            "ok": true,
            "status": self.status,
            "reason_code": self.reason_code,
            "package_identity": self.package_identity,
            "signature_state": self.signature_state,
            "version": self.version,
        })
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "native-install-verdict"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let invalid = || "native_install_request_invalid".to_owned();
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_install_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("native_install_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let answer = verify(&request, &mut SystemRunner).ok_or_else(invalid)?;
    serde_json::to_vec(&answer.to_json())
        .map_err(|_| "native_install_response_encode_failed".to_owned())
}

/// The verdict for the platform the caller named, or `None` for a request
/// that carries the other platform's fields.
fn verify(request: &Request, runner: &mut impl Runner) -> Option<Verdict> {
    match request.platform.as_str() {
        "macos"
            if request.windows_signer_thumbprints.is_empty()
                && request.windows_directory.is_none() =>
        {
            Some(verify_macos(request, runner))
        }
        "windows" if request.macos_team_id.is_none() => Some(verify_windows(request, runner)),
        "macos" | "windows" => None,
        _ => Some(verdict(
            "unsupported",
            "native_platform_unsupported",
            "unknown",
            "unsupported",
        )),
    }
}

fn verify_macos(request: &Request, runner: &mut impl Runner) -> Verdict {
    let identity = MACOS_IDENTITY;
    let Some(expected_team_id) = request.macos_team_id.as_deref() else {
        return verdict(
            "unknown",
            "native_publisher_pin_absent",
            identity,
            "unverified",
        );
    };
    let executable = format!(
        "{}/hol-guard/hol-guard",
        request.runtime_root.trim_end_matches('/')
    );
    let plain = |program: &str, arguments: &[&str], timeout: Duration| Invocation {
        program: program.to_owned(),
        arguments: arguments.iter().map(|item| (*item).to_owned()).collect(),
        context: None,
        timeout,
    };
    let receipt = runner.run(&plain(
        "/usr/sbin/pkgutil",
        &["--pkg-info-plist", identity],
        RECEIPT_TIMEOUT,
    ));
    let receipt_version = match receipt {
        Ok(ran) if ran.success => receipt_version(&ran.stdout),
        _ => None,
    };
    let Some(receipt_version) = receipt_version else {
        return verdict(
            "absent",
            "native_package_receipt_absent",
            identity,
            "unknown",
        );
    };
    let signature = runner.run(&plain(
        "/usr/bin/codesign",
        &["--verify", "--deep", "--strict", executable.as_str()],
        SIGNATURE_TIMEOUT,
    ));
    let details = runner.run(&plain(
        "/usr/bin/codesign",
        &["-d", "--verbose=4", executable.as_str()],
        SIGNATURE_TIMEOUT,
    ));
    let (Ok(signature), Ok(details)) = (signature, details) else {
        return verdict(
            "absent",
            "native_package_receipt_absent",
            identity,
            "unknown",
        );
    };
    let Some(version) = receipt_version.and_then(validated_version) else {
        return verdict(
            "tampered",
            "native_package_version_invalid",
            identity,
            "invalid",
        );
    };
    let details_text = String::from_utf8_lossy(&details.stderr);
    let team_id = details_text
        .split(is_line_break)
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .map(str::trim);
    if !signature.success || !details.success || team_id != Some(expected_team_id) {
        return verdict(
            "tampered",
            "native_publisher_signature_invalid",
            identity,
            "invalid",
        )
        .with_version(version);
    }
    verdict("healthy", "native_install_valid", identity, "valid").with_version(version)
}

/// The receipt's `pkg-version`: `None` when the output is not a property
/// list, `Some(None)` when it is one without a string `pkg-version`.
fn receipt_version(bytes: &[u8]) -> Option<Option<String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let document = roxmltree::Document::parse(text).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "plist" {
        return None;
    }
    let mut top = root.children().filter(roxmltree::Node::is_element);
    let Some(dictionary) = top.next().filter(|node| node.has_tag_name("dict")) else {
        return Some(None);
    };
    let mut entries = dictionary.children().filter(roxmltree::Node::is_element);
    while let Some(key) = entries.next() {
        let value = entries.next();
        if key.has_tag_name("key") && key.text().unwrap_or_default() == "pkg-version" {
            return Some(
                value
                    .filter(|node| node.has_tag_name("string"))
                    .map(|node| node.text().unwrap_or_default().to_owned()),
            );
        }
    }
    Some(None)
}

fn verify_windows(request: &Request, runner: &mut impl Runner) -> Verdict {
    let identity = WINDOWS_IDENTITY;
    if request.windows_signer_thumbprints.is_empty() {
        return verdict(
            "unknown",
            "native_publisher_pin_absent",
            identity,
            "unverified",
        );
    }
    let absent = || {
        verdict(
            "absent",
            "native_package_identity_absent",
            identity,
            "unknown",
        )
    };
    let Some(windows_directory) = request.windows_directory.as_deref() else {
        return absent();
    };
    let executable = nt_join(
        &nt_join(&request.runtime_root, "hol-guard"),
        "hol-guard.exe",
    );
    let escaped = executable.replace('\'', "''");
    let command = format!(
        "$s=Get-AuthenticodeSignature -LiteralPath '{escaped}';\
         $v=(Get-Item -LiteralPath '{escaped}').VersionInfo.ProductVersion;\
         @{{Status=$s.Status.ToString();Thumbprint=if($s.SignerCertificate)\
         {{$s.SignerCertificate.Thumbprint}}else{{$null}};Version=$v}}|ConvertTo-Json -Compress"
    );
    let system_directory = nt_join(windows_directory, "System32");
    let invocation = Invocation {
        program: nt_join(&system_directory, r"WindowsPowerShell\v1.0\powershell.exe"),
        arguments: vec![
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            command,
        ],
        context: Some(WindowsContext {
            cwd: system_directory.clone(),
            environment: vec![
                ("ComSpec".to_owned(), nt_join(&system_directory, "cmd.exe")),
                ("SystemRoot".to_owned(), windows_directory.to_owned()),
                ("WINDIR".to_owned(), windows_directory.to_owned()),
            ],
        }),
        timeout: AUTHENTICODE_TIMEOUT,
    };
    let payload = match runner.run(&invocation) {
        Ok(ran) if ran.success => {
            serde_json::from_str::<Value>(String::from_utf8_lossy(&ran.stdout).trim()).ok()
        }
        _ => None,
    };
    let Some(payload) = payload else {
        return absent();
    };
    let field = |name: &str| payload.get(name).and_then(Value::as_str);
    let thumbprint = field("Thumbprint").map(|value| value.replace(' ', "").to_uppercase());
    let pinned = thumbprint.is_some_and(|value| {
        request
            .windows_signer_thumbprints
            .iter()
            .any(|pin| *pin == value)
    });
    match field("Version").and_then(|value| validated_version(value.to_owned())) {
        Some(version) if payload.is_object() && field("Status") == Some("Valid") && pinned => {
            verdict("healthy", "native_install_valid", identity, "valid").with_version(version)
        }
        _ => verdict(
            "tampered",
            "native_publisher_signature_invalid",
            identity,
            "invalid",
        ),
    }
}

/// A non-blank PEP 440 version, without surrounding whitespace.
fn validated_version(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty() && Version::from_str(trimmed).is_ok()).then(|| trimmed.to_owned())
}

/// `ntpath.join(base, name)` for a relative `name`.
fn nt_join(base: &str, name: &str) -> String {
    if base.is_empty() || base.ends_with(['\\', '/', ':']) {
        format!("{base}{name}")
    } else {
        format!("{base}\\{name}")
    }
}

/// The line boundaries `str.splitlines` splits on.
fn is_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(context) = &invocation.context {
            command.current_dir(&context.cwd).env_clear();
            for (name, value) in &context.environment {
                command.env(name, value);
            }
        }
        let deadline = Instant::now() + invocation.timeout;
        let mut child = command.spawn()?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("child output unavailable"));
        };
        let stdout = read_detached(stdout);
        let stderr = read_detached(stderr);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(POLL);
        };
        // A descendant may keep a pipe open after the child exits; wait only
        // for the remaining budget and leave the reader behind on timeout.
        let collect = |receiver: mpsc::Receiver<Vec<u8>>| {
            receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()
                .filter(|bytes| bytes.len() as u64 <= MAX_OUTPUT_BYTES)
                .ok_or_else(|| io::Error::other("child output unreadable"))
        };
        Ok(Ran {
            success: status.success(),
            stdout: collect(stdout)?,
            stderr: collect(stderr)?,
        })
    }
}

fn read_detached(stream: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if stream
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_ok()
        {
            let _ = sender.send(bytes);
        }
    });
    receiver
}

#[cfg(test)]
#[path = "native_install_verdict_tests.rs"]
mod tests;
