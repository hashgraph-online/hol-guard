//! `desktop-foreign-remove --stdin`: retire the HOL Guard installs that
//! `desktop-foreign-inventory` found (`remove_foreign_installs` in
//! `guard/desktop_foreign_installs.py` before the removal moved here).
//!
//! The caller stops each venv's resident first and marks the venvs whose
//! resident would not stop; those keep their install. A `pip --user` copy is
//! uninstalled only after its interpreter confirms the package lives in its
//! own user site-packages, never in a system or distro install, and never
//! under the module that asked for the removal.
//!
//! The runtime runs with an isolated environment, so the caller sends the
//! variables a Python child needs to find its user site.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

const COMMAND: &str = "desktop-foreign-remove";
const SCHEMA: &str = "desktop-foreign-remove.v1";
/// Above the 4 MiB inventory answer the request is built from.
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const PIP_UNINSTALL_TIMEOUT: Duration = Duration::from_secs(120);
const USER_SITE_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_OUTPUT_LIMIT: u64 = 64 * 1024;
const NOT_INSTALLED_EXIT: i32 = 3;
/// Prints the user site-packages that holds hol-guard. Exits 3 when the
/// interpreter has no hol-guard and 4 when the copy it imports lives
/// elsewhere, so pip is never pointed at a system or distro install.
const USER_SITE_PROBE: &str = r#"
import importlib.metadata as metadata, os, site, sys
try:
    location = os.path.realpath(str(metadata.distribution("hol-guard").locate_file("")))
except metadata.PackageNotFoundError:
    sys.exit(3)
user_site = os.path.realpath(site.getusersitepackages())
if location != user_site:
    sys.exit(4)
print(location)
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    venvs: Vec<Venv>,
    stale_entries: Vec<String>,
    user_site: Vec<UserSite>,
    /// The resolved module that asked; its own install is never uninstalled.
    running_module: String,
    /// The variables each Python child runs with.
    environment: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Venv {
    kind: String,
    root: String,
    entries: Vec<String>,
    /// Whether every resident this venv runs stopped.
    retired: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserSite {
    interpreter: String,
    entries: Vec<String>,
}

#[derive(Default)]
struct Removal {
    removed: Vec<(String, String)>,
    entry_dirs: BTreeSet<String>,
    notes: Vec<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "desktop_foreign_remove_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("desktop_foreign_remove_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "desktop_foreign_remove_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("desktop_foreign_remove_request_invalid".to_owned());
    }
    let removal = remove(&request);
    let removed: Vec<_> = removal
        .removed
        .iter()
        .map(|(kind, path)| json!({"kind": kind, "path": path}))
        .collect();
    serde_json::to_vec(&json!({
        "removed": removed,
        "removed_entry_dirs": removal.entry_dirs,
        "notes": removal.notes,
    }))
    .map_err(|_| "desktop_foreign_remove_response_unencodable".to_owned())
}

fn remove(request: &Request) -> Removal {
    let mut removal = Removal::default();
    for venv in &request.venvs {
        if !venv.retired {
            removal.notes.push(format!(
                "Kept {}: its Guard runtime is still running.",
                venv.root
            ));
            continue;
        }
        for entry in &venv.entries {
            if unlink(entry) {
                removal.entry_dirs.insert(parent(entry));
            }
        }
        if let Err(error) = remove_tree(Path::new(&venv.root)) {
            removal
                .notes
                .push(format!("Could not remove {}: {error}.", venv.root));
            continue;
        }
        removal.removed.push((venv.kind.clone(), venv.root.clone()));
    }
    for entry in &request.stale_entries {
        if unlink(entry) {
            removal.entry_dirs.insert(parent(entry));
            removal
                .removed
                .push(("stale_link".to_owned(), entry.clone()));
        }
    }
    for site in &request.user_site {
        remove_user_site(request, site, &mut removal);
    }
    removal
}

fn remove_user_site(request: &Request, site: &UserSite, removal: &mut Removal) {
    let interpreter = &site.interpreter;
    let location = match user_site_location(interpreter, &request.environment) {
        Location::NotInstalled => {
            // The package is gone and only its console scripts remain.
            for entry in &site.entries {
                if unlink(entry) {
                    removal.entry_dirs.insert(parent(entry));
                    removal
                        .removed
                        .push(("stale_script".to_owned(), entry.clone()));
                }
            }
            return;
        }
        Location::UserSite(location) => location,
        Location::Unknown => String::new(),
    };
    if location.is_empty() || Path::new(&request.running_module).starts_with(&location) {
        removal.notes.push(format!(
            "Kept hol-guard for {interpreter}: it is not a separate pip --user install."
        ));
        return;
    }
    let arguments = ["-m", "pip", "uninstall", "-y", "hol-guard"];
    match run(
        interpreter,
        &arguments,
        &request.environment,
        PIP_UNINSTALL_TIMEOUT,
        false,
    ) {
        Err(error) => removal.notes.push(format!(
            "Could not uninstall hol-guard from {interpreter}: {error}."
        )),
        Ok((status, _)) if !status.success() => removal.notes.push(format!(
            "Could not uninstall hol-guard from {interpreter}: pip exited {}.",
            exit_code(status)
        )),
        Ok(_) => {
            removal
                .removed
                .push(("pip_user".to_owned(), interpreter.clone()));
            removal.entry_dirs.extend(
                site.entries
                    .iter()
                    .filter(|entry| !Path::new(entry).exists())
                    .map(|entry| parent(entry.as_str())),
            );
        }
    }
}

enum Location {
    NotInstalled,
    UserSite(String),
    Unknown,
}

/// `_user_site_location`: where the interpreter's hol-guard lives.
fn user_site_location(interpreter: &str, environment: &BTreeMap<String, String>) -> Location {
    let Ok((status, stdout)) = run(
        interpreter,
        &["-c", USER_SITE_PROBE],
        environment,
        USER_SITE_PROBE_TIMEOUT,
        true,
    ) else {
        return Location::Unknown;
    };
    if status.code() == Some(NOT_INSTALLED_EXIT) {
        return Location::NotInstalled;
    }
    let location = String::from_utf8_lossy(&stdout).trim().to_owned();
    if status.success() && !location.is_empty() && Path::new(&location).is_absolute() {
        Location::UserSite(location)
    } else {
        Location::Unknown
    }
}

/// Runs `program` with only `environment`, stdin and stderr closed, killing
/// it at `timeout`. Captures at most `PROBE_OUTPUT_LIMIT` bytes of stdout.
fn run(
    program: &str,
    arguments: &[&str],
    environment: &BTreeMap<String, String>,
    timeout: Duration,
    capture: bool,
) -> Result<(ExitStatus, Vec<u8>), String> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| strerror(&error))?;
    let (sender, receiver) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.take(PROBE_OUTPUT_LIMIT).read_to_end(&mut bytes);
            let _ = sender.send(bytes);
        });
    } else {
        let _ = sender.send(Vec::new());
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {} seconds", timeout.as_secs()));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(strerror(&error));
            }
        }
    };
    // A descendant may hold stdout open; detach the reader when it does.
    let stdout = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_default();
    Ok((status, stdout))
}

/// `shutil.rmtree`, which refuses a symbolic link rather than deleting it.
fn remove_tree(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| strerror(&error))?;
    if metadata.file_type().is_symlink() {
        return Err("Cannot call rmtree on a symbolic link".to_owned());
    }
    fs::remove_dir_all(root).map_err(|error| strerror(&error))
}

fn unlink(path: &str) -> bool {
    fs::remove_file(path).is_ok()
}

fn parent(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The OS message alone, as `OSError.strerror` reads it.
fn strerror(error: &io::Error) -> String {
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(index) if text.ends_with(')') => text[..index].to_owned(),
        _ => text,
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    // A signal-killed pip reads as Python's negative returncode.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return -signal;
        }
    }
    status.code().unwrap_or(-1)
}

#[cfg(test)]
#[path = "desktop_foreign_remove_tests.rs"]
mod tests;
