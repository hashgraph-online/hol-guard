//! `posix-processes --stdin`: the bounded POSIX process queries the daemon
//! ownership checks read (`guard/daemon/manager_process_query.py` before it
//! moved here).
//!
//! - `inventory` answers `ps -axo pid=,command=` as `listing`, or, on Linux
//!   without a trusted `ps`, every `/proc/<pid>/cmdline` as `entries`.
//! - `elapsed` answers `ps -axo pid=,etime=,command=` as `listing`.
//! - `parent` answers the parent process id of `pid`.
//! - `command` answers the command line of `pid`.
//!
//! `ps` is only run from `/bin/ps` or `/usr/bin/ps`, resolved to a regular
//! executable file, with a clean `C` locale. A query that fails, exits
//! non-zero, takes longer than five seconds, writes more than 1 MiB or is not
//! UTF-8 answers `null`: callers read that as "cannot be proven". The procfs
//! inventory shares the same 1 MiB budget, and an unreadable or oversized
//! process table answers `null` as well, since an incomplete list could hide
//! a running daemon. Off POSIX every answer is `null`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_request_text::py_strip;
use crate::onefile_open_paths::bounded_stdout;

const SCHEMA: &str = "posix-processes.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_LIMIT_BYTES: u64 = 1024 * 1024;
const TRUSTED_PS_PATHS: [&str; 2] = ["/bin/ps", "/usr/bin/ps"];
const PROC_ROOT: &str = "/proc";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    pid: Option<i64>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "posix-processes"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "posix_processes_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("posix_processes_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let host = Host {
        ps: trusted_ps_path(),
        proc_root: cfg!(target_os = "linux").then(|| PathBuf::from(PROC_ROOT)),
        timeout: QUERY_TIMEOUT,
        output_limit: OUTPUT_LIMIT_BYTES,
    };
    let answer = answer(&request, &host)?;
    serde_json::to_vec(&answer).map_err(|_| "posix_processes_response_unencodable".to_owned())
}

/// Where the queries run: the trusted `ps`, the procfs root used without
/// one, and the bounds every query shares.
struct Host {
    ps: Option<PathBuf>,
    proc_root: Option<PathBuf>,
    timeout: Duration,
    output_limit: u64,
}

fn answer(request: &Request, host: &Host) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    match (request.op.as_str(), request.pid) {
        ("inventory", None) => Ok(inventory(host)),
        ("elapsed", None) => Ok(json!({ "listing": ps(host, &["-axo", "pid=,etime=,command="]) })),
        ("parent", Some(pid)) if pid > 0 => {
            let parent = ps(host, &["-p", &pid.to_string(), "-o", "ppid="])
                .and_then(|output| py_strip(&output).parse::<i64>().ok())
                .filter(|parent| *parent > 0);
            Ok(json!({ "parent_pid": parent }))
        }
        ("command", Some(pid)) if pid > 0 => {
            let command = ps(host, &["-p", &pid.to_string(), "-o", "command="])
                .map(|output| py_strip(&output).to_owned())
                .filter(|command| !command.is_empty());
            Ok(json!({ "command": command }))
        }
        _ => Err(invalid()),
    }
}

fn inventory(host: &Host) -> Value {
    if host.ps.is_some() {
        return json!({ "listing": ps(host, &["-axo", "pid=,command="]), "entries": null });
    }
    let entries = host
        .proc_root
        .as_deref()
        .and_then(|root| proc_entries(root, host.output_limit));
    json!({ "listing": null, "entries": entries })
}

/// The trusted `ps` run with `arguments`, its stdout as UTF-8 text.
fn ps(host: &Host, arguments: &[&str]) -> Option<String> {
    let ps = host.ps.as_deref()?;
    let mut command = Command::new(ps);
    command
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C");
    let stdout = bounded_stdout(command, host.output_limit, host.timeout)?;
    String::from_utf8(stdout).ok()
}

/// `/bin/ps` or `/usr/bin/ps`, resolved, when it is a regular file this
/// process may execute.
#[cfg(unix)]
fn trusted_ps_path() -> Option<PathBuf> {
    TRUSTED_PS_PATHS.iter().find_map(|raw| {
        let resolved = fs::canonicalize(raw).ok()?;
        let regular = fs::metadata(&resolved).ok()?.is_file();
        let executable = nix::unistd::access(&resolved, nix::unistd::AccessFlags::X_OK).is_ok();
        (regular && executable).then_some(resolved)
    })
}

#[cfg(not(unix))]
fn trusted_ps_path() -> Option<PathBuf> {
    let _ = TRUSTED_PS_PATHS;
    None
}

/// Every process under `root` with a non-empty command line, its NUL
/// separators read as spaces. A missing process was simply gone; any other
/// read failure, or command lines past `budget` bytes in total, answer
/// `None`.
fn proc_entries(root: &Path, budget: u64) -> Option<Vec<(i64, String)>> {
    let mut remaining = budget;
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Some(pid) = name.parse::<i64>().ok().filter(|pid| *pid > 0) else {
            continue;
        };
        let mut raw = Vec::new();
        match fs::File::open(entry.path().join("cmdline")) {
            Ok(file) => {
                file.take(remaining + 1).read_to_end(&mut raw).ok()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        }
        if raw.len() as u64 > remaining {
            return None;
        }
        remaining -= raw.len() as u64;
        while raw.last() == Some(&0) {
            raw.pop();
        }
        let raw: Vec<u8> = raw
            .into_iter()
            .map(|byte| if byte == 0 { b' ' } else { byte })
            .collect();
        let text = String::from_utf8_lossy(&raw);
        let command = py_strip(&text);
        if !command.is_empty() {
            entries.push((pid, command.to_owned()));
        }
    }
    Some(entries)
}

fn invalid() -> String {
    "posix_processes_request_invalid".to_owned()
}

#[cfg(test)]
#[path = "posix_processes_tests.rs"]
mod tests;
