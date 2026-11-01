//! `macos-code-signing --stdin`: Apple code-signature checks for the Desktop
//! Core updater and the Desktop hook proxy.
//!
//! - `team` verifies one executable or bundle with the pinned `codesign` and
//!   reads its Team ID. An unsigned, ad hoc or unverifiable signature has no
//!   team.
//! - `sealed` says whether a onedir launcher is signed as an app bundle whose
//!   resources are sealed (`_CodeSignature/CodeResources`, sealed resources
//!   version 2).
//! - `tree` checks that every Mach-O file in an extracted onedir tree carries
//!   the expected team, and answers the first failure as the updater's reason
//!   code.
//!
//! Every check runs the same pinned path on every platform; a host without
//! `codesign` simply has no verified signature.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::native_install_verdict::{Invocation, Runner, SystemRunner};

const SCHEMA: &str = "macos-code-signing.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const CODESIGN: &str = "/usr/bin/codesign";
const MAX_TIMEOUT_MS: u64 = 120_000;
const SEAL_TIMEOUT: Duration = Duration::from_secs(30);
const TREE_FILE_TIMEOUT: Duration = Duration::from_secs(5);
/// More entries than any onedir build ships; a larger tree is refused rather
/// than walked without end.
const MAX_TREE_ENTRIES: usize = 200_000;
const MACHO_MAGICS: [[u8; 4]; 8] = [
    [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xca, 0xfe, 0xba, 0xbe],
    [0xca, 0xfe, 0xba, 0xbf],
    [0xbe, 0xba, 0xfe, 0xca],
    [0xbf, 0xba, 0xfe, 0xca],
];

const INSTALL_FAILED: &str = "desktop_core_install_failed";
const SIGNATURE_INVALID: &str = "desktop_core_signature_invalid";
const SIGNATURE_MISMATCH: &str = "desktop_core_signature_mismatch";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    deep: bool,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    expected_team: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "macos-code-signing"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "macos_code_signing_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("macos_code_signing_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request, &mut SystemRunner)?;
    serde_json::to_vec(&answer).map_err(|_| "macos_code_signing_response_unencodable".to_owned())
}

fn answer(request: &Request, runner: &mut impl Runner) -> Result<Value, String> {
    let path = request
        .path
        .as_deref()
        .filter(|path| Path::new(path).is_absolute())
        .ok_or_else(invalid)?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    match (
        request.op.as_str(),
        request.timeout_ms,
        request.expected_team.as_deref(),
    ) {
        ("team", Some(timeout_ms), None) if (1..=MAX_TIMEOUT_MS).contains(&timeout_ms) => {
            let timeout = Duration::from_millis(timeout_ms);
            Ok(json!({ "team": signing_team(runner, path, request.deep, timeout) }))
        }
        ("sealed", None, None) if !request.deep => {
            Ok(json!({ "sealed": sealed(runner, Path::new(path)) }))
        }
        ("tree", None, Some(expected_team)) if !request.deep && !expected_team.is_empty() => {
            Ok(json!({ "failure": tree_failure(runner, Path::new(path), expected_team) }))
        }
        _ => Err(invalid()),
    }
}

fn codesign(arguments: &[&str], timeout: Duration) -> Invocation {
    Invocation {
        program: CODESIGN.to_owned(),
        arguments: arguments.iter().map(|item| (*item).to_owned()).collect(),
        context: None,
        timeout,
    }
}

/// The verified Team ID, or `None` for a signature that does not verify,
/// carries no team or could not be read.
fn signing_team(
    runner: &mut impl Runner,
    path: &str,
    deep: bool,
    timeout: Duration,
) -> Option<String> {
    let mut verify = vec!["--verify"];
    if deep {
        verify.push("--deep");
    }
    verify.extend(["--strict", path]);
    let verified = runner.run(&codesign(&verify, timeout)).ok()?;
    let details = runner
        .run(&codesign(&["--display", "--verbose=4", path], timeout))
        .ok()?;
    if !verified.success || !details.success {
        return None;
    }
    let details = String::from_utf8_lossy(&details.stderr);
    let team = details
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))?
        .trim();
    (!team.is_empty() && team != "not set").then(|| team.to_owned())
}

fn sealed(runner: &mut impl Runner, launcher: &Path) -> bool {
    let Some(parent) = launcher.parent() else {
        return false;
    };
    if !parent
        .join("_CodeSignature")
        .join("CodeResources")
        .is_file()
    {
        return false;
    }
    let Some(launcher) = launcher.to_str() else {
        return false;
    };
    let Ok(details) = runner.run(&codesign(
        &["--display", "--verbose=4", launcher],
        SEAL_TIMEOUT,
    )) else {
        return false;
    };
    let mut output = String::from_utf8_lossy(&details.stderr).into_owned();
    output.push_str(&String::from_utf8_lossy(&details.stdout));
    details.success
        && output.contains("Format=app bundle")
        && output.contains("Sealed Resources version=2")
}

/// The updater's reason code for the first Mach-O file, in path order, that
/// does not carry `expected_team`; `None` when every one does.
fn tree_failure(
    runner: &mut impl Runner,
    tree: &Path,
    expected_team: &str,
) -> Option<&'static str> {
    if !tree.join("_internal").is_dir() {
        return Some(INSTALL_FAILED);
    }
    let Ok(mut files) = regular_files(tree) else {
        return Some(INSTALL_FAILED);
    };
    // Component by component, as Python orders paths: `a/b` before `a-c`.
    files.sort_by(|left, right| left.components().cmp(right.components()));
    for file in files.iter().filter(|file| is_macho(file)) {
        let Some(path) = file.to_str() else {
            return Some(SIGNATURE_INVALID);
        };
        match signing_team(runner, path, false, TREE_FILE_TIMEOUT) {
            None => return Some(SIGNATURE_INVALID),
            Some(team) if team != expected_team => return Some(SIGNATURE_MISMATCH),
            Some(_) => {}
        }
    }
    None
}

/// Every regular file under `root`, without following links. A directory
/// that cannot be read fails the walk, so no file is left unchecked.
fn regular_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            seen += 1;
            if seen > MAX_TREE_ENTRIES {
                return Err(io::Error::other("tree too large"));
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    Ok(files)
}

fn is_macho(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok_and(|()| MACHO_MAGICS.contains(&magic))
}

fn invalid() -> String {
    "macos_code_signing_request_invalid".to_owned()
}

#[cfg(test)]
#[path = "macos_code_signing_tests.rs"]
mod tests;
