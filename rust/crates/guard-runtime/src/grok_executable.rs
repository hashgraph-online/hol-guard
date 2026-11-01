//! `grok-executable --stdin`: find, verify and register the trusted Grok
//! launcher (`guard/adapters/grok_executable.py` finds the PATH candidate and
//! frames the request).
//!
//! - `resolve` takes the explicit selection, else the saved registration, else
//!   the automatic PATH candidate, which must sit in a known installation
//!   root. The launcher may not come from the workspace, the Guard home or the
//!   cwd, and its content hash is returned for the launch to bind to.
//! - `register` re-verifies an explicit selection and saves it, hash-bound, as
//!   `managed/grok/trusted-executable.json` under the Guard home.
//! - `launch-env` names the inherited variables to drop and rebuilds PATH from
//!   its safe entries. Only variable names, PATH and GROK_HOME cross over.
//!
//! Every rejection is a fixed, non-sensitive sentence.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::encrypted_secret_store::random_bytes;
use crate::grok_executable_paths::{expand, security_error, strict, Context};
use crate::pyjson::{parse, PyVal};

const SCHEMA: &str = "grok-executable.v1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_ENV_KEYS: usize = 4096;
const MAX_REGISTRATION_BYTES: u64 = 64 * 1024;
const REGISTRATION_FILE: &str = "trusted-executable.json";
const NAMES: [&str; 5] = ["grok", "grok.exe", "grok.cmd", "grok.bat", "grok.com"];
const UNSAFE_KEYS: [&str; 12] = [
    "BASH_ENV",
    "CDPATH",
    "ENV",
    "GIT_EXEC_PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYOPT",
];
const NOT_FOUND: &str = "Grok executable was not found in a trusted installation location.";
const SAVE_FAILED: &str = "The Grok executable registration could not be saved.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: String,
    home_dir: String,
    #[serde(default)]
    workspace_dir: Option<String>,
    cwd: String,
    #[serde(default)]
    windows_roots: Vec<String>,
    #[serde(default)]
    explicit: Option<String>,
    #[serde(default)]
    candidate: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_value: Option<String>,
    #[serde(default)]
    grok_home: Option<String>,
    #[serde(default)]
    env_keys: Vec<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "grok-executable"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "grok_executable_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("grok_executable_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    answer(&request).map(|value| value.to_string().into_bytes())
}

fn invalid() -> String {
    "grok_executable_request_invalid".to_owned()
}

fn absolute(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(invalid())
    }
}

fn answer(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA || request.windows_roots.len() > 3 {
        return Err(invalid());
    }
    let context = Context::new(
        absolute(&request.home_dir)?,
        absolute(&request.guard_home)?,
        request.workspace_dir.as_deref().map(absolute).transpose()?,
        absolute(&request.cwd)?,
        request
            .windows_roots
            .iter()
            .filter(|root| !root.is_empty())
            .map(PathBuf::from)
            .collect(),
    );
    let launch_fields =
        request.path_value.is_some() || request.grok_home.is_some() || !request.env_keys.is_empty();
    let selection_fields = request.explicit.is_some() || request.candidate.is_some();
    match request.op.as_str() {
        "resolve" if request.path.is_none() && !launch_fields => {
            let resolution = resolve(
                &context,
                request.explicit.as_deref(),
                request.candidate.as_deref(),
            );
            Ok(resolution_json(resolution))
        }
        "register" if !selection_fields && !launch_fields => {
            let path = request.path.as_deref().ok_or_else(invalid)?;
            Ok(register(&context, path))
        }
        "launch-env"
            if request.path.is_none()
                && !selection_fields
                && request.env_keys.len() <= MAX_ENV_KEYS =>
        {
            Ok(launch_environment(
                &context,
                request.path_value.as_deref(),
                request.grok_home.as_deref(),
                &request.env_keys,
            ))
        }
        _ => Err(invalid()),
    }
}

struct Trusted {
    path: String,
    sha256: String,
    source: &'static str,
}

impl Trusted {
    fn to_json(&self) -> Value {
        json!({ "path": self.path, "content_sha256": self.sha256, "source": self.source })
    }
}

fn resolution_json(resolution: Result<Trusted, &'static str>) -> Value {
    match resolution {
        Ok(trusted) => json!({ "executable": trusted.to_json(), "error": null }),
        Err(error) => json!({ "executable": null, "error": error }),
    }
}

/// `resolve_trusted_grok_executable`.
fn resolve(
    context: &Context,
    explicit: Option<&str>,
    candidate: Option<&str>,
) -> Result<Trusted, &'static str> {
    if let Some(explicit) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        return resolve_candidate(context, explicit, "explicit", false);
    }
    if let Some(registered) = registered(context) {
        return registered;
    }
    let candidate = candidate.ok_or(NOT_FOUND)?;
    resolve_candidate(context, candidate, "automatic", true)
}

/// `_resolve_candidate`.
fn resolve_candidate(
    context: &Context,
    value: &str,
    source: &'static str,
    require_automatic_root: bool,
) -> Result<Trusted, &'static str> {
    let candidate = expand(value, &context.home);
    if !candidate.is_absolute() {
        return Err("Grok executable paths must be absolute.");
    }
    if context.blocked(&candidate) {
        return Err("Grok executable paths cannot come from the workspace or Guard cwd.");
    }
    if require_automatic_root && !context.automatic_root(&candidate) {
        return Err(
            "Grok was found on PATH outside a trusted installation root; select it once with --grok-executable.",
        );
    }
    let unresolvable = "The selected Grok executable cannot be resolved.";
    let resolved = strict(&candidate).ok_or(unresolvable)?;
    let text = resolved.to_str().ok_or(unresolvable)?.to_owned();
    if context.blocked(&resolved) {
        return Err("Grok executable symlink targets cannot be inside the workspace.");
    }
    if !valid_name(&candidate, false) || !valid_name(&resolved, true) {
        return Err("The selected file is not a Grok executable.");
    }
    security_error(&candidate, &resolved)?;
    let sha256 =
        file_sha256(&resolved).map_err(|_| "The selected Grok executable could not be hashed.")?;
    Ok(Trusted {
        path: text,
        sha256,
        source,
    })
}

/// `_valid_executable_name`. Package-manager launchers commonly link a
/// trusted `grok` entry to a versioned target, so a target may carry any
/// name; its root, permissions and content are still verified.
fn valid_name(path: &Path, allow_target_name: bool) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    NAMES.contains(&name.as_str()) || (allow_target_name && !name.is_empty())
}

fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn registration_path(context: &Context) -> PathBuf {
    context
        .guard_home
        .join("managed")
        .join("grok")
        .join(REGISTRATION_FILE)
}

/// `_registered_executable`: `None` when nothing was registered.
fn registered(context: &Context) -> Option<Result<Trusted, &'static str>> {
    let path = registration_path(context);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return None;
        }
        Err(_) => {
            return Some(Err(
                "The saved Grok executable registration cannot be inspected.",
            ))
        }
    };
    Some(registered_file(context, &path, &metadata))
}

fn registered_file(
    context: &Context,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Trusted, &'static str> {
    if !metadata.is_file() {
        return Err("The saved Grok executable registration is not a regular file.");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = crate::grok_executable_paths::owner_trusted(metadata.uid());
        if !owner || metadata.mode() & 0o022 != 0 {
            return Err(
                "The saved Grok executable registration has unsafe ownership or permissions.",
            );
        }
    }
    let unreadable = "The saved Grok executable registration is unreadable.";
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_REGISTRATION_BYTES + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| unreadable)?;
    if bytes.len() as u64 > MAX_REGISTRATION_BYTES {
        return Err(unreadable);
    }
    let text = String::from_utf8(bytes).map_err(|_| unreadable)?;
    let payload = parse(&text).map_err(|_| unreadable)?;
    if !matches!(payload, PyVal::Dict(_)) || !payload.get("schemaVersion").is_some_and(is_one) {
        return Err("The saved Grok executable registration has an unsupported format.");
    }
    let (Some(registered_path), Some(registered_hash)) = (
        payload.get("path").and_then(PyVal::as_str),
        payload.get("sha256").and_then(PyVal::as_str),
    ) else {
        return Err("The saved Grok executable registration is incomplete.");
    };
    let trusted = resolve_candidate(context, registered_path, "registration", false)?;
    if !same_digest(&trusted.sha256, registered_hash) {
        return Err(
            "The registered Grok executable changed; select the updated file again with --grok-executable.",
        );
    }
    Ok(trusted)
}

/// `value == 1` in Python, where `True` and `1.0` also compare equal.
fn is_one(value: &PyVal) -> bool {
    match value {
        PyVal::Int(digits) => digits == "1",
        PyVal::Float(number) => *number == 1.0,
        PyVal::Bool(flag) => *flag,
        _ => false,
    }
}

/// `hmac.compare_digest`: the comparison time does not depend on where the
/// digests first differ.
fn same_digest(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// `register_trusted_grok_executable`.
fn register(context: &Context, path: &str) -> Value {
    let trusted = match resolve_candidate(context, path, "explicit", false) {
        Ok(trusted) => trusted,
        Err(error) => return json!({ "executable": null, "error": error, "trusted": false }),
    };
    let registered = Trusted {
        source: "registration",
        ..trusted
    };
    match write_registration(context, &registered) {
        Ok(()) => json!({ "executable": registered.to_json(), "error": null, "trusted": true }),
        Err(_) => json!({ "executable": null, "error": SAVE_FAILED, "trusted": true }),
    }
}

fn write_registration(context: &Context, trusted: &Trusted) -> std::io::Result<()> {
    let path = registration_path(context);
    let directory = path.parent().ok_or(ErrorKind::InvalidInput)?;
    create_private_directory(directory)?;
    let registered_at = registered_at().ok_or(ErrorKind::InvalidData)?;
    let payload = json!({
        "schemaVersion": 1,
        "path": trusted.path,
        "sha256": trusted.sha256,
        "registeredAt": registered_at,
    });
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json_with_limit(&payload, &mut bytes, usize::MAX, "encode")
        .map_err(|_| ErrorKind::InvalidData)?;
    bytes.push(b'\n');
    let temporary = directory.join(format!(
        ".{REGISTRATION_FILE}.{}",
        hex::encode(random_bytes(8))
    ));
    let result = write_private(&temporary, &bytes).and_then(|()| fs::rename(&temporary, &path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// The state directory is made owner-only; directories above it keep the
/// default mode.
fn create_private_directory(directory: &Path) -> std::io::Result<()> {
    if let Some(parent) = directory.parent() {
        fs::create_dir_all(parent)?;
    }
    match private_directory_builder().create(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn private_directory_builder() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

#[cfg(not(unix))]
fn private_directory_builder() -> fs::DirBuilder {
    fs::DirBuilder::new()
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// `datetime.now(timezone.utc).isoformat()` with `Z` for the offset.
fn registered_at() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).ok()?, "Z")
}

/// `sanitized_grok_launch_environment`: the inherited variables to drop and
/// the PATH to launch with.
fn launch_environment(
    context: &Context,
    path_value: Option<&str>,
    grok_home: Option<&str>,
    keys: &[String],
) -> Value {
    let mut dropped: Vec<&str> = keys
        .iter()
        .map(String::as_str)
        .filter(|key| UNSAFE_KEYS.contains(key) || key.starts_with("DYLD_"))
        .collect();
    let grok_home = grok_home.filter(|value| !value.is_empty());
    if grok_home.is_some_and(|value| context.blocked(&expand(value, &context.home))) {
        dropped.push("GROK_HOME");
    }
    json!({ "path": context.sanitized_path(path_value), "drop": dropped })
}

#[cfg(test)]
#[path = "grok_executable_tests.rs"]
mod tests;
