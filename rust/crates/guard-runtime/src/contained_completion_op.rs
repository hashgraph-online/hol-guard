//! Native, one-use verification of a completed workspace-contained command.
//!
//! Python may record a proof after the contained runner returns, but only this
//! operation may read or consume that proof on the PostToolUse decision path.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use nix::fcntl::{open, openat, renameat, OFlag};
use nix::sys::stat::Mode;
use nix::time::{clock_gettime, ClockId};
use nix::unistd::{unlinkat, Uid, UnlinkatFlags};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const FEATURE: &str = "contained-completion-consume-v1";
const REQUEST_SCHEMA: &str = "guard-contained-completion-consume-request.v1";
const RESULT_SCHEMA: &str = "guard-contained-completion-consume-result.v1";
const PROOF_SCHEMA: &str = "guard-contained-completion.v2";
const DIRECTORY: &str = "contained-completions-v2";
const BINDING_PREFIX: &[u8] = b"guard-contained-completion-binding.v2\0";
const TTL_NS: u64 = 30_000_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumeRequest {
    schema: String,
    request_id: String,
    pub(crate) guard_home: String,
    workspace: String,
    harness: String,
    payload: Value,
    reviewed_output_sha256: String,
}

fn append_field(raw: &mut Vec<u8>, value: &str) -> Option<()> {
    let bytes = value.as_bytes();
    raw.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_be_bytes());
    raw.extend_from_slice(bytes);
    (raw.len() <= 1024 * 1024).then_some(())
}

fn binding(request: &ConsumeRequest) -> Option<String> {
    let payload = request.payload.as_object()?;
    if request.harness != "omp"
        || payload.get("tool_name")?.as_str()? != "bash"
        || payload.get("guard_contained_output_profile")?.as_str()?
            != "controller-contained-output.v1"
    {
        return None;
    }
    let workspace = std::fs::canonicalize(&request.workspace).ok()?;
    let workspace = workspace.to_str()?;
    let tool_input = payload.get("tool_input")?.as_object()?;
    if tool_input.len() != 1 {
        return None;
    }
    let command = tool_input.get("command")?.as_str()?;
    let fields = ["session_id", "tool_call_id", "config_path"]
        .map(|name| payload.get(name).and_then(Value::as_str));
    if fields
        .iter()
        .any(|field| field.is_none_or(|value| value.is_empty() || value.chars().count() > 4096))
    {
        return None;
    }
    let mut raw = BINDING_PREFIX.to_vec();
    append_field(&mut raw, &request.harness)?;
    append_field(&mut raw, workspace)?;
    for field in fields.into_iter().flatten() {
        append_field(&mut raw, field)?;
    }
    append_field(&mut raw, command)?;
    match payload.get("guard_execution_environment") {
        None | Some(Value::Null) => raw.push(0),
        Some(Value::Object(environment)) if environment.len() <= 128 => {
            raw.push(1);
            raw.extend_from_slice(&u32::try_from(environment.len()).ok()?.to_be_bytes());
            for (key, value) in environment {
                append_field(&mut raw, key)?;
                append_field(&mut raw, value.as_str()?)?;
            }
        }
        _ => return None,
    }
    (raw.len() <= 1024 * 1024).then(|| hex::encode(Sha256::digest(&raw)))
}

fn private_directory(file: &File) -> bool {
    file.metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == Uid::current().as_raw()
            && metadata.mode() & 0o7777 == 0o700
    })
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn open_private_directory(path: &Path) -> Option<File> {
    if !path.is_absolute() {
        return None;
    }
    let mut current = open("/", directory_flags(), Mode::empty()).ok()?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return None;
        };
        current = openat(&current, name, directory_flags(), Mode::empty()).ok()?;
    }
    let directory = File::from(current);
    private_directory(&directory).then_some(directory)
}

fn proof_directory(guard_home: &str) -> Option<File> {
    let home = open_private_directory(Path::new(guard_home))?;
    let directory = File::from(openat(&home, DIRECTORY, directory_flags(), Mode::empty()).ok()?);
    private_directory(&directory).then_some(directory)
}

struct Claim {
    directory: File,
    name: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let _ = unlinkat(
            self.directory.as_fd(),
            self.name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
}

fn claim_file(guard_home: &str, binding: &str) -> Option<(Claim, File)> {
    let directory = proof_directory(guard_home)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).ok()?;
    let name = format!("claimed-{}", hex::encode(nonce));
    renameat(directory.as_fd(), binding, directory.as_fd(), name.as_str()).ok()?;
    let claim = Claim { directory, name };
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let file =
        File::from(openat(&claim.directory, claim.name.as_str(), flags, Mode::empty()).ok()?);
    Some((claim, file))
}

fn proof_bytes(file: &mut File) -> Option<Vec<u8>> {
    let metadata = file.metadata().ok()?;
    let size = usize::try_from(metadata.len()).ok()?;
    if !metadata.is_file()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || size == 0
        || size > 8192
    {
        return None;
    }
    let mut raw = vec![0u8; size];
    file.read_exact(&mut raw).ok()?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing).ok()? != 0 {
        return None;
    }
    Some(raw)
}

fn monotonic_ns() -> Option<u64> {
    let now = clock_gettime(ClockId::CLOCK_MONOTONIC).ok()?;
    u64::try_from(now.tv_sec())
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(now.tv_nsec()).ok()?)
}

fn boot_id() -> Option<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()?
        .trim()
        .to_owned();
    (value.len() == 36 && value.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'))
        .then_some(value)
}

fn proof_digest(request: &ConsumeRequest) -> Option<String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
    {
        return None;
    }
    let payload = request.payload.as_object()?;
    if payload.get("hook_event_name")?.as_str()? != "PostToolUse" {
        return None;
    }
    let response = payload.get("tool_response")?.as_array()?;
    if response.len() != 1 {
        return None;
    }
    let output = response[0].as_object()?;
    if output.len() != 2 || output.get("type")?.as_str()? != "text" {
        return None;
    }
    let text = output.get("text")?.as_str()?;
    if text.len() > 1024 * 1024
        || request.reviewed_output_sha256 != hex::encode(Sha256::digest(text.as_bytes()))
    {
        return None;
    }
    let is_error = payload.get("is_error")?.as_bool()?;
    let binding = binding(request)?;
    let (_claim, mut file) = claim_file(&request.guard_home, &binding)?;
    let raw = proof_bytes(&mut file)?;
    let row: Value = serde_json::from_slice(&raw).ok()?;
    if serde_json::to_vec(&row).ok()? != raw {
        return None;
    }
    let row = row.as_object()?;
    if row.len() != 7
        || row.get("schema")?.as_str()? != PROOF_SCHEMA
        || row.get("binding")?.as_str()? != binding
        || row.get("output_sha256")?.as_str()? != request.reviewed_output_sha256
        || row.get("is_error")?.as_bool()? != is_error
        || row.get("boot_id")?.as_str()? != boot_id()?
    {
        return None;
    }
    let created = row.get("created_ns")?.as_u64()?;
    let expires = row.get("expires_ns")?.as_u64()?;
    let now = monotonic_ns()?;
    if created > now || now >= expires || expires.checked_sub(created)? != TTL_NS {
        return None;
    }
    Some(hex::encode(Sha256::digest(&raw)))
}

pub(crate) fn evaluate(request: &ConsumeRequest) -> Result<Vec<u8>, String> {
    crate::encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "status": "ok",
        "proof_digest": proof_digest(request),
    }))
}
