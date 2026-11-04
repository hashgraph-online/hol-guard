//! `verified-github-read --stdin`: what makes a public GitHub pull-request
//! read provable, ported from `runtime/verified_github_reads.py`
//! (`_validate_request`, `_pull_belongs_to_repository`, `_valid_pull_fields`,
//! `_proof`, `_source_digest` and `_ca_bundle_digest`).
//!
//! Python still sends the two credential-free GET requests through the
//! managed transport; this command checks what it may ask for and what came
//! back, and binds the proof:
//!
//! - `{"op": "plan", ...read}` answers the two exact API URLs and the
//!   `identity` the read runs under (the executor's source and the network
//!   policy, with the managed CA bundle's contents);
//! - `{"op": "compose", ...read, "identity", "tls_runtime",
//!   "repository_body", "pull_body"}` reads the two replies (base64, read up
//!   to one byte past the limit) and answers `{"stdout", "binding_digest"}`,
//!   or `{"verified": false}` when the replies or the identity do not prove
//!   the read.
//!
//! A request outside the reviewed shape is an error. Python turns every
//! answer other than a composed proof into ordinary review.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use guard_contracts::write_canonical_json;
use guard_runtime_pyjson::{parse, PyVal};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const VERIFIED_GITHUB_READ_VERSION: &str = "guard.verified-github-read.v1";
const VERIFIED_READ_POLICY_VERSION: &str = "guard.verified-read-policy.v1";
const VERIFIED_GITHUB_RULE_VERSION: &str = "guard.verified-read.github-public.v1";
const API_ORIGIN: &str = "https://api.github.com";
const FIELDS: [&str; 3] = ["mergeable", "number", "state"];
const MAX_PULL_NUMBER: u64 = 2_147_483_647;
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_IDENTITY_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Two base64 replies one byte past their limit, plus the other members.
const MAX_REQUEST_BYTES: u64 = 3 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Plan,
    Compose,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: Op,
    owner: String,
    repository: String,
    pull_number: u64,
    fields: Vec<String>,
    /// `ManagedNetworkPolicy.to_dict()`.
    network_policy: Map<String, Value>,
    ca_bundle_path: Option<String>,
    /// The Python module that sends the requests.
    executor_path: String,
    /// What `compose` carries: the planned identity, Python's TLS library and
    /// the two replies as base64.
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    tls_runtime: Option<String>,
    #[serde(default)]
    repository_body: Option<String>,
    #[serde(default)]
    pull_body: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "verified-github-read"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "verified_github_read_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("verified_github_read_request_too_large".to_owned());
    }
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(request)?)
        .map_err(|_| "verified_github_read_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "verified_github_read_request_invalid".to_owned()
}

fn answer(request: Value) -> Result<Value, String> {
    let read: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    let fields = checked_fields(&read)?;
    let composed = (
        &read.identity,
        &read.tls_runtime,
        &read.repository_body,
        &read.pull_body,
    );
    match (&read.op, composed) {
        (Op::Plan, (None, None, None, None)) => {
            let (repository_url, pull_url) = urls(&read);
            Ok(json!({
                "fields": fields,
                "urls": [repository_url, pull_url],
                "identity": identity(&read),
            }))
        }
        (
            Op::Compose,
            (Some(planned), Some(tls_runtime), Some(repository_body), Some(pull_body)),
        ) => {
            let repository_body = STANDARD.decode(repository_body).map_err(|_| invalid())?;
            let pull_body = STANDARD.decode(pull_body).map_err(|_| invalid())?;
            let unproven = json!({"verified": false});
            // The executor or the CA bundle changed while the read ran.
            let Value::String(identity) = identity(&read) else {
                return Ok(unproven);
            };
            if &identity != planned {
                return Ok(unproven);
            }
            let Some(stdout) = output(&read, &fields, &repository_body, &pull_body) else {
                return Ok(unproven);
            };
            let binding_digest = proof(
                &read,
                &fields,
                &identity,
                tls_runtime,
                &repository_body,
                &pull_body,
                &stdout,
            );
            Ok(json!({"stdout": stdout, "binding_digest": binding_digest}))
        }
        _ => Err(invalid()),
    }
}

/// `_validate_request`: static owner and repository names, a bounded pull
/// number and unique reviewed fields, which come back sorted.
fn checked_fields(read: &Request) -> Result<Vec<String>, String> {
    if !static_name(&read.owner) || !static_name(&read.repository) {
        return Err(invalid());
    }
    if !(1..=MAX_PULL_NUMBER).contains(&read.pull_number) {
        return Err(invalid());
    }
    let mut fields = read.fields.clone();
    fields.sort();
    fields.dedup();
    if fields.is_empty()
        || fields.len() != read.fields.len()
        || fields.iter().any(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err(invalid());
    }
    Ok(fields)
}

/// `[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})`, matched in full.
fn static_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && name.len() <= 100
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn urls(read: &Request) -> (String, String) {
    let repository = format!("{API_ORIGIN}/repos/{}/{}", read.owner, read.repository);
    let pull = format!("{repository}/pulls/{}", read.pull_number);
    (repository, pull)
}

/// The executor's source digest and the network policy digest, or `null`
/// when either identity file cannot be read within its bounds.
fn identity(read: &Request) -> Value {
    let Some(source) = identity_file_digest(Path::new(&read.executor_path)) else {
        return Value::Null;
    };
    let mut policy = read.network_policy.clone();
    if let Some(path) = &read.ca_bundle_path {
        let Some(digest) = identity_file_digest(Path::new(path)) else {
            return Value::Null;
        };
        policy.insert("caBundleSha256".to_owned(), Value::String(digest));
    }
    Value::String(framed_digest(&json!({
        "executor_source": source,
        "network_policy": framed_digest(&Value::Object(policy)),
    })))
}

/// The stdout a proven read prints, or `None` when the replies do not show
/// a public repository and one of its pull requests.
fn output(
    read: &Request,
    fields: &[String],
    repository_body: &[u8],
    pull_body: &[u8],
) -> Option<String> {
    let full_name = format!("{}/{}", read.owner, read.repository);
    let repository = reply(repository_body)?;
    if !matches!(repository.get("private"), Some(PyVal::Bool(false)))
        || !same_name(repository.get("full_name"), &full_name)
    {
        return None;
    }
    let pull = reply(pull_body)?;
    let number = match pull.get("number") {
        Some(PyVal::Int(digits)) => digits.parse::<u64>().ok()?,
        _ => return None,
    };
    let base_name = pull
        .get("base")
        .and_then(|base| base.get("repo"))
        .and_then(|repo| repo.get("full_name"));
    if number != read.pull_number || !same_name(base_name, &full_name) {
        return None;
    }
    let state = match pull.get("state").and_then(PyVal::as_str) {
        Some(state @ ("open" | "closed")) => state,
        _ => return None,
    };
    let mergeable = match pull.get("mergeable") {
        Some(PyVal::Bool(mergeable)) => Value::Bool(*mergeable),
        None | Some(PyVal::Null) => Value::Null,
        Some(_) => return None,
    };
    let mut shown = Map::new();
    for field in fields {
        let value = match field.as_str() {
            "number" => json!(number),
            "state" => json!(state),
            _ => mergeable.clone(),
        };
        shown.insert(field.clone(), value);
    }
    Some(format!(
        "{}\n",
        String::from_utf8(canonical(&Value::Object(shown))).ok()?
    ))
}

/// A reply as `json.loads` reads it, when it is one JSON object within the limit.
fn reply(body: &[u8]) -> Option<PyVal> {
    if body.len() > MAX_RESPONSE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    let value = parse(text.strip_prefix('\u{feff}').unwrap_or(text)).ok()?;
    value.as_dict().is_some().then_some(value)
}

/// GitHub's name for the repository, compared without case. The requested
/// name is ASCII, so a reply that spells it with other characters is not it.
fn same_name(observed: Option<&PyVal>, full_name: &str) -> bool {
    observed
        .and_then(PyVal::as_str)
        .is_some_and(|observed| observed.eq_ignore_ascii_case(full_name))
}

/// `_proof`: the digest that binds the read to its target, executor,
/// network identity, both replies and the output.
fn proof(
    read: &Request,
    fields: &[String],
    identity: &str,
    tls_runtime: &str,
    repository_body: &[u8],
    pull_body: &[u8],
    stdout: &str,
) -> String {
    let target = framed_digest(&json!({
        "host": "github.com",
        "owner": read.owner.to_ascii_lowercase(),
        "repository": read.repository.to_ascii_lowercase(),
        "pull_number": read.pull_number,
    }));
    framed_digest(&json!({
        "schema_version": VERIFIED_GITHUB_READ_VERSION,
        "policy_version": VERIFIED_READ_POLICY_VERSION,
        "rule_version": VERIFIED_GITHUB_RULE_VERSION,
        "operation": "github-public-pull-request-view",
        "target": target,
        "fields": fields,
        "method": "GET",
        "origin_credential_mode": "none",
        "network_transport": "enterprise-managed",
        "executor_identity": identity,
        "executor_runtime": "guard-runtime:verified-github-read.v1",
        "redirect_mode": "rejected",
        "tls_runtime": framed_digest(&json!(tls_runtime)),
        "repository_response": hex::encode(Sha256::digest(repository_body)),
        "pull_response": hex::encode(Sha256::digest(pull_body)),
        "output": framed_digest(&json!(stdout)),
        "parser": "structured-github-public-read-v1",
        "io_flow": "public-get/repository-preflight/pull-request-get/stdout-bounded",
        "expected_effects": ["network-read", "remote-state-read"],
    }))
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    // A `Value` holds no NaN and no lone surrogate, and the writer is
    // unbounded here, so the canonical encoding of one cannot fail.
    write_canonical_json(value, &mut encoded)
        .expect("a json value is always canonically encodable");
    encoded
}

/// `verified_read_digest`: SHA-256 over the canonical JSON, prefixed with its
/// length as eight big-endian bytes.
fn framed_digest(value: &Value) -> String {
    let payload = canonical(value);
    let mut digest = Sha256::new();
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(&payload);
    hex::encode(digest.finalize())
}

/// SHA-256 of a regular file of at most 4 MiB, opened without following a
/// final symlink and unchanged while it was read.
fn identity_file_digest(path: &Path) -> Option<String> {
    let mut file = open_without_following(path).ok()?;
    let before = file.metadata().ok()?;
    if !before.is_file() || before.len() > MAX_IDENTITY_FILE_BYTES {
        return None;
    }
    let mut payload = Vec::new();
    (&mut file)
        .take(MAX_IDENTITY_FILE_BYTES + 1)
        .read_to_end(&mut payload)
        .ok()?;
    let after = file.metadata().ok()?;
    if payload.len() as u64 > MAX_IDENTITY_FILE_BYTES || stable(&before) != stable(&after) {
        return None;
    }
    Some(hex::encode(Sha256::digest(&payload)))
}

#[cfg(unix)]
fn open_without_following(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_without_following(path: &Path) -> std::io::Result<File> {
    // Python had no `O_NOFOLLOW` on Windows either; a final reparse point is
    // refused here instead.
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::other("identity file is a link"));
    }
    File::open(path)
}

/// The fields that change when a file is replaced or rewritten.
#[cfg(unix)]
fn stable(metadata: &Metadata) -> (u64, u64, u64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

#[cfg(not(unix))]
fn stable(metadata: &Metadata) -> (u64, Option<std::time::SystemTime>) {
    (metadata.len(), metadata.modified().ok())
}

#[cfg(test)]
#[path = "verified_github_read_tests.rs"]
mod tests;
