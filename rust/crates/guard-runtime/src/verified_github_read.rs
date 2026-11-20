//! `verified-github-read --stdin`: one credential-free read of a public
//! GitHub pull request, and the proof that binds it, ported from
//! `runtime/verified_github_reads.py`.
//!
//! `{"op": "read", "owner", "repository", "pull_number", "fields",
//! "timeout_seconds"}` resolves the machine's managed network policy, sends
//! the two exact GET requests to the public API under it (no credential, no
//! redirect, each reply bounded at 1 MiB) and answers `{"stdout",
//! "binding_digest"}`, or `{"verified": false}` when the policy cannot be
//! honoured, an exchange fails, the replies do not show a public repository
//! and one of its pull requests, or the network identity changed during the
//! read.
//!
//! A request outside the reviewed shape is an error. Python turns every
//! answer other than a composed proof into ordinary review.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

use guard_command::egress_caller::policy_get_with_headers;
use guard_command::egress_caller_policy::{ManagedEgressPolicy, ManagedNetworkPolicy, ProxyMode};
use guard_contracts::write_canonical_json;
use guard_runtime_pyjson::{parse, PyVal};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::managed_policy_load::ManagedPolicySource;
use crate::supply_chain_eval_caller::caller_network_policy;

const VERIFIED_GITHUB_READ_VERSION: &str = "guard.verified-github-read.v1";
const VERIFIED_READ_POLICY_VERSION: &str = "guard.verified-read-policy.v1";
const VERIFIED_GITHUB_RULE_VERSION: &str = "guard.verified-read.github-public.v1";
const API_ORIGIN: &str = "https://api.github.com";
/// The executor the proof names: this runtime build sends the requests.
const EXECUTOR: &str = concat!("hol-guard-runtime/", env!("CARGO_PKG_VERSION"));
/// The TLS stack the exchanges run on.
const TLS_RUNTIME: &str = "rustls";
const FIELDS: [&str; 3] = ["mergeable", "number", "state"];
const MAX_PULL_NUMBER: u64 = 2_147_483_647;
const MAX_TIMEOUT_SECONDS: f64 = 30.0;
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_IDENTITY_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Read,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Only `read` is accepted.
    #[serde(rename = "op")]
    _op: Op,
    owner: String,
    repository: String,
    pull_number: u64,
    fields: Vec<String>,
    /// Each of the two exchanges gets this long.
    timeout_seconds: f64,
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
    let (read, fields) = checked(request)?;
    let answer = match caller_network_policy(&ManagedPolicySource::native()) {
        Ok(network) => match ManagedEgressPolicy::resolve(&network) {
            Ok(egress) => compose_read(&read, &fields, &network, |url| {
                public_get(url, read.timeout_seconds, &egress)
            }),
            Err(_) => unproven(),
        },
        Err(_) => unproven(),
    };
    serde_json::to_vec(&answer)
        .map_err(|_| "verified_github_read_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "verified_github_read_request_invalid".to_owned()
}

fn unproven() -> Value {
    json!({"verified": false})
}

/// The request and its sorted fields, when it has the reviewed shape.
fn checked(request: Value) -> Result<(Request, Vec<String>), String> {
    let read: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    let timeout = read.timeout_seconds;
    if !timeout.is_finite() || timeout <= 0.0 || timeout > MAX_TIMEOUT_SECONDS {
        return Err(invalid());
    }
    let fields = checked_fields(&read)?;
    Ok((read, fields))
}

/// Read both resources through `get` and compose the proof, or answer
/// `{"verified": false}`. `get` answers a 200 reply's body.
fn compose_read(
    read: &Request,
    fields: &[String],
    network: &ManagedNetworkPolicy,
    mut get: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Value {
    let Some(planned) = identity(network) else {
        return unproven();
    };
    let (repository_url, pull_url) = urls(read);
    let Some(repository_body) = get(&repository_url) else {
        return unproven();
    };
    let Some(pull_body) = get(&pull_url) else {
        return unproven();
    };
    // The CA bundle changed while the read ran.
    if identity(network).as_deref() != Some(planned.as_str()) {
        return unproven();
    }
    let Some(stdout) = output(read, fields, &repository_body, &pull_body) else {
        return unproven();
    };
    let binding_digest = proof(
        read,
        fields,
        &planned,
        &repository_body,
        &pull_body,
        &stdout,
    );
    json!({"stdout": stdout, "binding_digest": binding_digest})
}

/// One credential-free GET under the managed policy: the body of a 200
/// reply within the bound, with no redirect followed.
fn public_get(url: &str, seconds: f64, egress: &ManagedEgressPolicy) -> Option<Vec<u8>> {
    let headers = BTreeMap::from([
        (
            "Accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        ),
        // Identity encoding keeps the byte bound equal to the decoded bound.
        ("Accept-Encoding".to_owned(), "identity".to_owned()),
        (
            "User-Agent".to_owned(),
            "hol-guard-verified-read".to_owned(),
        ),
        ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
    ]);
    let cap = u64::try_from(MAX_RESPONSE_BYTES).ok()?;
    match policy_get_with_headers(url, headers, seconds, 0, cap, egress) {
        Ok((200, _, body)) => Some(body),
        _ => None,
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

/// `ManagedNetworkPolicy.to_dict()`, the policy as the proof names it.
fn policy_dict(network: &ManagedNetworkPolicy) -> Map<String, Value> {
    let mode = match network.proxy_mode {
        ProxyMode::None => "none",
        ProxyMode::System => "system",
        ProxyMode::Explicit => "explicit",
    };
    let mut policy = Map::new();
    policy.insert("proxyMode".to_owned(), json!(mode));
    policy.insert(
        "proxyConfigured".to_owned(),
        json!(network.proxy_url.is_some()),
    );
    policy.insert(
        "caBundleConfigured".to_owned(),
        json!(network.ca_bundle_path.is_some()),
    );
    policy.insert(
        "allowPublicRegistries".to_owned(),
        json!(network.allow_public_registries),
    );
    policy
}

/// The executor and the network policy digest, with the managed CA bundle's
/// contents, or `None` when that bundle cannot be read within its bounds.
fn identity(network: &ManagedNetworkPolicy) -> Option<String> {
    let mut policy = policy_dict(network);
    if let Some(path) = &network.ca_bundle_path {
        let digest = identity_file_digest(path)?;
        policy.insert("caBundleSha256".to_owned(), Value::String(digest));
    }
    Some(framed_digest(&json!({
        "executor_source": EXECUTOR,
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
        "tls_runtime": framed_digest(&json!(TLS_RUNTIME)),
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
