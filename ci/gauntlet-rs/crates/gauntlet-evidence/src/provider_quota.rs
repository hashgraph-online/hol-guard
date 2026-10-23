//! Read-only Python v1 provider-quota journal verification.
//!
//! This reader takes outside config and allowance pins, shares the Python
//! writer's lock, and never grants provider admission or resets a journal.

use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::payload::exact_keys;
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use rustix::fs::{
    flock, fstat, openat, statat, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat,
};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_LOG: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 30_000;

pub(super) fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

pub(super) fn unchanged(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn hex32(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 32
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sha_value(value: &Value) -> bool {
    value.as_str().is_some_and(is_sha256)
}

pub(super) fn bounded(value: &Value, minimum: u64, maximum: u64) -> Result<u64> {
    value
        .as_u64()
        .filter(|number| (minimum..=maximum).contains(number))
        .ok_or(invalid("quota integer outside its explicit bound"))
}

fn decode(raw: &[u8]) -> Result<Value> {
    let canonical = canonicalize(raw).map_err(|_| invalid("invalid bounded quota JSON"))?;
    serde_json::from_slice(&canonical).map_err(|_| invalid("invalid bounded quota JSON"))
}

pub(super) fn digest(value: &Value) -> Result<String> {
    Ok(sha256(&canonical_value(value)?))
}

pub(super) fn root_owned_by_reader(root: &Path, descriptor: &OwnedFd) -> Result<()> {
    if root.canonicalize().ok().as_deref() != Some(root) {
        return Err(invalid("canonical absolute quota directory required"));
    }
    let current = fstat(descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    let user = geteuid().as_raw();
    if FileType::from_raw_mode(current.st_mode) != FileType::Directory
        || current.st_uid != user
        || [10001, 10004].contains(&user)
        || current.st_mode & 0o7777 != 0o700
    {
        return Err(invalid("quota storage is not private to its provider"));
    }
    for parent in root.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || ![0, user].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(invalid(
                "quota ancestry is writable outside provider authority",
            ));
        }
    }
    Ok(())
}

pub(super) fn private_file(root: &OwnedFd, name: &str) -> Result<(OwnedFd, Stat)> {
    let descriptor = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid("required durable quota state is missing or inaccessible"))?;
    let observed = fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    let path = statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    if FileType::from_raw_mode(observed.st_mode) != FileType::RegularFile
        || observed.st_uid != geteuid().as_raw()
        || observed.st_nlink != 1
        || observed.st_mode & 0o7777 != 0o600
        || !unchanged(&observed, &path)
    {
        return Err(invalid(
            "quota files are not private single-link regular files",
        ));
    }
    Ok((descriptor, observed))
}

fn read_private(root: &OwnedFd, name: &str, limit: usize) -> Result<Vec<u8>> {
    let (descriptor, before) = private_file(root, name)?;
    if before.st_size < 0 || before.st_size as u64 > limit as u64 {
        return Err(invalid("quota journal exceeds its bound"));
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let after = fstat(&file).map_err(|error| EvidenceError::Io(error.to_string()))?;
    let named = statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    if raw.len() > limit
        || raw.len() as i64 != before.st_size
        || !unchanged(&before, &after)
        || !unchanged(&before, &named)
    {
        return Err(invalid("quota file changed while reading"));
    }
    Ok(raw)
}

pub(super) struct State {
    pub(super) last_hash: String,
    pub(super) pending: BTreeMap<String, (u64, u64)>,
    pub(super) finished: BTreeSet<String>,
    pub(super) authorizations: BTreeSet<String>,
    pub(super) charged: u64,
    pub(super) requests: u64,
    pub(super) token_cap: u64,
    pub(super) halted: bool,
    allowance_digest: Option<String>,
}

pub(super) struct ReplayedQuota {
    #[cfg(feature = "quota-write")]
    pub(super) config: Value,
    #[cfg(feature = "quota-write")]
    pub(super) state: State,
    #[cfg(feature = "quota-write")]
    pub(super) rows: usize,
    #[cfg(feature = "quota-write")]
    pub(super) journal_bytes: usize,
    snapshot: Value,
}

impl State {
    fn new(token_cap: u64) -> Self {
        Self {
            last_hash: "0".repeat(64),
            pending: BTreeMap::new(),
            finished: BTreeSet::new(),
            authorizations: BTreeSet::new(),
            allowance_digest: None,
            charged: 0,
            requests: 0,
            token_cap,
            halted: false,
        }
    }

    pub(super) fn apply(&mut self, event: &Value, maximum_requests: u64) -> Result<()> {
        let key = event["reservation_id"]
            .as_str()
            .filter(|_| hex32(&event["reservation_id"]))
            .ok_or(invalid("quota reservation identity malformed"))?;
        match event["type"].as_str() {
            Some("extend_allowance") => {
                if !exact_keys(
                    event,
                    &[
                        "type",
                        "reservation_id",
                        "total_tokens",
                        "authorization_digest",
                    ],
                ) || !self.pending.is_empty()
                    || self.halted
                    || self.finished.contains(key)
                {
                    return Err(invalid("allowance extension requires settled known usage"));
                }
                let cap = bounded(&event["total_tokens"], 1, 1_000_000_000)?;
                let authorization = event["authorization_digest"]
                    .as_str()
                    .filter(|_| sha_value(&event["authorization_digest"]))
                    .ok_or(invalid("quota requires a lowercase immutable input digest"))?;
                if cap <= self.token_cap || !self.authorizations.insert(authorization.to_owned()) {
                    return Err(invalid(
                        "allowance extension does not increase lifetime ceiling",
                    ));
                }
                self.token_cap = cap;
                self.allowance_digest = Some(authorization.to_owned());
                self.finished.insert(key.to_owned());
            }
            Some("reserve") => {
                if !exact_keys(
                    event,
                    &[
                        "type",
                        "reservation_id",
                        "prompt_tokens",
                        "output_limit",
                        "request_digest",
                    ],
                ) || !self.pending.is_empty()
                    || self.finished.contains(key)
                    || self.halted
                {
                    return Err(invalid("overlapping, repeated or halted quota admission"));
                }
                let prompt = bounded(&event["prompt_tokens"], 1, 1_000_000_000)?;
                let output = bounded(&event["output_limit"], 1, 1_000_000_000)?;
                if !sha_value(&event["request_digest"]) {
                    return Err(invalid("quota requires a lowercase immutable input digest"));
                }
                let charged = self
                    .charged
                    .checked_add(prompt)
                    .and_then(|value| value.checked_add(output))
                    .ok_or(invalid("quota journal exceeds provider budget"))?;
                self.requests += 1;
                if self.requests > maximum_requests || charged > self.token_cap {
                    return Err(invalid("quota journal exceeds provider budget"));
                }
                self.charged = charged;
                self.pending.insert(key.to_owned(), (prompt, output));
            }
            Some("settle") => {
                if !exact_keys(
                    event,
                    &["type", "reservation_id", "prompt_tokens", "output_tokens"],
                ) || self.halted
                    || !self.pending.contains_key(key)
                {
                    return Err(invalid("quota settlement lacks exact reserved request"));
                }
                let (prompt, limit) = self.pending.remove(key).expect("checked pending key");
                let actual_prompt = event["prompt_tokens"]
                    .as_u64()
                    .ok_or(invalid("actual prompt differs from reservation"))?;
                let output = bounded(&event["output_tokens"], 0, 1_000_000_000)?;
                if actual_prompt != prompt || output > limit {
                    return Err(invalid("settled usage differs from reservation"));
                }
                self.charged -= limit - output;
                self.finished.insert(key.to_owned());
            }
            Some("uncertain") => {
                let reason = event["reason"].as_str();
                if !exact_keys(event, &["type", "reservation_id", "reason"])
                    || self.halted
                    || !self.pending.contains_key(key)
                    || !reason.is_some_and(|value| (1..=256).contains(&value.chars().count()))
                {
                    return Err(invalid("unknown usage lacks active exact reservation"));
                }
                self.halted = true;
            }
            _ => return Err(invalid("unknown provider quota journal event")),
        }
        Ok(())
    }

    fn snapshot(&self, config: &Value, config_digest: &str, maximum_requests: u64) -> Value {
        let reserved: u64 = self
            .pending
            .values()
            .map(|(prompt, output)| prompt + output)
            .sum();
        let mut snapshot = json!({
            "schema":"gauntlet-provider-quota-status.v1",
            "config_digest":config_digest,
            "model_identity_digest":config["model_identity_digest"],
            "token_cap":self.token_cap,
            "charged_tokens":self.charged,
            "known_tokens":self.charged - reserved,
            "reserved_tokens":reserved,
            "requests":self.requests,
            "maximum_requests":maximum_requests,
            "pending_requests":self.pending.len(),
            "halted":self.halted,
            "remaining_tokens":self.token_cap - self.charged,
            "journal_hash":self.last_hash,
            "qualification_eligible":false,
        });
        if let Some(allowance) = self.allowance_digest.as_deref() {
            snapshot["allowance_digest"] = json!(allowance);
        }
        snapshot
    }
}

pub(super) fn replay_locked<F>(
    descriptor: &OwnedFd,
    expected_config_digest: &str,
    expected_allowance_digest: Option<&str>,
    mut visit: F,
) -> Result<ReplayedQuota>
where
    F: FnMut(&Value) -> Result<()>,
{
    let config = decode(&read_private(descriptor, "config.json", 16_384)?)?;
    if !exact_keys(
        &config,
        &[
            "schema",
            "authorization_id",
            "quota_id",
            "total_tokens",
            "maximum_requests",
            "model_identity_digest",
            "maximum_inflight",
        ],
    ) || config["schema"] != "gauntlet-provider-quota.v1"
        || !hex32(&config["quota_id"])
        || config["maximum_inflight"].as_u64() != Some(1)
        || digest(&config)? != expected_config_digest
    {
        return Err(invalid(
            "provider quota configuration differs from external pin",
        ));
    }
    let token_cap = bounded(&config["total_tokens"], 1, 1_000_000_000)?;
    let maximum_requests = bounded(&config["maximum_requests"], 1, 10_000)?;
    if !sha_value(&config["model_identity_digest"]) {
        return Err(invalid("quota requires a lowercase immutable input digest"));
    }
    let raw = read_private(descriptor, "events.jsonl", MAX_LOG)?;
    if !raw.is_empty() && !raw.ends_with(b"\n") {
        return Err(invalid("interrupted quota append requires reconciliation"));
    }
    let mut rows: Vec<&[u8]> = if raw.is_empty() {
        Vec::new()
    } else {
        raw.split(|byte| *byte == b'\n').collect()
    };
    if raw.ends_with(b"\n") {
        rows.pop();
    }
    if rows.len() > MAX_ROWS {
        return Err(invalid("provider quota journal row bound exceeded"));
    }
    let mut state = State::new(token_cap);
    let mut snapshot = state.snapshot(&config, expected_config_digest, maximum_requests);
    visit(&snapshot)?;
    for (sequence, line) in rows.iter().enumerate() {
        let row = decode(line)?;
        if !exact_keys(
            &row,
            &["sequence", "previous_hash", "config_digest", "event"],
        ) || row["sequence"].as_u64() != Some(sequence as u64)
            || row["previous_hash"] != state.last_hash
            || row["config_digest"] != expected_config_digest
        {
            return Err(invalid(
                "provider quota journal chain or configuration changed",
            ));
        }
        let event = &row["event"];
        if !event.is_object()
            || event.get("type").is_none()
            || event.get("reservation_id").is_none()
        {
            return Err(invalid("malformed provider quota event"));
        }
        state.apply(event, maximum_requests)?;
        state.last_hash = digest(&row)?;
        snapshot = state.snapshot(&config, expected_config_digest, maximum_requests);
        visit(&snapshot)?;
    }
    if state.allowance_digest.as_deref() != expected_allowance_digest {
        return Err(invalid("provider allowance differs from external pin"));
    }
    Ok(ReplayedQuota {
        #[cfg(feature = "quota-write")]
        config,
        #[cfg(feature = "quota-write")]
        state,
        #[cfg(feature = "quota-write")]
        rows: rows.len(),
        #[cfg(feature = "quota-write")]
        journal_bytes: raw.len(),
        snapshot,
    })
}

pub(super) fn visit_provider_quota_snapshots<F>(
    root: &Path,
    expected_config_digest: &str,
    expected_allowance_digest: Option<&str>,
    visit: F,
) -> Result<Value>
where
    F: FnMut(&Value) -> Result<()>,
{
    if !is_sha256(expected_config_digest)
        || expected_allowance_digest.is_some_and(|value| !is_sha256(value))
    {
        return Err(invalid("outside provider quota digest required"));
    }
    let descriptor = open_absolute_directory(root)?;
    root_owned_by_reader(root, &descriptor)?;
    let (lock, lock_before) = private_file(&descriptor, "quota.lock")?;
    flock(&lock, FlockOperation::NonBlockingLockShared)
        .map_err(|_| invalid("provider quota journal is busy"))?;
    let replayed = replay_locked(
        &descriptor,
        expected_config_digest,
        expected_allowance_digest,
        visit,
    )?;
    let current_lock = statat(&descriptor, "quota.lock", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&lock_before, &current_lock) {
        return Err(invalid("provider quota lock changed during reading"));
    }
    flock(&lock, FlockOperation::Unlock).map_err(|error| EvidenceError::Io(error.to_string()))?;
    Ok(replayed.snapshot)
}

/// Verify a Python v1 journal and return its Python-shaped read-only snapshot.
/// A valid snapshot is operational accounting only, never model admission.
pub fn read_provider_quota_snapshot(
    root: &Path,
    expected_config_digest: &str,
    expected_allowance_digest: Option<&str>,
) -> Result<Value> {
    visit_provider_quota_snapshots(
        root,
        expected_config_digest,
        expected_allowance_digest,
        |_| Ok(()),
    )
}

#[cfg(test)]
#[path = "provider_quota_tests.rs"]
mod tests;
