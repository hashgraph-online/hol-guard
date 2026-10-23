//! Opt-in Python v1 quota writer. It is not linked into the default verifier.
//! Every mutation replays the entire private journal under the Python lock.

use crate::crypto::is_sha256;
use crate::io::open_absolute_directory;
use crate::provider_quota::{
    invalid, private_file, replay_locked, root_owned_by_reader, unchanged, ReplayedQuota,
};
use crate::{canonical_value, EvidenceError, Result};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{
    flock, fstat, openat, statat, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat,
};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

const MAX_LOG: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 30_000;

/// An existing, externally pinned Python v1 quota. The caller is responsible
/// for proving the external authorization and model identity before use.
#[derive(Clone, Debug)]
pub struct ProviderQuotaWriter {
    root: PathBuf,
    config_digest: String,
    allowance_digest: Option<String>,
}

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

fn same_file(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
}

pub(super) fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| invalid("secure quota reservation identity unavailable"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(32);
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(id)
}

fn append_event(
    root: &OwnedFd,
    replayed: &mut ReplayedQuota,
    config_digest: &str,
    event: Value,
) -> Result<()> {
    if replayed.rows >= MAX_ROWS {
        return Err(invalid("provider quota journal row bound exceeded"));
    }
    let maximum_requests = replayed.config["maximum_requests"]
        .as_u64()
        .ok_or(invalid("quota integer outside its explicit bound"))?;
    replayed.state.apply(&event, maximum_requests)?;
    let row = json!({
        "sequence": replayed.rows,
        "previous_hash": replayed.state.last_hash,
        "config_digest": config_digest,
        "event": event,
    });
    let mut bytes = canonical_value(&row)?;
    bytes.push(b'\n');
    if replayed
        .journal_bytes
        .checked_add(bytes.len())
        .is_none_or(|total| total > MAX_LOG)
    {
        return Err(invalid("quota journal byte bound exceeded"));
    }
    let descriptor = openat(
        root,
        "events.jsonl",
        OFlags::WRONLY | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let before = fstat(&descriptor).map_err(io)?;
    let named = statat(root, "events.jsonl", AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != rustix::process::geteuid().as_raw()
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != 1
        || before.st_size < 0
        || before.st_size as usize != replayed.journal_bytes
        || !unchanged(&before, &named)
    {
        return Err(invalid("quota journal changed before append"));
    }
    let mut file = File::from(descriptor);
    file.write_all(&bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    let after = fstat(&file).map_err(io)?;
    let named = statat(root, "events.jsonl", AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if !same_file(&before, &after)
        || !same_file(&after, &named)
        || after.st_size as usize != replayed.journal_bytes + bytes.len()
        || !unchanged(&after, &named)
    {
        return Err(invalid("quota journal changed after append"));
    }
    Ok(())
}

impl ProviderQuotaWriter {
    /// Canonical config digest that the owner must persist outside this store.
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Most recent external allowance authorization pin, if extended.
    pub fn allowance_digest(&self) -> Option<&str> {
        self.allowance_digest.as_deref()
    }

    /// Open only an existing quota; never create or reset a counter.
    pub fn open_existing(
        root: &Path,
        expected_config_digest: &str,
        expected_allowance_digest: Option<&str>,
    ) -> Result<Self> {
        if !is_sha256(expected_config_digest)
            || expected_allowance_digest.is_some_and(|value| !is_sha256(value))
        {
            return Err(invalid("outside provider quota digest required"));
        }
        let writer = Self {
            root: root.to_path_buf(),
            config_digest: expected_config_digest.to_owned(),
            allowance_digest: expected_allowance_digest.map(str::to_owned),
        };
        writer.with_exclusive(|_, _| Ok(()))?;
        Ok(writer)
    }

    fn with_exclusive<T>(
        &self,
        operation: impl FnOnce(&OwnedFd, &mut ReplayedQuota) -> Result<T>,
    ) -> Result<T> {
        let root = open_absolute_directory(&self.root)?;
        root_owned_by_reader(&self.root, &root)?;
        let root_before = fstat(&root).map_err(io)?;
        let (lock, lock_before) = private_file(&root, "quota.lock")?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| invalid("provider quota journal is busy"))?;
        let mut replayed = replay_locked(
            &root,
            &self.config_digest,
            self.allowance_digest.as_deref(),
            |_| Ok(()),
        )?;
        let result = operation(&root, &mut replayed);
        let named_lock = statat(&root, "quota.lock", AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        let root_after = open_absolute_directory(&self.root)?;
        root_owned_by_reader(&self.root, &root_after)?;
        let root_after = fstat(&root_after).map_err(io)?;
        if !unchanged(&lock_before, &named_lock) || !same_file(&root_before, &root_after) {
            return Err(invalid("quota root or lock changed while writing"));
        }
        flock(&lock, FlockOperation::Unlock).map_err(io)?;
        result
    }

    /// Reserve before generation. A pending reservation blocks all later calls.
    pub fn reserve(
        &self,
        prompt_tokens: u64,
        output_limit: u64,
        request_digest: &str,
        maximum_accounted_tokens: Option<u64>,
    ) -> Result<String> {
        if !(1..=1_000_000_000).contains(&prompt_tokens)
            || !(1..=1_000_000_000).contains(&output_limit)
            || !is_sha256(request_digest)
            || maximum_accounted_tokens.is_some_and(|cap| !(1..=1_000_000_000).contains(&cap))
        {
            return Err(invalid("invalid quota reservation inputs"));
        }
        self.with_exclusive(|root, replayed| {
            let state = &replayed.state;
            if state.halted || !state.pending.is_empty() {
                return Err(invalid("unsettled or unknown usage prevents inference"));
            }
            let cap = maximum_accounted_tokens
                .map_or(state.token_cap, |limit| state.token_cap.min(limit));
            let requested = state
                .charged
                .checked_add(prompt_tokens)
                .and_then(|value| value.checked_add(output_limit));
            if state.requests >= replayed.config["maximum_requests"].as_u64().unwrap_or(0)
                || requested.is_none_or(|value| value > cap)
            {
                return Err(invalid("request exceeds remaining provider budget"));
            }
            let id = random_id()?;
            append_event(
                root,
                replayed,
                &self.config_digest,
                json!({"type":"reserve","reservation_id":id,
                    "prompt_tokens":prompt_tokens,"output_limit":output_limit,
                    "request_digest":request_digest}),
            )?;
            Ok(id)
        })
    }

    /// Replace the output reservation by independently observed known usage.
    pub fn settle(&self, id: &str, prompt_tokens: u64, output_tokens: u64) -> Result<()> {
        if !(1..=1_000_000_000).contains(&prompt_tokens) || output_tokens > 1_000_000_000 {
            return Err(invalid("invalid quota settlement inputs"));
        }
        self.with_exclusive(|root, replayed| {
            let lease = replayed.state.pending.get(id);
            if replayed.state.halted
                || !lease.is_some_and(|(prompt, limit)| {
                    *prompt == prompt_tokens && output_tokens <= *limit
                })
            {
                return Err(invalid("settlement differs from active reservation"));
            }
            append_event(
                root,
                replayed,
                &self.config_digest,
                json!({
                    "type":"settle","reservation_id":id,
                    "prompt_tokens":prompt_tokens,"output_tokens":output_tokens,
                }),
            )
        })
    }

    /// Persist uncertainty and permanently halt this lifetime allowance.
    pub fn uncertain(&self, id: &str, reason: &str) -> Result<()> {
        if !(1..=256).contains(&reason.chars().count()) {
            return Err(invalid("bounded unknown-usage reason required"));
        }
        self.with_exclusive(|root, replayed| {
            if replayed.state.halted || !replayed.state.pending.contains_key(id) {
                return Err(invalid("unknown usage needs active reservation"));
            }
            append_event(
                root,
                replayed,
                &self.config_digest,
                json!({
                    "type":"uncertain","reservation_id":id,"reason":reason,
                }),
            )
        })
    }

    /// Extend only a fully settled journal at an independently pinned hash.
    /// The returned writer requires the new allowance digest on every replay.
    pub fn extend_allowance(
        &self,
        total_tokens: u64,
        authorization_digest: &str,
        expected_journal_hash: &str,
    ) -> Result<Self> {
        if !(1..=1_000_000_000).contains(&total_tokens)
            || !is_sha256(authorization_digest)
            || !is_sha256(expected_journal_hash)
        {
            return Err(invalid("invalid outside allowance authorization"));
        }
        self.with_exclusive(|root, replayed| {
            if replayed.state.halted
                || !replayed.state.pending.is_empty()
                || replayed.state.last_hash != expected_journal_hash
                || total_tokens <= replayed.state.token_cap
                || replayed.state.authorizations.contains(authorization_digest)
            {
                return Err(invalid("allowance needs exact settled journal"));
            }
            append_event(
                root,
                replayed,
                &self.config_digest,
                json!({
                    "type":"extend_allowance","reservation_id":random_id()?,
                    "total_tokens":total_tokens,"authorization_digest":authorization_digest,
                }),
            )
        })?;
        Self::open_existing(&self.root, &self.config_digest, Some(authorization_digest))
    }
}

#[cfg(test)]
#[path = "provider_quota_writer_tests.rs"]
mod tests;
