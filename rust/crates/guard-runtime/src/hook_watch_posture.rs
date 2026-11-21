//! Whether a harness is in Watch, proven from the signed files the daemon
//! leaves behind, for a hook bridge whose daemon did not answer.
//!
//! A bridge that cannot reach the daemon denies the call, because it cannot
//! know what Guard would have decided. Under Watch that denial is wrong: with
//! the daemon up, a Watch harness only records, so a dead daemon stopped
//! calls that a live one would have let through. The bridge asks this module
//! first and continues the call only when the posture is proven.
//!
//! The proof is what the daemon itself reads when it answers. The ACKed
//! policy snapshot in `policy-snapshot-v3.json` must carry a valid integrity
//! MAC under the private verifier key, and the per-harness overrides in
//! `harness-postures-v1.json` must carry the sidecar MAC under the same key
//! and name the same generation and policy digest. A harness is in Watch when
//! its override is `watch`, or when it has no override and the snapshot mode
//! is `observe`, as `recording_only_for_binding` decides. The sidecar is
//! required even when there are no overrides: the snapshot is saved before
//! the sidecar, so a snapshot without one may be a publish that stopped
//! between the two writes, and the overrides it was meant to carry are
//! unknown. Anything missing, unreadable, malformed or unauthenticated proves
//! nothing, so the bridge keeps denying.
//!
//! The snapshot's expiry is not checked. It bounds how long the daemon may
//! enforce a policy it has not refreshed; here the question is only which
//! posture the user last chose. A posture the user changes is signed into a
//! new sidecar by the next publish, which also takes a new generation, so a
//! publish that stops before the sidecar is written leaves a sidecar for the
//! old generation that proves nothing. Watch also ends on its own: the
//! daemon turns it back to Protected at the auto-revert deadline, and cannot
//! while it is down. The sidecar therefore signs each Watch deadline, and
//! Watch is proven only while the bridge clock is before it.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_policy_snapshot::{integrity_mac, verifier_key_id, PolicySnapshotV3};
use serde::Deserialize;
use serde_json::Value;

use crate::daemon_policy_authority::hmac_sha256_raw;
use crate::policy_store::{read_private_file, read_verifier_key};

const STATE_DIRECTORY: &str = "native-runtime";
const AUTHORITY_FILE_NAME: &str = "policy-snapshot-v3.json";
const AUTHORITY_SCHEMA: &str = "guard-policy-snapshot-authority.v3";
const AUTHORITY_MAX_BYTES: u64 =
    guard_policy_snapshot::POLICY_SNAPSHOT_MAX_BYTES as u64 + 16 * 1024;
const SIDECAR_FILE_NAME: &str = "harness-postures-v1.json";
const SIDECAR_SCHEMA: &str = "guard-harness-postures.v2";
const SIDECAR_DOMAIN: &[u8] = b"hol-guard/harness-postures/v2\0";
const SIDECAR_MAX_BYTES: u64 = 16 * 1024;
const POSTURES: [&str; 3] = ["protected", "extra_careful", "watch"];
const WATCH: &str = "watch";
const OBSERVE_MODE: &str = "observe";

/// `harness-postures-v1.json` as `write_harness_postures_sidecar` writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sidecar {
    pub(crate) schema: String,
    pub(crate) generation: u64,
    pub(crate) policy_digest: String,
    pub(crate) harness_postures: BTreeMap<String, String>,
    /// When each harness Watch override reverts, in epoch microseconds. A
    /// Watch override with no entry has no revert date (auto-revert is off
    /// or Watch was never stamped), so the daemon would not end it either.
    pub(crate) harness_watch_ends_at_us: BTreeMap<String, u64>,
    /// When the machine-wide Watch reverts, in epoch microseconds.
    pub(crate) watch_ends_at_us: Option<u64>,
    pub(crate) mac: String,
}

/// True only when the signed state under `guard_home` proves that
/// `harness` (a runtime harness key such as `claude-code`) is in Watch.
pub(crate) fn harness_in_watch(guard_home: &Path, harness: &str) -> bool {
    let state_base = guard_home.join(STATE_DIRECTORY);
    let Ok(key) = read_verifier_key(&state_base) else {
        return false;
    };
    let Some(snapshot) = authenticated_snapshot(&state_base, guard_home, &key) else {
        return false;
    };
    let sidecar = match read_private_file(
        &state_base.join(SIDECAR_FILE_NAME),
        SIDECAR_MAX_BYTES,
        "harness_postures",
        guard_home,
    ) {
        Ok(Some(bytes)) => match serde_json::from_slice::<Sidecar>(&bytes) {
            Ok(sidecar) => sidecar,
            Err(_) => return false,
        },
        Ok(None) | Err(_) => return false,
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now_us = u64::try_from(now.as_micros()).unwrap_or(u64::MAX);
    watch_for(&snapshot, &sidecar, harness, &key, now_us)
}

/// The ACKed snapshot in the authority record, when its integrity MAC holds
/// under `key` and the record names the snapshot's generation and digest.
fn authenticated_snapshot(
    state_base: &Path,
    guard_home: &Path,
    key: &[u8],
) -> Option<PolicySnapshotV3> {
    let bytes = read_private_file(
        &state_base.join(AUTHORITY_FILE_NAME),
        AUTHORITY_MAX_BYTES,
        "state",
        guard_home,
    )
    .ok()??;
    let record: Value = serde_json::from_slice(&bytes).ok()?;
    if record.get("schema").and_then(Value::as_str) != Some(AUTHORITY_SCHEMA) {
        return None;
    }
    let snapshot: PolicySnapshotV3 =
        serde_json::from_value(record.get("snapshot")?.clone()).ok()?;
    let floor = record.get("generation_floor").and_then(Value::as_u64);
    let digest = record.get("policy_digest").and_then(Value::as_str);
    let authentic = snapshot.integrity.key_id == verifier_key_id(key)
        && integrity_mac(&snapshot, key).is_ok_and(|mac| {
            crate::constant_time_eq(mac.as_bytes(), snapshot.integrity.mac.as_bytes())
        });
    (authentic
        && floor == Some(snapshot.generation)
        && digest == Some(snapshot.policy_digest.as_str()))
    .then_some(snapshot)
}

/// The Watch decision for `harness` at `now_us` (epoch microseconds) from an
/// authenticated snapshot and the sidecar beside it. A sidecar that is not
/// bound to this snapshot, or not authentic, proves nothing, and neither does
/// a Watch whose signed revert deadline has passed.
pub(crate) fn watch_for(
    snapshot: &PolicySnapshotV3,
    sidecar: &Sidecar,
    harness: &str,
    key: &[u8],
    now_us: u64,
) -> bool {
    if !sidecar_authentic(sidecar, snapshot, key) {
        return false;
    }
    let before = |deadline: Option<&u64>| deadline.is_none_or(|deadline| now_us < *deadline);
    match sidecar.harness_postures.get(harness).map(String::as_str) {
        Some(posture) => posture == WATCH && before(sidecar.harness_watch_ends_at_us.get(harness)),
        None => snapshot.mode == OBSERVE_MODE && before(sidecar.watch_ends_at_us.as_ref()),
    }
}

fn sidecar_authentic(sidecar: &Sidecar, snapshot: &PolicySnapshotV3, key: &[u8]) -> bool {
    let Some(body) = sidecar_body(sidecar) else {
        return false;
    };
    let mut message = SIDECAR_DOMAIN.to_vec();
    message.extend_from_slice(body.as_bytes());
    let expected = hex::encode(hmac_sha256_raw(key, &message));
    sidecar.schema == SIDECAR_SCHEMA
        && sidecar.generation == snapshot.generation
        && sidecar.policy_digest == snapshot.policy_digest
        && crate::constant_time_eq(expected.as_bytes(), sidecar.mac.as_bytes())
}

/// The bytes `_sidecar_mac` signs: `json.dumps` of the generation, digest,
/// sorted overrides and Watch deadlines with sorted keys and compact
/// separators. The overrides may be empty, which is the signed proof that
/// there are none. Only plain harness keys, known postures and a hex digest
/// are accepted, so the text is the same whichever JSON encoder writes it.
pub(crate) fn sidecar_body(sidecar: &Sidecar) -> Option<String> {
    let plain = |text: &str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    let digest_valid = sidecar.policy_digest.len() == 64
        && sidecar
            .policy_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !digest_valid
        || sidecar
            .harness_postures
            .iter()
            .any(|(harness, posture)| !plain(harness) || !POSTURES.contains(&posture.as_str()))
        || sidecar
            .harness_watch_ends_at_us
            .keys()
            .any(|harness| !plain(harness))
    {
        return None;
    }
    let postures = sidecar
        .harness_postures
        .iter()
        .map(|(harness, posture)| format!("\"{harness}\":\"{posture}\""))
        .collect::<Vec<_>>()
        .join(",");
    let ends = sidecar
        .harness_watch_ends_at_us
        .iter()
        .map(|(harness, at)| format!("\"{harness}\":{at}"))
        .collect::<Vec<_>>()
        .join(",");
    let watch_ends = sidecar
        .watch_ends_at_us
        .map_or_else(|| "null".to_owned(), |at| at.to_string());
    Some(format!(
        "{{\"generation\":{},\"harness_postures\":{{{postures}}},\"harness_watch_ends_at_us\":{{{ends}}},\"policy_digest\":\"{}\",\"watch_ends_at_us\":{watch_ends}}}",
        sidecar.generation, sidecar.policy_digest
    ))
}

#[cfg(test)]
#[path = "hook_watch_posture_tests.rs"]
pub(crate) mod tests;
