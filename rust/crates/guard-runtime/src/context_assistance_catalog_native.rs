//! Owner MAC retains the roots/time that authenticated a cached catalog.
//! Those facts authorize offline installed-receipt resolution, not new installs
//! under expired or revoked keys. No production or test root is embedded here.
use super::*;
use crate::guard_config_update::io::{CatalogPair, LifecycleFile, WriteLock};
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
#[path = "context_assistance_catalog_publication.rs"]
pub(super) mod publication;
pub(super) use publication::{configure, import};
const MAX_LEDGER: usize = 1024;
#[path = "context_assistance_catalog_identities.rs"]
mod identities;
use identities::Seen;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    schema: String,
    accepted_at: u64,
    authority: Authority,
    signed_catalog: String,
    checkpoint: guard_cigar_release::CatalogCheckpoint,
    seen: Seen,
    withdrawn_sdk: BTreeSet<String>,
    withdrawn_python: BTreeSet<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    payload: String,
    mac: String,
}
pub(super) fn storage(e: crate::guard_config_update::Failure) -> String {
    match e {
        crate::guard_config_update::Failure::Error(c)
            if matches!(
                c.as_str(),
                "cigar_catalog_state_incomplete"
                    | "cigar_catalog_layout_conflict"
                    | "cigar_catalog_state_changed"
            ) =>
        {
            error(&c)
        }
        crate::guard_config_update::Failure::Error(c) if c.ends_with("commit_outcome_unknown") => {
            error("cigar_catalog_commit_outcome_unknown")
        }
        crate::guard_config_update::Failure::Error(c) if c.ends_with("write_busy") => {
            error("cigar_catalog_busy")
        }
        _ => error("cigar_catalog_storage_invalid_or_changed"),
    }
}
pub(super) fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| error("clock_invalid"))
}
pub(super) fn parse<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, String> {
    crate::strict_json_value(raw).and_then(|v| {
        crate::strict_json::from_value(v).map_err(|_| error("cigar_catalog_state_invalid"))
    })
}
fn message(home: &Path, payload: &str) -> Result<Vec<u8>, String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    serde_json::to_vec(&(
        "hol-guard-cigar-retained-catalog.v1",
        format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes())),
        payload,
    ))
    .map_err(|_| error("cigar_catalog_state_invalid"))
}
fn verify(
    raw: &[u8],
    roots: &Authority,
    checkpoint: Option<&guard_cigar_release::CatalogCheckpoint>,
    time: u64,
) -> Result<TrustedCatalog, String> {
    let keys = roots.resolve()?;
    TrustedCatalog::verify(
        raw,
        &CatalogTrust {
            keys: &keys,
            checkpoint,
            now: time,
        },
    )
    .map_err(|e| error(e.code()))
}
pub(super) fn authority(lock: &WriteLock) -> Result<Option<Authority>, String> {
    let roots = lock
        .lifecycle_bytes(LifecycleFile::CatalogTrust)
        .map_err(storage)?
        .map(|b| parse::<Authority>(&b))
        .transpose()?;
    if let Some(a) = &roots {
        a.resolve()?;
    }
    Ok(roots)
}
pub(super) fn decode(
    home: &Path,
    raw: &[u8],
    key: &[u8; 32],
) -> Result<(Payload, TrustedCatalog), String> {
    let envelope: Envelope = parse(raw)?;
    if envelope.schema != "guard-cigar-retained-catalog.v1" || !is_lower_hex(&envelope.mac, 64) {
        return Err(error("cigar_catalog_state_invalid"));
    }
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &message(home, &envelope.payload)?,
        &hex::decode(&envelope.mac).map_err(|_| error("cigar_catalog_state_invalid"))?,
    )
    .map_err(|_| error("cigar_catalog_state_unauthenticated"))?;
    let payload: Payload = parse(envelope.payload.as_bytes())?;
    if payload.schema != "guard-cigar-retained-catalog-payload.v1"
        || payload.accepted_at == 0
        || payload.withdrawn_sdk.len() > MAX_LEDGER
        || payload.withdrawn_python.len() > MAX_LEDGER
        || payload
            .withdrawn_sdk
            .iter()
            .chain(&payload.withdrawn_python)
            .any(|id| !valid_id(id))
    {
        return Err(error("cigar_catalog_state_invalid"));
    }
    let catalog = verify(
        payload.signed_catalog.as_bytes(),
        &payload.authority,
        Some(&payload.checkpoint),
        payload.accepted_at,
    )?;
    if catalog.checkpoint() != &payload.checkpoint {
        return Err(error("cigar_catalog_state_invalid"));
    }
    payload.seen.validate()?;
    let mut seen = payload.seen.clone();
    seen.remember(&catalog)?;
    if seen != payload.seen {
        return Err(error("cigar_catalog_state_invalid"));
    }
    Ok((payload, catalog))
}
pub(super) fn cached(
    home: &Path,
    lock: &WriteLock,
) -> Result<Option<(Payload, TrustedCatalog)>, String> {
    lock.catalog_pair()
        .map_err(storage)?
        .as_ref()
        .map(|p| decode(home, p.cache(), p.key()))
        .transpose()
}
pub(super) fn load_locked(home: &Path, lock: &WriteLock, time: u64) -> Result<Snapshot, String> {
    let pair = lock.catalog_pair().map_err(storage)?;
    load_pair(home, lock, time, pair.as_ref())
}
pub(super) fn load_pair(
    home: &Path,
    lock: &WriteLock,
    time: u64,
    pair: Option<&CatalogPair>,
) -> Result<Snapshot, String> {
    snapshot_locked(
        lock,
        time,
        pair.map(|p| decode(home, p.cache(), p.key())).transpose()?,
    )
}
fn snapshot_locked(
    lock: &WriteLock,
    time: u64,
    cache: Option<(Payload, TrustedCatalog)>,
) -> Result<Snapshot, String> {
    let mut s = Snapshot::bundled()?;
    match super::feed::inspect(lock) {
        Ok(value) => s.feed_sha256 = value,
        Err(code) => s.feed_diagnostic = Some(code),
    }
    let roots = authority(lock);
    s.trust_diagnostic = roots.as_ref().err().cloned();
    s.key_ids = roots
        .as_ref()
        .ok()
        .and_then(|a| a.as_ref())
        .map(|a| {
            a.keys
                .iter()
                .filter(|k| !k.revoked)
                .map(|k| k.key_id.clone())
                .collect()
        })
        .unwrap_or_default();
    if let Some((p, catalog)) = cache {
        let mut seen = p.seen;
        seen.remember(&s.catalog)?;
        s.withdrawn_sdk.extend(p.withdrawn_sdk);
        s.withdrawn_python.extend(p.withdrawn_python);
        if catalog.checkpoint().revision == s.catalog.checkpoint().revision
            && catalog.checkpoint() != s.catalog.checkpoint()
        {
            return Err(error("cigar_catalog_revision_conflict"));
        }
        if catalog.checkpoint().revision >= s.catalog.checkpoint().revision {
            s.diagnostic = if time < p.accepted_at {
                Some(error("clock_invalid"))
            } else {
                match &roots {
                    Ok(Some(a)) => verify(
                        p.signed_catalog.as_bytes(),
                        a,
                        Some(catalog.checkpoint()),
                        time,
                    )
                    .err(),
                    Ok(None) => Some(error("cigar_catalog_trust_unavailable")),
                    Err(code) => Some(code.clone()),
                }
            };
            s.catalog = catalog;
            s.source = "cached";
        }
    }
    s.withdrawn_sdk.extend(
        s.catalog
            .document()
            .builds
            .iter()
            .filter(|b| b.withdrawn)
            .map(|b| b.identity.build_id.clone()),
    );
    s.withdrawn_python.extend(
        s.catalog
            .document()
            .interpreters
            .iter()
            .filter(|b| b.withdrawn)
            .map(|b| b.build_id.clone()),
    );
    Ok(s)
}
pub(super) fn load(home: &Path) -> Result<Snapshot, String> {
    let mut present = false;
    for name in [
        "cigar-catalog.json",
        "cigar-catalog.key",
        "cigar-catalog-trust.json",
        "cigar-catalog-feed.json",
        "cigar-catalog-state",
    ] {
        match fs::symlink_metadata(home.join(name)) {
            Ok(_) => present = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error("cigar_catalog_storage_invalid_or_changed")),
        }
    }
    if !present {
        return Snapshot::bundled();
    }
    let lock = WriteLock::acquire(home).map_err(storage)?;
    load_locked(home, &lock, now()?)
}

#[cfg(all(test, unix))]
pub(super) fn import_at(home: &Path, raw: &[u8], time: u64) -> Result<Value, String> {
    publication::import_at(home, raw, time)
}
#[cfg(all(test, unix))]
pub(super) fn load_at(home: &Path, time: u64) -> Result<Snapshot, String> {
    let lock = WriteLock::acquire(home).map_err(storage)?;
    load_locked(home, &lock, time)
}
