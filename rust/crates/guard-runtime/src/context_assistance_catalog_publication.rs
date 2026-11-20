use super::*;
fn policy(home: &Path) -> Result<(), String> {
    super::super::super::preparation::verification_policy(home)
}
pub(crate) fn configure(home: &Path, value: Authority) -> Result<Value, String> {
    value.resolve()?;
    policy(home)?;
    let _lease = super::super::super::preparation::lifecycle_lease(home)?;
    let lock = WriteLock::acquire(home).map_err(storage)?;
    cached(home, &lock)?;
    let old = lock
        .lifecycle_bytes(LifecycleFile::CatalogTrust)
        .map_err(storage)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| error("cigar_catalog_authority_invalid"))?;
    lock.publish_lifecycle(LifecycleFile::CatalogTrust, old.as_deref(), &bytes)
        .map_err(storage)?;
    Ok(load_locked(home, &lock, now()?)?.metadata())
}
pub(crate) fn import(home: &Path, raw: &[u8]) -> Result<Value, String> {
    import_at(home, raw, now()?)
}
pub(super) fn import_at(home: &Path, raw: &[u8], time: u64) -> Result<Value, String> {
    policy(home)?;
    let _lease = super::super::super::preparation::lifecycle_lease(home)?;
    import_held(home, raw, time, |_| Ok(()))
}
pub(crate) fn import_held(
    home: &Path,
    raw: &[u8],
    time: u64,
    before_publish: impl FnOnce(&guard_cigar_release::CatalogCheckpoint) -> Result<(), String>,
) -> Result<Value, String> {
    policy(home)?;
    let lock = WriteLock::acquire(home).map_err(storage)?;
    let previous = lock.catalog_pair().map_err(storage)?;
    let old = previous
        .as_ref()
        .map(|p| decode(home, p.cache(), p.key()))
        .transpose()?;
    if old.as_ref().is_some_and(|(p, _)| time < p.accepted_at) {
        return Err(error("clock_invalid"));
    }
    let mut seen = old
        .as_ref()
        .map(|(p, _)| p.seen.clone())
        .unwrap_or_default();
    let before = snapshot_locked(&lock, time, old)?;
    let roots = authority(&lock)?.ok_or_else(|| error("cigar_catalog_trust_unavailable"))?;
    let catalog = verify(raw, &roots, Some(before.catalog.checkpoint()), time)?;
    seen.remember(&TrustedCatalog::bundled().map_err(|e| error(e.code()))?)?;
    seen.remember(&before.catalog)?;
    seen.remember(&catalog)?;
    let mut sdk = before.withdrawn_sdk;
    let mut python = before.withdrawn_python;
    sdk.extend(
        catalog
            .document()
            .builds
            .iter()
            .filter(|b| b.withdrawn)
            .map(|b| b.identity.build_id.clone()),
    );
    python.extend(
        catalog
            .document()
            .interpreters
            .iter()
            .filter(|b| b.withdrawn)
            .map(|b| b.build_id.clone()),
    );
    if sdk.len() > MAX_LEDGER || python.len() > MAX_LEDGER {
        return Err(error("cigar_catalog_withdrawal_limit"));
    }
    let checkpoint = catalog.checkpoint().clone();
    let payload = Payload {
        schema: "guard-cigar-retained-catalog-payload.v1".into(),
        accepted_at: time,
        authority: roots,
        signed_catalog: String::from_utf8(raw.to_vec())
            .map_err(|_| error("cigar_catalog_invalid"))?,
        checkpoint: catalog.checkpoint().clone(),
        seen,
        withdrawn_sdk: sdk,
        withdrawn_python: python,
    };
    let payload =
        serde_json::to_string(&payload).map_err(|_| error("cigar_catalog_state_invalid"))?;
    let secret = match previous.as_ref() {
        Some(p) => Zeroizing::new(*p.key()),
        None => {
            let mut k = Zeroizing::new([0_u8; 32]);
            getrandom::fill(k.as_mut()).map_err(|_| error("cigar_catalog_storage_unavailable"))?;
            k
        }
    };
    let mac = hex::encode(
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref()),
            &message(home, &payload)?,
        )
        .as_ref(),
    );
    let bytes = serde_json::to_vec(&Envelope {
        schema: "guard-cigar-retained-catalog.v1".into(),
        payload,
        mac,
    })
    .map_err(|_| error("cigar_catalog_state_invalid"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(error("cigar_catalog_too_large"));
    }
    before_publish(&checkpoint)?;
    lock.publish_catalog(previous.as_ref(), &bytes, &secret)
        .map_err(storage)?;
    drop(secret);
    Ok(load_locked(home, &lock, time)?.metadata())
}
