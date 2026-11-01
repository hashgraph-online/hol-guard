use super::super::native::{authority, cached, load_locked, now, parse, storage};
use super::*;
use crate::guard_config_update::io::{LifecycleFile, WriteLock};
fn read(lock: &WriteLock) -> Result<Option<Feed>, String> {
    let f = lock
        .lifecycle_bytes(LifecycleFile::CatalogFeed)
        .map_err(storage)?
        .map(|v| parse::<Feed>(&v))
        .transpose()?;
    if let Some(f) = &f {
        f.validate()?;
    }
    Ok(f)
}
pub(crate) fn inspect(lock: &WriteLock) -> Result<Option<String>, String> {
    read(lock)?
        .filter(|f| f.url.is_some())
        .map(|f| f.fingerprint())
        .transpose()
}
pub(super) fn configure(home: &Path, feed: Feed) -> Result<Value, String> {
    super::super::super::preparation::verification_policy(home)?;
    let _lease = super::super::super::preparation::lifecycle_lease(home)?;
    let lock = WriteLock::acquire(home).map_err(storage)?;
    cached(home, &lock)?;
    let old = lock
        .lifecycle_bytes(LifecycleFile::CatalogFeed)
        .map_err(storage)?;
    lock.publish_lifecycle(
        LifecycleFile::CatalogFeed,
        old.as_deref(),
        &serde_json::to_vec(&feed).map_err(|_| error("cigar_catalog_feed_invalid"))?,
    )
    .map_err(storage)?;
    Ok(load_locked(home, &lock, now()?)?.metadata())
}
/// Only this constructor can create the publication capability held by a
/// background refresh. Its private lease serializes roots/feed/install/switch.
pub(crate) struct Owner {
    home: PathBuf,
    _lease: fs::File,
    url: String,
    fingerprint: String,
}
pub(crate) fn begin(home: &Path) -> Result<Owner, String> {
    super::super::super::preparation::verification_policy(home)?;
    let lease = super::super::super::preparation::lifecycle_lease(home)?;
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let lock = WriteLock::acquire(&home).map_err(storage)?;
    load_locked(&home, &lock, now()?)?;
    let feed = read(&lock)?.ok_or_else(|| error("cigar_catalog_feed_unavailable"))?;
    let fingerprint = feed.fingerprint()?;
    let url = feed
        .url
        .ok_or_else(|| error("cigar_catalog_feed_unavailable"))?;
    let roots = authority(&lock)?.ok_or_else(|| error("cigar_catalog_trust_unavailable"))?;
    let time = now()?;
    if !roots
        .resolve()?
        .iter()
        .any(|k| !k.revoked && k.not_before <= time && time < k.not_after)
    {
        return Err(error("cigar_catalog_key_unavailable"));
    }
    Ok(Owner {
        home,
        _lease: lease,
        url,
        fingerprint,
    })
}
impl Owner {
    pub(crate) fn url(&self) -> &str {
        &self.url
    }
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub(crate) fn publish(
        &self,
        raw: &[u8],
        before: impl FnOnce(&guard_cigar_release::CatalogCheckpoint) -> Result<(), String>,
    ) -> Result<Value, String> {
        super::super::native::publication::import_held(&self.home, raw, now()?, before)
    }
}
/// Recovery never fetches or trusts job metadata as publication authority. It
/// can durably re-publish only the identical currently authenticated cache.
pub(crate) fn reconcile(
    home: &Path,
    expected: Option<&guard_cigar_release::CatalogCheckpoint>,
    after: impl FnOnce(bool) -> Result<(), String>,
) -> Result<(), String> {
    let _lease = super::super::super::preparation::lifecycle_lease(home)?;
    let lock = WriteLock::acquire(home).map_err(storage)?;
    let pair = lock.catalog_pair().map_err(storage)?;
    let current = super::super::native::load_pair(home, &lock, now()?, pair.as_ref())?;
    let matches = current.source == "cached" && expected == Some(current.catalog.checkpoint());
    if matches {
        let pair = pair
            .as_ref()
            .ok_or_else(|| error("cigar_catalog_state_incomplete"))?;
        lock.publish_catalog(Some(pair), pair.cache(), pair.key())
            .map_err(storage)?;
    }
    // Do not hold the short writer lock across job cleanup/persistence.
    drop(lock);
    after(matches)
}
