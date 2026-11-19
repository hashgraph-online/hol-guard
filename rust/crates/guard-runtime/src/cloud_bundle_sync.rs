//! Fetch, verify and save the workspace's signed supply-chain and network
//! protection bundles (`runner.sync_supply_chain_bundle` and
//! `runner.sync_network_protection_bundle`).
//!
//! Every exchange goes through [`brokered`], so the resident reaches Guard
//! Cloud only under the machine's managed network policy, and a round that is
//! still waiting on an exchange saves nothing.

use std::path::Path;

use guard_command::local_supply_chain::{ecosystem_support_matrix, utc_now_iso, SupplyChainStore};
use guard_command::supply_chain_bundle::{
    load_supply_chain_bundle_response, load_supply_chain_verification_keys,
    verify_supply_chain_bundle_response, RingRsaPssVerify, SupplyChainBundleResponse,
    SupplyChainVerificationKey,
};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::{
    brokered, fetch_bundle, resolve_auth, sync_url, FetchError, SyncError,
};
use crate::cloud_bundle_network::sync_network_best_effort;
use crate::package_authority_op::ResidentSupplyChainStore;

pub(crate) const KEYRING_KEY: &str = "supply_chain_bundle_keyring";
const ENTITLEMENT_KEY: &str = "supply_chain_bundle_entitlement";
const PARTITION_CACHE_KEY: &str = "supply_chain_bundle_partition_cache";
const SUMMARY_KEY: &str = "supply_chain_bundle_summary";
const DAEMON_KEY: &str = "supply_chain_bundle_daemon";
pub(crate) const NETWORK_KEY: &str = "network_protection_bundle";

/// The store a sync reads and writes.
pub(crate) struct BundleStore {
    pub(crate) resident: ResidentSupplyChainStore,
    path: std::path::PathBuf,
    /// The sign-in a caller already resolved; the store's own otherwise.
    pub(crate) auth: Option<Map<String, Value>>,
    /// The sign-in a 401 refresh produced, kept across broker rounds so one
    /// sync refreshes at most once.
    pub(crate) refreshed_auth: std::cell::RefCell<Option<Map<String, Value>>>,
}

impl BundleStore {
    pub(crate) fn new(
        guard_home: &Path,
        store_path: &Path,
        auth: Option<Map<String, Value>>,
    ) -> Self {
        Self {
            resident: ResidentSupplyChainStore::new(store_path, guard_home),
            path: store_path.to_path_buf(),
            auth,
            refreshed_auth: std::cell::RefCell::new(None),
        }
    }

    /// Read-only while an exchange waits on the caller, so a discarded round
    /// cannot save anything.
    fn conn(&self) -> Result<Connection, SyncError> {
        crate::supply_chain_egress::open_store(&self.path)
            .map_err(|error| SyncError::Failed(format!("Guard store is unavailable: {error}")))
    }

    pub(crate) fn set_payload(
        &self,
        key: &str,
        payload: &Value,
        now: &str,
    ) -> Result<(), SyncError> {
        self.conn()?
            .execute(
                "INSERT INTO sync_state (state_key, payload_json, updated_at) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(state_key) DO UPDATE SET payload_json = excluded.payload_json, \
                 updated_at = excluded.updated_at",
                params![key, payload.to_string(), now],
            )
            .map(|_| ())
            .map_err(|error| SyncError::Failed(format!("Guard store write failed: {error}")))
    }

    pub(crate) fn delete_payload(&self, key: &str) -> Result<(), SyncError> {
        self.conn()?
            .execute("DELETE FROM sync_state WHERE state_key = ?1", params![key])
            .map(|_| ())
            .map_err(|error| SyncError::Failed(format!("Guard store write failed: {error}")))
    }

    /// `store_supply_chain.upsert_supply_chain_bundle`.
    fn cache_bundle(
        &self,
        workspace_id: &str,
        response: &SupplyChainBundleResponse,
        now: &str,
    ) -> Result<(), SyncError> {
        let bundle = &response.bundle;
        self.conn()?
            .execute(
                "INSERT OR REPLACE INTO guard_supply_chain_bundle_cache (workspace_id, \
                 bundle_version, key_id, tier, policy_hash, feed_snapshot_hash, scoring_version, \
                 payload_hash, response_json, cached_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    workspace_id,
                    bundle.bundle_version,
                    bundle.key_id,
                    bundle.tier,
                    bundle.policy_hash,
                    bundle.feed_snapshot_hash,
                    bundle.scoring_version,
                    response.payload_hash,
                    response.to_dict().to_string(),
                    now,
                ],
            )
            .map(|_| ())
            .map_err(|error| SyncError::Failed(format!("Guard store write failed: {error}")))
    }

    pub(crate) fn workspace_id(&self) -> Result<String, SyncError> {
        self.resident.get_cloud_workspace_id().ok_or_else(|| {
            SyncError::NotConfigured("Guard Cloud workspace is not connected.".to_owned())
        })
    }
}

/// The verified response and the partition cache an incremental sync built.
struct PartitionSync {
    cache_payload: Value,
    refreshed: usize,
    total: usize,
}

/// A signed bundle answer for `workspace_id`: one signed for another
/// workspace is refused even before a keyring is saved.
fn verify(
    raw: &Value,
    trusted: Option<&[SupplyChainVerificationKey]>,
    cached_version: Option<&str>,
    workspace_id: &str,
) -> Result<SupplyChainBundleResponse, String> {
    let response = load_supply_chain_bundle_response(raw).map_err(|error| error.to_string())?;
    verify_supply_chain_bundle_response(
        &response,
        trusted,
        cached_version,
        None,
        &RingRsaPssVerify,
    )
    .map_err(|error| error.to_string())?;
    if response.bundle.workspace_id != workspace_id {
        return Err("the signed bundle is for another workspace".to_owned());
    }
    Ok(response)
}

fn bundle_failed(message: &str) -> SyncError {
    SyncError::Failed(format!("Guard supply-chain bundle sync failed: {message}"))
}

/// The sign-in's sync URL (`str(auth_context["sync_url"])`).
pub(crate) fn base_url(auth: &Map<String, Value>) -> Result<String, SyncError> {
    match auth.get("sync_url") {
        Some(Value::String(url)) => Ok(url.clone()),
        _ => Err(SyncError::Failed(
            "Guard Cloud sign-in has no sync URL.".to_owned(),
        )),
    }
}

pub(crate) fn workspace_url(
    route: &str,
    base: &str,
    workspace_id: &str,
) -> Result<String, SyncError> {
    sync_url(route, base, &[("workspace_id", json!(workspace_id))])
        .ok_or_else(|| SyncError::Failed(format!("Guard sync URL is invalid: {base}")))
}

/// `_sync_supply_chain_bundle_incremental`: `None` falls back to the full
/// bundle. Only a pending exchange is an error.
fn incremental(
    store: &BundleStore,
    auth: &Map<String, Value>,
    bundle_url: &str,
    trusted: Option<&[SupplyChainVerificationKey]>,
    cached_version: Option<&str>,
    workspace_id: &str,
) -> Result<Option<PartitionSync>, SyncError> {
    let Some(index_url) = sync_url("supply_chain_index", bundle_url, &[]) else {
        return Ok(None);
    };
    let index = match fetch_bundle(auth, &index_url) {
        Ok(Value::Object(index)) => index,
        Ok(_) => return Ok(None),
        Err(FetchError::Sync(SyncError::Pending)) => return Err(SyncError::Pending),
        Err(_) => return Ok(None),
    };
    let Some(Value::Array(descriptors)) = index.get("partitions") else {
        return Ok(None);
    };
    if descriptors.is_empty() {
        return Ok(None);
    }
    let cached_partitions = match store.resident.get_sync_payload(PARTITION_CACHE_KEY) {
        Some(Value::Object(mut payload)) => match payload.remove("partitions") {
            Some(Value::Object(partitions)) => partitions,
            _ => Map::new(),
        },
        _ => Map::new(),
    };
    let mut next = Map::new();
    let mut refreshed = 0;
    for descriptor in descriptors {
        let (Some(ecosystem), Some(partition), Some(payload_hash)) = (
            descriptor.get("ecosystem").and_then(Value::as_str),
            descriptor.get("partition").and_then(Value::as_i64),
            descriptor.get("payloadHash").and_then(Value::as_str),
        ) else {
            continue;
        };
        let cache_key = format!("{ecosystem}:{partition}");
        let reused = cached_partitions
            .get(&cache_key)
            .filter(|cached| {
                cached.get("payload_hash").and_then(Value::as_str) == Some(payload_hash)
            })
            .and_then(|cached| cached.get("response"))
            .filter(|response| response.is_object())
            .and_then(|response| verify(response, trusted, cached_version, workspace_id).ok())
            .filter(|response| response.payload_hash == payload_hash);
        let response = match reused {
            Some(response) => response,
            None => {
                let Some(url) = sync_url(
                    "supply_chain_partition",
                    bundle_url,
                    &[
                        ("ecosystem", json!(ecosystem)),
                        ("partition", json!(partition)),
                    ],
                ) else {
                    return Ok(None);
                };
                let payload = match fetch_bundle(auth, &url) {
                    Ok(payload) => payload,
                    Err(FetchError::Sync(SyncError::Pending)) => return Err(SyncError::Pending),
                    Err(_) => return Ok(None),
                };
                // A partition whose signed hash is not the one the index
                // names would be cached under the wrong label: the full
                // bundle is fetched instead.
                let Ok(response) = verify(&payload, trusted, cached_version, workspace_id)
                    .and_then(|response| {
                        if response.payload_hash == payload_hash {
                            Ok(response)
                        } else {
                            Err(String::new())
                        }
                    })
                else {
                    return Ok(None);
                };
                refreshed += 1;
                response
            }
        };
        next.insert(
            cache_key,
            json!({"payload_hash": payload_hash, "response": response.to_dict()}),
        );
    }
    if next.is_empty() {
        return Ok(None);
    }
    let bundle_version = index
        .get("bundleVersion")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .or(cached_version)
        .unwrap_or_default()
        .to_owned();
    let total = next.len();
    Ok(Some(PartitionSync {
        cache_payload: json!({
            "bundle_version": bundle_version,
            "partitions": next,
            "workspace_id": workspace_id,
        }),
        refreshed,
        total,
    }))
}

/// Fetch and verify the full bundle.
fn full_bundle(
    auth: &Map<String, Value>,
    bundle_url: &str,
    trusted: Option<&[SupplyChainVerificationKey]>,
    cached_version: Option<&str>,
    workspace_id: &str,
) -> Result<SupplyChainBundleResponse, SyncError> {
    let payload = fetch_bundle(auth, bundle_url).map_err(SyncError::from)?;
    verify(&payload, trusted, cached_version, workspace_id).map_err(|error| bundle_failed(&error))
}

/// `runner.sync_supply_chain_bundle`, one round.
pub(crate) fn sync_supply_chain(store: &BundleStore) -> Result<Value, SyncError> {
    let auth = resolve_auth(&store.resident, false, store.auth.as_ref())?;
    let workspace_id = store.workspace_id()?;
    let bundle_url = workspace_url("supply_chain_bundle", &base_url(&auth)?, &workspace_id)?;
    let cached = store.resident.get_cached_supply_chain_bundle(&workspace_id);
    let cached_version = cached
        .as_ref()
        .and_then(|cached| cached.get("bundle"))
        .and_then(|bundle| bundle.get("bundleVersion"))
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_owned);
    let cached_version = cached_version.as_deref();
    let keys =
        load_supply_chain_verification_keys(store.resident.get_sync_payload(KEYRING_KEY).as_ref())
            .map_err(|error| bundle_failed(&error.to_string()))?;
    let trusted = (!keys.is_empty()).then_some(keys.as_slice());
    let partitions = incremental(
        store,
        &auth,
        &bundle_url,
        trusted,
        cached_version,
        &workspace_id,
    )?;
    let response = match (&partitions, &cached) {
        (Some(partitions), Some(cached)) if partitions.refreshed == 0 && cached.is_object() => {
            match verify(cached, trusted, cached_version, &workspace_id) {
                Ok(response) => response,
                Err(_) => {
                    match full_bundle(&auth, &bundle_url, trusted, cached_version, &workspace_id) {
                        Ok(response) => response,
                        Err(error @ (SyncError::NotAvailable { .. } | SyncError::Pending)) => {
                            return Err(error)
                        }
                        Err(SyncError::Failed(message))
                            if message.starts_with("Guard supply-chain") =>
                        {
                            return Err(SyncError::Failed(message))
                        }
                        Err(error) => return Err(bundle_failed(&error.message())),
                    }
                }
            }
        }
        _ => full_bundle(&auth, &bundle_url, trusted, cached_version, &workspace_id)?,
    };
    let synced_at = utc_now_iso();
    store.cache_bundle(&workspace_id, &response, &synced_at)?;
    let keyring: Vec<Value> = response
        .verification_keys
        .iter()
        .map(|key| key.to_dict())
        .collect();
    store.set_payload(
        KEYRING_KEY,
        &json!({"workspace_id": workspace_id, "keys": keyring}),
        &synced_at,
    )?;
    let verified = crate::supply_chain_bundle_verify_op::summary(&response);
    store.set_payload(
        ENTITLEMENT_KEY,
        &json!({
            "bundle_version": verified["bundle_version"],
            "key_id": verified["key_id"],
            "policy_hash": verified["policy_hash"],
            "tier": verified["tier"],
            "workspace_id": workspace_id,
        }),
        &synced_at,
    )?;
    if let Some(partitions) = &partitions {
        store.set_payload(PARTITION_CACHE_KEY, &partitions.cache_payload, &synced_at)?;
    }
    let mut summary = json!({
        "advisory_count": verified["advisory_count"],
        "bundle_version": verified["bundle_version"],
        "ecosystem_support": ecosystem_support_matrix(),
        "feed_snapshot_hash": verified["feed_snapshot_hash"],
        "package_count": verified["package_count"],
        "policy_hash": verified["policy_hash"],
        "status": "synced",
        "synced_at": synced_at,
        "tier": verified["tier"],
        "workspace_id": workspace_id,
    });
    if let Some(partitions) = &partitions {
        summary["partition_sync"] = json!({
            "enabled": true,
            "refreshed": partitions.refreshed,
            "total": partitions.total,
        });
    }
    store.set_payload(SUMMARY_KEY, &summary, &synced_at)?;
    Ok(summary)
}

/// `workers.ticks.bundle_refresh`: the supply-chain bundle, then the network
/// protection bundle whether or not the first synced.
pub(crate) fn bundle_refresh(store: &BundleStore) -> Value {
    let refreshed_at = utc_now_iso();
    let payload = match brokered(|| sync_supply_chain(store)) {
        Ok(mut summary) => {
            summary["status"] = json!("synced");
            summary
        }
        Err(SyncError::AuthExpired(message)) => {
            json!({"status": "auth_expired", "refreshed_at": refreshed_at, "message": message})
        }
        Err(SyncError::NotConfigured(_)) => {
            json!({"status": "not_configured", "refreshed_at": refreshed_at})
        }
        Err(error) => {
            json!({"error": error.message(), "refreshed_at": refreshed_at, "status": "error"})
        }
    };
    let status = payload["status"].as_str().unwrap_or_default().to_owned();
    let _ = store.set_payload(DAEMON_KEY, &payload, &refreshed_at);
    let _ = sync_network_best_effort(store);
    json!({"ok": status == "synced", "status": status})
}
