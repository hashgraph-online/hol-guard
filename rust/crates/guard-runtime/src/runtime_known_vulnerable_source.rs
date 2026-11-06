//! Cached inputs for launch admission: the runtime advisories from the saved
//! supply-chain bundle, and the identity of each launched executable.
//!
//! Both are read locally on the hook path, never from Cloud. The bundle is
//! verified again whenever its rows change, when it reaches its expiry, and
//! at least once a minute, so an expiry or key change is seen without a
//! resync. An executable is hashed again whenever its file changes; an
//! unchanged file reuses its identity.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

use crate::local_store_read::{open_read_only_cached, table_exists, STORE_FILE_NAME};
use crate::runtime_identity::{launch_advisories, CachedBundleInput, LaunchAdvisories};

const BUNDLE_TABLE: &str = "guard_supply_chain_bundle_cache";
const ENTITLEMENT_KEY: &str = "supply_chain_bundle_entitlement";
const KEYRING_KEY: &str = "supply_chain_bundle_keyring";
const OAUTH_KEY: &str = "oauth_local_credentials";
const REVERIFY_AFTER: Duration = Duration::from_secs(60);
const MAX_PROBES: usize = 64;

/// The Guard home, its workspace, and the write stamp of every row the
/// verification reads.
type StoreKey = (PathBuf, String, [Option<String>; 3]);

static ADVISORIES: Mutex<Option<(StoreKey, Instant, Arc<LaunchAdvisories>)>> = Mutex::new(None);

/// The verified (or stale, positive-only) advisories for this Guard home's
/// workspace. `None` when Guard is not connected or has no cached bundle for
/// it; a bundle the shared check refuses supplies no advisories.
pub(super) fn advisories(guard_home: &Path) -> Option<Arc<LaunchAdvisories>> {
    let connection = open_read_only_cached(&guard_home.join(STORE_FILE_NAME)).ok()??;
    if !table_exists(&connection, "sync_state").ok()?
        || !table_exists(&connection, BUNDLE_TABLE).ok()?
    {
        return None;
    }
    let workspace = sync_payload(&connection, OAUTH_KEY)?
        .get("workspace_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_owned();
    let stamps = [
        sync_stamp(&connection, ENTITLEMENT_KEY),
        sync_stamp(&connection, KEYRING_KEY),
        bundle_stamp(&connection, &workspace),
    ];
    stamps[2].as_ref()?;
    let key: StoreKey = (guard_home.to_path_buf(), workspace.clone(), stamps);
    if let Ok(cached) = ADVISORIES.lock() {
        if let Some((cached_key, at, advisories)) = cached.as_ref() {
            if *cached_key == key && reusable(advisories, *at) {
                return Some(Arc::clone(advisories));
            }
        }
    }
    let input = bundle_input(&connection, workspace)?;
    let advisories = Arc::new(launch_advisories(Some(&input)));
    if let Ok(mut cached) = ADVISORIES.lock() {
        *cached = Some((key, Instant::now(), Arc::clone(&advisories)));
    }
    Some(advisories)
}

/// Whether a verification can be reused: for at most a minute, and never
/// past the moment its bundle goes stale or its grace key expires.
pub(super) fn reusable(advisories: &LaunchAdvisories, at: Instant) -> bool {
    at.elapsed() < REVERIFY_AFTER
        && advisories.source["valid_until"]
            .as_f64()
            .is_none_or(|until| crate::runtime_identity::now_seconds() <= until)
}

/// The native cached-bundle input, as the posture loader builds it. The
/// recorded sync is passed through as-is; the shared check refuses a cache it
/// cannot vouch for.
fn bundle_input(connection: &Connection, workspace: String) -> Option<CachedBundleInput> {
    let response: String = connection
        .prepare_cached(&format!(
            "select response_json from {BUNDLE_TABLE} where workspace_id = ?1 limit 1"
        ))
        .and_then(|mut statement| statement.query_row([&workspace], |row| row.get(0)))
        .ok()?;
    let mut response: Value = serde_json::from_str(&response).ok()?;
    response.as_object_mut()?.remove("cached_at");
    Some(CachedBundleInput::new(
        response,
        workspace,
        sync_payload(connection, KEYRING_KEY),
        sync_payload(connection, ENTITLEMENT_KEY),
    ))
}

fn sync_payload(connection: &Connection, key: &str) -> Option<Value> {
    let raw: String = connection
        .prepare_cached("select payload_json from sync_state where state_key = ?1 limit 1")
        .and_then(|mut statement| statement.query_row([key], |row| row.get(0)).optional())
        .ok()??;
    serde_json::from_str(&raw).ok()
}

fn sync_stamp(connection: &Connection, key: &str) -> Option<String> {
    connection
        .prepare_cached(
            "select updated_at || ':' || length(payload_json) from sync_state \
             where state_key = ?1 limit 1",
        )
        .and_then(|mut statement| statement.query_row([key], |row| row.get(0)).optional())
        .ok()?
}

fn bundle_stamp(connection: &Connection, workspace: &str) -> Option<String> {
    connection
        .prepare_cached(&format!(
            "select cached_at || ':' || length(response_json) from {BUNDLE_TABLE} \
             where workspace_id = ?1 limit 1"
        ))
        .and_then(|mut statement| {
            statement
                .query_row([workspace], |row| row.get(0))
                .optional()
        })
        .ok()?
}

/// What identifies one version of a file: replacing or rewriting it changes
/// at least one field.
#[derive(Clone, PartialEq, Eq, Hash)]
struct FileStamp {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: (u64, u64, i64, i64),
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    Some(FileStamp {
        path: path.to_path_buf(),
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        inode,
    })
}

type Probed = Option<(String, Value)>;

static PROBES: Mutex<Option<HashMap<FileStamp, Probed>>> = Mutex::new(None);

/// The resolved path and runtime artifact of the executable at `path`, or
/// `None` when it cannot be identified. Hashing a runtime binary costs tens
/// of milliseconds, so an unchanged file reuses its last identity.
pub(super) fn probe(path: &Path) -> Probed {
    let stamp = file_stamp(path)?;
    if let Ok(cached) = PROBES.lock() {
        if let Some(found) = cached.as_ref().and_then(|probes| probes.get(&stamp)) {
            return found.clone();
        }
    }
    let probed = crate::runtime_identity_probe::probe_one(path);
    // The file may have changed while it was hashed; only a stamp that held
    // across the probe can vouch for the result next time.
    if file_stamp(path).as_ref() == Some(&stamp) {
        if let Ok(mut cached) = PROBES.lock() {
            let probes = cached.get_or_insert_with(HashMap::new);
            if probes.len() >= MAX_PROBES {
                probes.clear();
            }
            probes.insert(stamp, probed.clone());
        }
    }
    probed
}
