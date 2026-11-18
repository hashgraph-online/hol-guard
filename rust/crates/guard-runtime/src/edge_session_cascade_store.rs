//! The session counts on disk, so a stop does not depend on one resident
//! process living through the whole session.
//!
//! The resident runtime can exit between two tool calls (its client lease is
//! short when no owner keeps it running), and the next call starts a new one
//! with empty memory. Each session's counts are kept in one owner-private
//! file under the Guard home and read back before every call. A file that is
//! missing, unreadable or malformed only forgets the counts, which can delay a
//! stop but never adds one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    Call, Session, Stop, FANOUT_PRIORS, MAX_CALLS, MAX_REQUESTS, MAX_SESSIONS, SESSION_IDLE,
};

const DIRECTORY: &str = "session-cascade.v1";
const STATE_DIRECTORY: &str = "native-runtime";
const KIND: &str = "session_cascade";
const MAX_BYTES: u64 = 16 * 1024;
const SUFFIX: &str = ".json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    calls: Vec<SavedCall>,
    spawns: Vec<u64>,
    requests: Vec<(String, Option<Stop>)>,
    touched: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedCall {
    digest: String,
    at: u64,
    allowed: bool,
}

/// The session files of one Guard home.
pub(super) struct Store {
    directory: PathBuf,
    private_root: PathBuf,
}

impl Store {
    /// The store under `guard_home`, or `None` when it cannot be used, in
    /// which case the counts stay in memory only.
    pub(super) fn open(guard_home: &str) -> Option<Self> {
        if guard_home.trim().is_empty() {
            return None;
        }
        let state = Path::new(guard_home).join(STATE_DIRECTORY);
        let private_root = crate::resident_state::private_root_for_state_base(&state).ok()?;
        let directory = state.join(DIRECTORY);
        for level in [&state, &directory] {
            crate::resident_state::ensure_private_directory_under(level, &private_root, false)
                .ok()?;
        }
        Some(Self {
            directory,
            private_root,
        })
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        // Keys are hex digests; anything else never names a file.
        (key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| self.directory.join(format!("{key}{SUFFIX}")))
    }

    /// The saved session for `key`: `Ok(None)` when none is saved or it is
    /// stale or malformed, `Err` when the file could not be read.
    pub(super) fn load(&self, key: &str, now: Instant) -> Result<Option<Session>, ()> {
        let path = self.path(key).ok_or(())?;
        let bytes =
            crate::policy_store::read_private_file(&path, MAX_BYTES, KIND, &self.private_root)
                .map_err(|_| ())?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Ok(serde_json::from_slice::<Saved>(&bytes)
            .ok()
            .and_then(|saved| decode(saved, now, wall_millis()?)))
    }

    /// Writes the session; `true` when it was written.
    pub(super) fn save(&self, key: &str, session: &Session, now: Instant) -> bool {
        let (Some(path), Some(wall)) = (self.path(key), wall_millis()) else {
            return false;
        };
        let Ok(bytes) = serde_json::to_vec(&encode(session, now, wall)) else {
            return false;
        };
        crate::policy_store::persist_private_bytes(
            &path,
            &bytes,
            MAX_BYTES,
            KIND,
            &self.private_root,
        )
        .is_ok()
    }

    pub(super) fn remove(&self, key: &str) {
        if let Some(path) = self.path(key) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Removes sessions idle past [`SESSION_IDLE`], then the oldest beyond
    /// [`MAX_SESSIONS`].
    pub(super) fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        let now = SystemTime::now();
        let mut kept = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(key) = name.to_str().and_then(|name| name.strip_suffix(SUFFIX)) else {
                continue;
            };
            let Some(path) = self.path(key) else {
                continue;
            };
            let modified = entry
                .metadata()
                .ok()
                .filter(std::fs::Metadata::is_file)
                .and_then(|metadata| metadata.modified().ok());
            match modified {
                Some(at) if now.duration_since(at).unwrap_or_default() <= SESSION_IDLE => {
                    kept.push((at, path));
                }
                Some(_) => {
                    let _ = std::fs::remove_file(path);
                }
                None => {}
            }
        }
        if kept.len() > MAX_SESSIONS {
            kept.sort();
            for (_, path) in kept.drain(..kept.len() - MAX_SESSIONS) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn wall_millis() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

fn millis_at(at: Instant, now: Instant, wall: u64) -> u64 {
    let age = u64::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX);
    wall.saturating_sub(age)
}

fn encode(session: &Session, now: Instant, wall: u64) -> Saved {
    Saved {
        calls: session
            .calls
            .iter()
            .map(|call| SavedCall {
                digest: hex::encode(call.digest),
                at: millis_at(call.at, now, wall),
                allowed: call.allowed,
            })
            .collect(),
        spawns: session
            .spawns
            .iter()
            .map(|at| millis_at(*at, now, wall))
            .collect(),
        requests: session.requests.iter().cloned().collect(),
        touched: millis_at(session.touched, now, wall),
    }
}

/// The session `saved` describes, or `None` when it is idle, out of bounds or
/// stamped in the future (a clock moved back). A whole session is dropped
/// rather than one entry, since dropping a call between two runs of the same
/// command would join two streaks into one.
fn decode(saved: Saved, now: Instant, wall: u64) -> Option<Session> {
    if saved.calls.len() > MAX_CALLS
        || saved.spawns.len() > FANOUT_PRIORS
        || saved.requests.len() > MAX_REQUESTS
    {
        return None;
    }
    let instant = |at: u64| -> Option<Instant> {
        let age = wall.checked_sub(at)?;
        now.checked_sub(Duration::from_millis(age))
    };
    let touched = instant(saved.touched)?;
    if now.saturating_duration_since(touched) > SESSION_IDLE {
        return None;
    }
    let mut session = Session::new(touched);
    for call in saved.calls {
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&call.digest, &mut digest).ok()?;
        session.calls.push_back(Call {
            digest,
            at: instant(call.at)?,
            allowed: call.allowed,
        });
    }
    for at in saved.spawns {
        session.spawns.push_back(instant(at)?);
    }
    session.requests.extend(saved.requests);
    Some(session)
}

#[cfg(test)]
pub(super) fn open_at(guard_home: &Path) -> Option<Store> {
    Store::open(guard_home.to_str()?)
}
