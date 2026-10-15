//! Derived identities, kept like `_cached_portable_project_identity`
//! (`store_portable_project_memory.py`): only a successful identity is kept,
//! under the workspace and the size and modification time of every Git
//! metadata file it was read from. The key also names the `.git` directory
//! the ancestor walk found, and the walk runs before every lookup, so a
//! repository appearing nearer the workspace is never shadowed by a hit.

use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// `_PROJECT_IDENTITY_CACHE_MAX_ITEMS`.
const MAX_ITEMS: usize = 128;

static CACHE: Mutex<Vec<(Key, String)>> = Mutex::new(Vec::new());

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Key {
    workspace: String,
    git_dir: PathBuf,
    config: (u64, SystemTime),
    head_log: (u64, SystemTime),
}

impl Key {
    /// `None` when a file has no modification time to key on.
    pub(super) fn new(
        workspace: &str,
        git_dir: &Path,
        config: &Metadata,
        head_log: &Metadata,
    ) -> Option<Self> {
        let print =
            |metadata: &Metadata| metadata.modified().ok().map(|time| (metadata.len(), time));
        Some(Self {
            workspace: workspace.to_owned(),
            git_dir: git_dir.to_path_buf(),
            config: print(config)?,
            head_log: print(head_log)?,
        })
    }
}

pub(super) fn get(key: &Key) -> Option<String> {
    let cache = CACHE.lock().ok()?;
    cache
        .iter()
        .find(|(held, _)| held == key)
        .map(|(_, identity)| identity.clone())
}

/// Keep `identity`, replacing every entry for the same workspace and
/// evicting the oldest entry when full.
pub(super) fn put(key: Key, identity: String) {
    let Ok(mut cache) = CACHE.lock() else {
        return;
    };
    cache.retain(|(held, _)| held.workspace != key.workspace);
    if cache.len() >= MAX_ITEMS {
        cache.remove(0);
    }
    cache.push((key, identity));
}
