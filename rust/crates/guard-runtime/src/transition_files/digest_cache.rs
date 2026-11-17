//! Digests of pinned artifacts this process already hashed.
//!
//! One install compares the same packaged files many times, and the bridge
//! file is the runtime executable itself, so hashing it on every compare
//! costs seconds. A digest is reused only for the same path and the same
//! descriptor fingerprint (device, inode, size, modification and change
//! times to the nanosecond, mode and owner), and only for a file whose change
//! time was at least `SETTLED` older than the moment hashing began. The
//! kernel stamps the change time on every write and no caller can set it, so
//! any later write gives the file a newer change time and misses the cache,
//! even on a filesystem that keeps whole seconds. Windows lets a writer set
//! the last-write time, so it never reuses a digest.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

const MAX_ENTRIES: usize = 256;
const SETTLED: Duration = Duration::from_secs(2);

type Key = (PathBuf, Vec<i128>);

fn entries() -> &'static Mutex<HashMap<Key, String>> {
    static ENTRIES: OnceLock<Mutex<HashMap<Key, String>>> = OnceLock::new();
    ENTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The digest recorded for `path` with exactly this fingerprint.
pub(super) fn recorded(path: &Path, fingerprint: &[i128]) -> Option<String> {
    if !cfg!(unix) {
        return None;
    }
    let entries = entries().lock().ok()?;
    entries
        .get(&(path.to_path_buf(), fingerprint.to_vec()))
        .cloned()
}

/// Record `digest` when the file's change time had settled before hashing
/// began at `started`.
pub(super) fn record(
    path: &Path,
    fingerprint: Vec<i128>,
    changed_ns: Option<i128>,
    started: SystemTime,
    digest: &str,
) {
    if !cfg!(unix) {
        return;
    }
    let Some(changed_ns) = changed_ns else {
        return;
    };
    let Some(settled_ns) = started
        .checked_sub(SETTLED)
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|since| i128::try_from(since.as_nanos()).unwrap_or(i128::MAX))
    else {
        return;
    };
    if changed_ns >= settled_ns {
        return;
    }
    let Ok(mut entries) = entries().lock() else {
        return;
    };
    if entries.len() >= MAX_ENTRIES {
        entries.clear();
    }
    entries.insert((path.to_path_buf(), fingerprint), digest.to_owned());
}

#[cfg(all(test, unix))]
mod tests {
    use super::{record, recorded};
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn ns(time: SystemTime) -> i128 {
        i128::try_from(time.duration_since(UNIX_EPOCH).expect("epoch").as_nanos()).expect("fits")
    }

    #[test]
    fn a_settled_file_is_reused_only_with_its_exact_fingerprint() {
        let path = Path::new("/digest-cache-test/settled");
        let now = SystemTime::now();
        let old = ns(now - Duration::from_secs(60));
        record(path, vec![1, 2, old], Some(old), now, "aa");
        assert_eq!(recorded(path, &[1, 2, old]).as_deref(), Some("aa"));
        assert_eq!(recorded(path, &[1, 2, old + 1]), None);
        assert_eq!(
            recorded(Path::new("/digest-cache-test/other"), &[1, 2, old]),
            None
        );
    }

    #[test]
    fn a_file_changed_just_before_hashing_is_never_reused() {
        let path = Path::new("/digest-cache-test/fresh");
        let now = SystemTime::now();
        let fresh = ns(now - Duration::from_millis(500));
        record(path, vec![3, fresh], Some(fresh), now, "bb");
        assert_eq!(recorded(path, &[3, fresh]), None);
        record(path, vec![4], None, now, "cc");
        assert_eq!(recorded(path, &[4]), None);
    }
}
