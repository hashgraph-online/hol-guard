//! CIGAR-only snapshots may retry a recognized concurrent atomic replacement.
//! Never cache settings or retry permissions, links, parsing or other failures.
use guard_secure_fs::{read_stable, SecureReadError};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_ATTEMPTS: usize = 3;

fn changed_snapshot<T>(
    mut read: impl FnMut() -> Result<T, SecureReadError>,
) -> Result<T, SecureReadError> {
    let deadline = Instant::now() + Duration::from_millis(50);
    for attempt in 1..=MAX_ATTEMPTS {
        match read() {
            Err(SecureReadError::Changed)
                if attempt < MAX_ATTEMPTS && Instant::now() < deadline =>
            {
                #[cfg(test)]
                eprintln!("CIGAR_CONFIG_SNAPSHOT_CHANGED_RETRY={attempt}");
                std::thread::sleep(Duration::from_millis(2));
            }
            result => return result,
        }
    }
    Err(SecureReadError::Changed)
}

/// Same file-size, leaf, UTF-8 and TOML contract as the general Guard loader.
/// Only optional CIGAR callers use this bounded fresh-snapshot policy.
pub(super) fn read_home(home: &Path) -> Result<Map<String, Value>, String> {
    let path = home.join(crate::package_authority_config::HOME_CONFIG_FILENAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(_) => return Err("config_file_unavailable".into()),
    }
    let read = changed_snapshot(|| {
        #[cfg(test)]
        if CHANGED_READS.with(|remaining| {
            let n = remaining.get();
            remaining.set(n.saturating_sub(1));
            n != 0
        }) {
            return Err(SecureReadError::Changed);
        }
        read_stable(&path, MAX_CONFIG_BYTES, false)
    })
    .map_err(|_| "config_file_unavailable_or_changed".to_owned())?;
    let text = std::str::from_utf8(&read.bytes).map_err(|_| "config_not_utf8")?;
    let table: toml::Table = text.parse().map_err(|_| "config_malformed")?;
    match serde_json::to_value(table).map_err(|_| "config_malformed")? {
        Value::Object(map) => Ok(map),
        _ => Err("config_malformed".into()),
    }
}

#[cfg(test)]
thread_local! {static CHANGED_READS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}

#[cfg(test)]
pub(crate) fn with_changed_reads<T>(count: usize, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CHANGED_READS.with(|remaining| remaining.set(0));
        }
    }
    CHANGED_READS.with(|remaining| assert_eq!(remaining.replace(count), 0));
    let _reset = Reset;
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_changed_reads_retry_and_return_the_new_observation() {
        let mut calls = 0;
        let result = changed_snapshot(|| {
            calls += 1;
            if calls < 3 {
                Err(SecureReadError::Changed)
            } else {
                Ok("new target settings")
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(result, "new target settings");
        let failures: [fn() -> SecureReadError; 5] = [
            || SecureReadError::PermissionDenied,
            || SecureReadError::SymlinkInPath,
            || SecureReadError::HardLinkedFile,
            || SecureReadError::ReadFailed,
            || SecureReadError::TooLarge,
        ];
        for error in failures {
            let mut calls = 0;
            let result: Result<(), _> = changed_snapshot(|| {
                calls += 1;
                Err(error())
            });
            assert_eq!(result.unwrap_err().to_string(), error().to_string());
            assert_eq!(calls, 1);
        }
    }
    #[test]
    fn persistent_change_exhausts_a_fixed_budget_without_a_cached_value() {
        let mut calls = 0;
        let result: Result<(), _> = changed_snapshot(|| {
            calls += 1;
            Err(SecureReadError::Changed)
        });
        assert_eq!(calls, 3);
        assert!(matches!(result, Err(SecureReadError::Changed)));
    }
}
