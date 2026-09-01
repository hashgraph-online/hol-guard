use std::fs;
use std::path::{Path, PathBuf};

use super::{
    ensure_private_directory, read_state_file_raw, validate_state, ResidentState, MAX_STATE_FILES,
    STATE_FILE_PREFIX, STATE_FILE_SUFFIX,
};

pub(crate) fn discover_home_states(
    base: &Path,
) -> Result<Vec<(PathBuf, String, ResidentState)>, String> {
    const MAX_SCOPES: usize = 16;
    let base = ensure_private_directory(base, false)?;
    let mut scopes = Vec::new();
    for entry in fs::read_dir(&base).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        let entry = entry.map_err(|_| "native_resident_state_list_failed".to_owned())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(digest_prefix) = name.strip_prefix("resident-v3-") else {
            continue;
        };
        if digest_prefix.len() != 16 || !digest_prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        if scopes.len() >= MAX_SCOPES {
            break;
        }
        let scope = ensure_private_directory(&entry.path(), true)?;
        scopes.push((scope, digest_prefix.to_owned()));
    }
    let mut states = Vec::new();
    for (scope, digest_prefix) in scopes {
        let paths = state_paths(&scope)?;
        for path in paths {
            let Ok(state) = read_state_file_raw(&path) else {
                continue;
            };
            let digest = state.runtime_sha256.clone();
            if digest.len() != 64
                || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !digest.starts_with(&digest_prefix)
                || validate_state(&scope, &state, &digest).is_err()
            {
                continue;
            }
            states.push((scope.clone(), digest, state));
        }
    }
    states.sort_by_key(|(_, _, state)| std::cmp::Reverse(state.generation));
    Ok(states)
}

fn state_paths(scope: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(scope).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        let entry = entry.map_err(|_| "native_resident_state_list_failed".to_owned())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(STATE_FILE_PREFIX) && name.ends_with(STATE_FILE_SUFFIX) {
            paths.push(entry.path());
            if paths.len() > MAX_STATE_FILES {
                paths.sort_unstable_by(|left, right| right.file_name().cmp(&left.file_name()));
                paths.truncate(MAX_STATE_FILES);
            }
        }
    }
    Ok(paths)
}
