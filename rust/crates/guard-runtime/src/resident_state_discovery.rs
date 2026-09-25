use std::fs;
use std::path::{Path, PathBuf};

use super::{
    ensure_private_directory_under, private_root_for_state_base, read_state_file_raw,
    validate_package_process_identity, validate_state, ResidentState, MAX_STATE_FILES,
    STATE_FILE_PREFIX, STATE_FILE_SUFFIX,
};

const MAX_SCOPES: usize = 16;
// Unrelated files and stale per-version scopes are skipped. This cap only
// fail-closes when a flooded directory might have hidden the caller's runtime
// before that scope was seen.
const MAX_DIRECTORY_ENTRIES: usize = 4096;

#[allow(dead_code)]
pub(crate) fn discover_home_states(
    base: &Path,
) -> Result<Vec<(PathBuf, String, ResidentState)>, String> {
    discover_home_states_prefer(base, None)
}

pub(crate) fn discover_home_states_prefer(
    base: &Path,
    preferred_digest: Option<&str>,
) -> Result<Vec<(PathBuf, String, ResidentState)>, String> {
    let private_root = private_root_for_state_base(base)?;
    let base = ensure_private_directory_under(base, &private_root, false)?;
    let preferred_prefix = preferred_digest
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|digest| &digest[..16]);
    let mut preferred_candidate = None;
    let mut fallback_candidates = Vec::with_capacity(MAX_SCOPES);
    let mut scanned = 0usize;
    let mut truncated = false;
    for entry in fs::read_dir(&base).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        scanned += 1;
        if scanned > MAX_DIRECTORY_ENTRIES {
            truncated = true;
            break;
        }
        // One unreadable leftover must not fail every hook after a crash.
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(digest_prefix) = name.strip_prefix("resident-v3-") else {
            continue;
        };
        if digest_prefix.len() != 16 || !digest_prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        let candidate = (entry.path(), digest_prefix.to_owned());
        if preferred_prefix.is_some_and(|prefix| digest_prefix.eq_ignore_ascii_case(prefix)) {
            preferred_candidate = Some(candidate);
            continue;
        }
        fallback_candidates.push(candidate);
    }
    if truncated && preferred_candidate.is_none() {
        return Err("native_resident_state_list_failed".to_owned());
    }
    // A newer runtime can be hidden behind an arbitrary number of stale
    // per-digest scopes. Sort the caller's exact digest prefix first, then
    // keep the existing global cap for bounded inspection of fallback state.
    fallback_candidates
        .sort_unstable_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    fallback_candidates.truncate(MAX_SCOPES - usize::from(preferred_candidate.is_some()));
    let preferred_digest = preferred_digest
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    // The live runtime is one scope. Read fallback versions only when that
    // scope has no usable state, so hook traffic does not stat every old install.
    let mut states = Vec::new();
    if let Some((path, digest_prefix)) = preferred_candidate {
        states.extend(load_scope_states(&path, &digest_prefix, &private_root)?);
    }
    let preferred_live = states.iter().any(|(_, _, state)| {
        validate_package_process_identity(state.process_id, &state.process_start_marker).is_ok()
    });
    if !preferred_live {
        for (path, digest_prefix) in fallback_candidates {
            if let Ok(found) = load_scope_states(&path, &digest_prefix, &private_root) {
                states.extend(found);
            }
        }
    }
    states.sort_unstable_by(|left, right| {
        let left_preferred = preferred_digest.is_some_and(|digest| left.1 == digest);
        let right_preferred = preferred_digest.is_some_and(|digest| right.1 == digest);
        right_preferred
            .cmp(&left_preferred)
            .then_with(|| right.2.generation.cmp(&left.2.generation))
    });
    Ok(states)
}

fn load_scope_states(
    scope: &Path,
    digest_prefix: &str,
    private_root: &Path,
) -> Result<Vec<(PathBuf, String, ResidentState)>, String> {
    let scope = ensure_private_directory_under(scope, private_root, true)?;
    let mut paths = state_paths(&scope)?;
    paths.sort();
    if paths.len() > MAX_STATE_FILES {
        let skip = paths.len() - MAX_STATE_FILES;
        paths.drain(0..skip);
    }
    let mut states = Vec::new();
    for path in paths {
        let Ok(state) = read_state_file_raw(&path, private_root) else {
            continue;
        };
        let digest = state.runtime_sha256.clone();
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !digest[..16].eq_ignore_ascii_case(digest_prefix)
            || validate_state(&scope, &state, &digest).is_err()
        {
            continue;
        }
        states.push((scope.clone(), digest, state));
    }
    Ok(states)
}

pub(super) fn state_paths(scope: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let mut scanned = 0usize;
    let mut truncated = false;
    for entry in fs::read_dir(scope).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        scanned += 1;
        if scanned > MAX_DIRECTORY_ENTRIES {
            truncated = true;
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(STATE_FILE_PREFIX) && name.ends_with(STATE_FILE_SUFFIX) {
            paths.push(entry.path());
        }
    }
    if truncated && paths.is_empty() {
        return Err("native_resident_state_list_failed".to_owned());
    }
    Ok(paths)
}
