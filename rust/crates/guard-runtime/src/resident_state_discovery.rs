use std::fs;
use std::path::{Path, PathBuf};

use super::{
    ensure_private_directory_under, private_root_for_state_base, read_state_file_raw,
    validate_state, ResidentState, MAX_STATE_FILES, STATE_FILE_PREFIX, STATE_FILE_SUFFIX,
};

const MAX_SCOPES: usize = 16;
// Keep unrelated native-runtime files from causing a false overflow while
// still bounding every home entry inspected by discovery.
const MAX_SCOPE_ENTRIES: usize = 64;

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
    let mut matching_scope_count = 0;
    for (entry_count, entry) in fs::read_dir(&base)
        .map_err(|_| "native_resident_state_list_failed".to_owned())?
        .enumerate()
    {
        if entry_count >= MAX_SCOPE_ENTRIES {
            return Err("native_resident_state_list_failed".to_owned());
        }
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
        matching_scope_count += 1;
        if matching_scope_count > MAX_SCOPES {
            return Err("native_resident_state_list_failed".to_owned());
        }
        let candidate = (entry.path(), digest_prefix.to_owned());
        if preferred_prefix.is_some_and(|prefix| digest_prefix.eq_ignore_ascii_case(prefix)) {
            preferred_candidate = Some(candidate);
            continue;
        }
        fallback_candidates.push(candidate);
    }
    // A newer runtime can be hidden behind an arbitrary number of stale
    // per-digest scopes. Sort the caller's exact digest prefix first, then
    // keep the existing global cap for bounded inspection of fallback state.
    fallback_candidates
        .sort_unstable_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    fallback_candidates.truncate(MAX_SCOPES - usize::from(preferred_candidate.is_some()));
    let scopes = preferred_candidate
        .into_iter()
        .chain(fallback_candidates)
        .map(|(path, digest_prefix)| {
            Ok((
                ensure_private_directory_under(&path, &private_root, true)?,
                digest_prefix,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let preferred_digest = preferred_digest
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let mut states = Vec::new();
    for (scope, digest_prefix) in scopes {
        let paths = state_paths(&scope)?;
        for path in paths {
            let Ok(state) = read_state_file_raw(&path, &private_root) else {
                continue;
            };
            let digest = state.runtime_sha256.clone();
            if digest.len() != 64
                || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !digest[..16].eq_ignore_ascii_case(&digest_prefix)
                || validate_state(&scope, &state, &digest).is_err()
            {
                continue;
            }
            states.push((scope.clone(), digest, state));
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

pub(super) fn state_paths(scope: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for (entry_count, entry) in fs::read_dir(scope)
        .map_err(|_| "native_resident_state_list_failed".to_owned())?
        .enumerate()
    {
        if entry_count >= MAX_STATE_FILES {
            return Err("native_resident_state_list_failed".to_owned());
        }
        let entry = entry.map_err(|_| "native_resident_state_list_failed".to_owned())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(STATE_FILE_PREFIX) && name.ends_with(STATE_FILE_SUFFIX) {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}
