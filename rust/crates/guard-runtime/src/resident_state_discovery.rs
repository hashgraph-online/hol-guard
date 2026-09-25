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
// Malformed names can sort ahead of a real generation. Reading this many
// times the retained set still reaches a valid state without letting junk hide it.
const MALFORMED_STATE_READ_MULTIPLIER: usize = 4;
const MAX_STATE_READ_ATTEMPTS: usize = MAX_STATE_FILES * MALFORMED_STATE_READ_MULTIPLIER;

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
    let validated_preferred_digest = preferred_digest
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let preferred_prefix = validated_preferred_digest.map(|digest| &digest[..16]);
    let mut preferred_candidate = None;
    let mut fallback_candidates = Vec::with_capacity(MAX_SCOPES);
    let mut scanned = 0usize;
    let mut truncated = false;
    for entry in fs::read_dir(&base).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        // Count every entry so unrelated names cannot hide a later file.
        scanned += 1;
        if scanned > MAX_DIRECTORY_ENTRIES {
            truncated = true;
            break;
        }
        // An iterator error ends the listing, so later entries are unseen.
        let Ok(entry) = entry else {
            truncated = true;
            break;
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
    // Fail closed only when no directory matching the preferred digest prefix
    // was found. A cap hit after that directory entry is found can omit later
    // fallbacks; those are read only when that scope has no live process.
    if truncated && preferred_candidate.is_none() {
        return Err("native_resident_state_list_failed".to_owned());
    }
    // Order fallback scopes by digest prefix, then path, and keep a bounded
    // set. The caller's scope is tracked separately and is not part of this sort.
    fallback_candidates
        .sort_unstable_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    fallback_candidates.truncate(MAX_SCOPES - usize::from(preferred_candidate.is_some()));
    // A preferred-scope listing failure still fail-closes. Other preferred
    // errors fall through so an older runtime can answer. One broken older
    // directory must not fail every hook.
    let mut states = Vec::new();
    if let Some((path, digest_prefix)) = preferred_candidate {
        match load_scope_states(&path, &digest_prefix, &private_root) {
            Ok(found) => states.extend(found),
            Err(error) if error == "native_resident_state_list_failed" => return Err(error),
            Err(_) => {}
        }
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
        let left_preferred = validated_preferred_digest.is_some_and(|digest| left.1 == digest);
        let right_preferred = validated_preferred_digest.is_some_and(|digest| right.1 == digest);
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
    paths.sort_by_key(|path| std::cmp::Reverse(generation_number(path).unwrap_or(0)));
    let mut states = Vec::new();
    for (attempted, path) in paths.into_iter().enumerate() {
        if attempted >= MAX_STATE_READ_ATTEMPTS || states.len() == MAX_STATE_FILES {
            break;
        }
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
        // Count every entry so unrelated names cannot hide a later state file.
        scanned += 1;
        if scanned > MAX_DIRECTORY_ENTRIES {
            truncated = true;
            break;
        }
        let Ok(entry) = entry else {
            truncated = true;
            break;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if canonical_generation(&name).is_some() {
            paths.push(entry.path());
        }
    }
    // Unlike the home scan, a truncated scope listing always fail-closes.
    // A later generation file in this directory may be the live state.
    if truncated {
        return Err("native_resident_state_list_failed".to_owned());
    }
    Ok(paths)
}

fn canonical_generation(name: &str) -> Option<u64> {
    let rest = name
        .strip_prefix(STATE_FILE_PREFIX)?
        .strip_suffix(STATE_FILE_SUFFIX)?;
    if rest.len() != 20 || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn generation_number(path: &Path) -> Option<u64> {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(canonical_generation)
}
