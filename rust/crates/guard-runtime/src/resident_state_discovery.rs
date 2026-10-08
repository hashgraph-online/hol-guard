use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    ensure_private_directory_under, private_root_for_state_base, process_start_marker,
    read_state_file_raw, validate_package_process_identity, validate_runtime_process_identity,
    validate_state, ResidentState, MAX_STATE_FILES, STATE_FILE_PREFIX, STATE_FILE_SUFFIX,
};

const MAX_SCOPES: usize = 16;
const MAX_RETAINED_STATES: usize = MAX_SCOPES * MAX_STATE_FILES;
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
    // Order fallback scopes deterministically. The caller's scope is tracked
    // separately; fallback I/O is bounded across the whole set below.
    fallback_candidates
        .sort_unstable_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    // A preferred-scope listing failure still fail-closes. Other preferred
    // errors fall through so an older runtime can answer. One broken older
    // directory must not fail every hook.
    let mut states = Vec::new();
    let mut budget = DiscoveryBudget::new();
    if let Some((path, digest_prefix)) = preferred_candidate {
        match load_scope_states(&path, &digest_prefix, &private_root, &mut budget) {
            Ok(found) => states.extend(found),
            Err(error) if error == "native_resident_state_list_failed" => return Err(error),
            Err(_) => {}
        }
    }
    let preferred_live = states.iter().any(|(_, _, state)| {
        validate_package_process_identity(state.process_id, &state.process_start_marker).is_ok()
    });
    if truncated && !preferred_live {
        // An unseen fallback may still hold the home-wide resident owner lock.
        return Err("native_resident_state_list_failed".to_owned());
    }
    if !preferred_live {
        // Empty and stale version directories must not displace the live
        // resident. Bound total fallback I/O instead of selecting hash prefixes.
        for (path, digest_prefix) in fallback_candidates {
            match load_scope_states(&path, &digest_prefix, &private_root, &mut budget) {
                Ok(found) => {
                    let mut live = None;
                    for (index, (_, _, state)) in found.iter().enumerate() {
                        if budget.verified_live(state)? {
                            live = Some(index);
                            break;
                        }
                    }
                    if states.len() + found.len() > MAX_RETAINED_STATES {
                        if let Some(index) = live {
                            states.clear();
                            states.push(found.into_iter().nth(index).unwrap());
                            break;
                        }
                        return Err("native_resident_state_list_failed".to_owned());
                    }
                    states.extend(found);
                    if live.is_some() {
                        break;
                    }
                }
                Err(_) if budget.exhausted => {
                    return Err("native_resident_state_list_failed".to_owned())
                }
                Err(_) => {}
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

struct DiscoveryBudget {
    entries: usize,
    reads: usize,
    identities: usize,
    probes: HashMap<(u32, String, String), bool>,
    exhausted: bool,
}

impl DiscoveryBudget {
    fn new() -> Self {
        Self {
            entries: MAX_DIRECTORY_ENTRIES,
            reads: MAX_SCOPES * MAX_STATE_READ_ATTEMPTS,
            identities: MAX_SCOPES,
            probes: HashMap::new(),
            exhausted: false,
        }
    }

    fn verified_live(&mut self, state: &ResidentState) -> Result<bool, String> {
        let Ok(marker) = process_start_marker(state.process_id) else {
            return Ok(false);
        };
        if !crate::constant_time_eq(marker.as_bytes(), state.process_start_marker.as_bytes()) {
            return Ok(false);
        }
        let key = (state.process_id, marker, state.runtime_sha256.clone());
        if let Some(verified) = self.probes.get(&key) {
            return Ok(*verified);
        }
        if self.identities == 0 {
            self.exhausted = true;
            return Err("native_resident_state_list_failed".to_owned());
        }
        self.identities -= 1;
        let verified = validate_runtime_process_identity(key.0, &key.1, &key.2).is_ok();
        self.probes.insert(key, verified);
        Ok(verified)
    }

    fn consume(&mut self, read: bool) -> Result<(), String> {
        let remaining = if read {
            &mut self.reads
        } else {
            &mut self.entries
        };
        if *remaining == 0 {
            self.exhausted = true;
            return Err("native_resident_state_list_failed".to_owned());
        }
        *remaining -= 1;
        Ok(())
    }
}

fn load_scope_states(
    scope: &Path,
    digest_prefix: &str,
    private_root: &Path,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<(PathBuf, String, ResidentState)>, String> {
    let scope = ensure_private_directory_under(scope, private_root, true)?;
    let mut paths = state_paths_with_budget(&scope, budget)?;
    paths.sort_by_key(|path| std::cmp::Reverse(generation_number(path).unwrap_or(0)));
    let mut states = Vec::new();
    for (attempted, path) in paths.into_iter().enumerate() {
        if attempted >= MAX_STATE_READ_ATTEMPTS || states.len() == MAX_STATE_FILES {
            break;
        }
        // Count actual reads only; a per-scope limit may stop before this read.
        budget.consume(true)?;
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
    state_paths_with_budget(scope, &mut DiscoveryBudget::new())
}

fn state_paths_with_budget(
    scope: &Path,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let mut scanned = 0usize;
    let mut truncated = false;
    for entry in fs::read_dir(scope).map_err(|_| "native_resident_state_list_failed".to_owned())? {
        budget.consume(false)?;
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

#[cfg(test)]
mod tests {
    use super::super::{ensure_private_directory, now_ms, publish_state, state_scope};
    use super::*;

    #[test]
    fn duplicate_identity_probes_are_cached_and_new_probes_are_bounded() {
        let base = std::env::temp_dir().join(format!(
            "hol-guard-discovery-probes-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
        let base = ensure_private_directory(&base, true).unwrap();
        let digest = "fe".repeat(32);
        let scope = state_scope(&base, &digest).unwrap();
        let mut state = publish_state(
            &scope,
            1,
            std::process::id(),
            &digest,
            "loopback",
            "127.0.0.1:1".to_owned(),
            &[9u8; crate::AUTH_TOKEN_BYTES],
        )
        .unwrap();
        let mut budget = DiscoveryBudget::new();
        budget.identities = 1;
        assert!(!budget.verified_live(&state).unwrap());
        assert_eq!(budget.identities, 0);
        assert!(!budget.verified_live(&state).unwrap());
        state.runtime_sha256 = "fd".repeat(32);
        assert_eq!(
            budget.verified_live(&state).unwrap_err(),
            "native_resident_state_list_failed"
        );
        state.process_start_marker = "stale-process-marker".to_owned();
        assert!(!budget.verified_live(&state).unwrap());
        fs::remove_dir_all(base).unwrap();
    }
}
