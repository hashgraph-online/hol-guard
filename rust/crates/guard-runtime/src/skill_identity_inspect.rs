//! Complete canonical identity of one skill directory, or a typed incomplete
//! state. A tree that cannot be inspected in full is never represented by a
//! partial digest.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

use guard_contracts::{
    SkillDirectoryIdentityV1, SkillDirectoryLimitsV1, SKILL_DIRECTORY_IDENTITY_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::skill_identity_canon::{
    canonical_component, canonical_relative_path, incomplete_state_hash, sha256_label,
    update_digest, Failure,
};
use crate::skill_identity_walk::{
    collect_entries, is_directory, lexical_normalize, resolve_existing, safe_lstat, security_mode,
    stat_key, EntryType, Structure, TreeEntry,
};

const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Fault-injection points so tests can mutate the tree at the exact moments
/// the inspector claims to detect concurrent change.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;
    use std::path::Path;

    type CollectHook = Box<dyn FnMut(usize, bool)>;
    type HashHook = Box<dyn FnMut(&Path)>;

    thread_local! {
        pub(crate) static COLLECT: RefCell<Option<CollectHook>> = const { RefCell::new(None) };
        pub(crate) static HASHED: RefCell<Option<HashHook>> = const { RefCell::new(None) };
    }

    pub(crate) fn collect(pass: usize, after: bool) {
        COLLECT.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(pass, after);
            }
        });
    }

    pub(crate) fn hashed(path: &Path) {
        HASHED.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }
}

fn collect_pass(
    root: &Path,
    limits: &SkillDirectoryLimitsV1,
    pass: usize,
) -> Result<(Vec<TreeEntry>, Structure), Failure> {
    #[cfg(test)]
    test_hooks::collect(pass, false);
    let collected = collect_entries(root, limits);
    #[cfg(test)]
    test_hooks::collect(pass, true);
    #[cfg(not(test))]
    let _ = pass;
    collected
}

#[derive(Default)]
struct State {
    entry_count: u64,
    total_bytes: u64,
    primary_content_hash: Option<String>,
}

/// Stable incomplete identity for a typed failure with the given progress.
pub(crate) fn incomplete_identity(
    reason: Failure,
    primary_content_hash: Option<String>,
    entry_count: u64,
    total_bytes: u64,
) -> SkillDirectoryIdentityV1 {
    let state_hash = incomplete_state_hash(
        reason,
        primary_content_hash.as_deref(),
        entry_count,
        total_bytes,
    );
    SkillDirectoryIdentityV1 {
        schema_version: SKILL_DIRECTORY_IDENTITY_SCHEMA.to_owned(),
        status: "incomplete".to_owned(),
        directory_hash: None,
        primary_content_hash,
        entry_count,
        total_bytes,
        failure_reason: Some(reason),
        incomplete_state_hash: Some(state_hash),
    }
}

/// Inspect the directory holding `skill_document`. Both paths must be
/// absolute; the operation front door enforces that.
pub(crate) fn inspect_skill_directory(
    skill_document: &Path,
    scope_root: &Path,
    limits: &SkillDirectoryLimitsV1,
) -> SkillDirectoryIdentityV1 {
    let mut state = State::default();
    match run(skill_document, scope_root, limits, &mut state) {
        Ok(identity) => identity,
        Err(reason) => incomplete_identity(
            reason,
            state.primary_content_hash,
            state.entry_count,
            state.total_bytes,
        ),
    }
}

fn run(
    skill_document: &Path,
    scope_root: &Path,
    limits: &SkillDirectoryLimitsV1,
    state: &mut State,
) -> Result<SkillDirectoryIdentityV1, Failure> {
    let logical_root = skill_document.parent().unwrap_or(Path::new("/"));
    let resolved_scope = resolve_scope_root(scope_root)?;
    validate_lexical_parent_links(scope_root, logical_root)?;
    let root_lstat = root_lstat(logical_root)?;
    let root_key = stat_key(&root_lstat);
    let resolved_root = resolve_existing(logical_root, Failure::RootMissing)?;
    if !is_directory(&resolved_root) {
        return Err(Failure::RootNotDirectory);
    }
    if !resolved_root.starts_with(&resolved_scope) {
        return Err(Failure::SymlinkEscape);
    }

    let primary_name = match skill_document.components().next_back() {
        Some(Component::Normal(name)) => canonical_component(name)?,
        _ => return Err(Failure::InvalidRelativePath),
    };
    let (entries, initial_structure) = collect_pass(&resolved_root, limits, 1)?;
    state.entry_count = entries.len() as u64;
    let primary_index = entries
        .iter()
        .position(|entry| entry.relative_path == primary_name)
        .filter(|index| entries[*index].entry_type != EntryType::Directory)
        .ok_or(Failure::PrimaryMissing)?;
    if entries[primary_index].entry_type == EntryType::Symlink {
        return Err(Failure::PrimarySymlinkUnsupported);
    }

    let order = std::iter::once(primary_index)
        .chain((0..entries.len()).filter(|index| *index != primary_index));
    let mut records: Vec<(String, Value)> = Vec::with_capacity(entries.len());
    for index in order {
        let entry = &entries[index];
        let (record, content_hash) = entry_record(entry, &resolved_root, limits, state)?;
        records.push((entry.relative_path.clone(), record));
        if index == primary_index {
            state.primary_content_hash = content_hash;
        }
    }

    if stat_key(&safe_lstat(logical_root)?) != root_key {
        return Err(Failure::TreeChangedDuringHash);
    }
    let (_, final_structure) = collect_pass(&resolved_root, limits, 2)?;
    if final_structure != initial_structure {
        return Err(Failure::TreeChangedDuringHash);
    }
    let final_root = safe_lstat(logical_root)?;
    if stat_key(&final_root) != root_key {
        return Err(Failure::TreeChangedDuringHash);
    }

    let mut digest = Sha256::new();
    update_digest(
        &mut digest,
        &json!({
            "schema": SKILL_DIRECTORY_IDENTITY_SCHEMA,
            "rootMode": security_mode(&final_root),
        }),
    )?;
    records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    for (_, record) in &records {
        update_digest(&mut digest, record)?;
    }
    Ok(SkillDirectoryIdentityV1 {
        schema_version: SKILL_DIRECTORY_IDENTITY_SCHEMA.to_owned(),
        status: "complete".to_owned(),
        directory_hash: Some(sha256_label(digest)),
        primary_content_hash: state.primary_content_hash.clone(),
        entry_count: state.entry_count,
        total_bytes: state.total_bytes,
        failure_reason: None,
        incomplete_state_hash: None,
    })
}

fn resolve_scope_root(scope_root: &Path) -> Result<std::path::PathBuf, Failure> {
    let resolved = resolve_existing(scope_root, Failure::RootMissing)?;
    if !is_directory(&resolved) {
        return Err(Failure::RootNotDirectory);
    }
    Ok(resolved)
}

/// Every ancestor between the scope and the skill root must be a real
/// directory, not a link, so a link cannot redirect the scope boundary.
fn validate_lexical_parent_links(scope_root: &Path, logical_root: &Path) -> Result<(), Failure> {
    let scope = lexical_normalize(scope_root);
    let root = lexical_normalize(logical_root);
    let relative = root
        .strip_prefix(&scope)
        .map_err(|_| Failure::SymlinkEscape)?;
    let parts: Vec<_> = relative.components().collect();
    let mut current = scope.clone();
    for part in &parts[..parts.len().saturating_sub(1)] {
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Failure::SymlinkDirectoryUnsupported)
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Failure::UnreadableEntry),
        }
    }
    Ok(())
}

fn root_lstat(root: &Path) -> Result<Metadata, Failure> {
    let metadata = fs::symlink_metadata(root).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => Failure::RootMissing,
        _ => Failure::UnreadableEntry,
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Failure::SymlinkDirectoryUnsupported);
    }
    if !file_type.is_dir() {
        return Err(Failure::RootNotDirectory);
    }
    Ok(metadata)
}

fn entry_record(
    entry: &TreeEntry,
    root: &Path,
    limits: &SkillDirectoryLimitsV1,
    state: &mut State,
) -> Result<(Value, Option<String>), Failure> {
    let metadata = safe_lstat(&entry.path)?;
    if stat_key(&metadata) != entry.key {
        return Err(Failure::TreeChangedDuringHash);
    }
    let mode = security_mode(&metadata);
    match entry.entry_type {
        EntryType::Directory => Ok((
            json!({"type": "directory", "path": entry.relative_path, "mode": mode}),
            None,
        )),
        EntryType::File => {
            let (digest, size) = hash_regular_file(&entry.path, &metadata, limits, state)?;
            Ok((
                json!({
                    "type": "file",
                    "path": entry.relative_path,
                    "mode": mode,
                    "size": size,
                    "digest": digest,
                }),
                Some(digest),
            ))
        }
        EntryType::Symlink => symlink_record(entry, root, &mode, limits, state),
    }
}

fn symlink_record(
    entry: &TreeEntry,
    root: &Path,
    mode: &str,
    limits: &SkillDirectoryLimitsV1,
    state: &mut State,
) -> Result<(Value, Option<String>), Failure> {
    let raw_target = entry
        .raw_link_target
        .as_deref()
        .ok_or(Failure::TreeChangedDuringHash)?;
    let base = entry.path.parent().unwrap_or(Path::new("/"));
    let resolved_target = resolve_existing(&base.join(raw_target), Failure::SymlinkBroken)?;
    if !resolved_target.starts_with(root) {
        return Err(Failure::SymlinkEscape);
    }
    let target_lstat = safe_lstat(&resolved_target)?;
    if target_lstat.file_type().is_dir() {
        return Err(Failure::SymlinkDirectoryUnsupported);
    }
    if !target_lstat.file_type().is_file() {
        return Err(Failure::SpecialFile);
    }
    let (target_digest, target_size) =
        hash_regular_file(&resolved_target, &target_lstat, limits, state)?;
    #[cfg(test)]
    test_hooks::hashed(&resolved_target);
    let current_link = safe_lstat(&entry.path)?;
    let current_raw = fs::read_link(&entry.path).map_err(|_| Failure::TreeChangedDuringHash)?;
    if stat_key(&current_link) != entry.key || current_raw.to_str() != Some(raw_target) {
        return Err(Failure::TreeChangedDuringHash);
    }
    let relative_target = resolved_target
        .strip_prefix(root)
        .map_err(|_| Failure::SymlinkEscape)?;
    let target_path = canonical_relative_path(
        relative_target
            .components()
            .map(|component| component.as_os_str()),
    )?;
    Ok((
        json!({
            "type": "symlink",
            "path": entry.relative_path,
            "mode": mode,
            "target": raw_target,
            "targetPath": target_path,
            "targetType": "file",
            "targetMode": security_mode(&target_lstat),
            "targetSize": target_size,
            "targetDigest": target_digest,
        }),
        Some(target_digest),
    ))
}

fn open_regular(path: &Path) -> Result<File, Failure> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => Failure::TreeChangedDuringHash,
            _ => Failure::UnreadableEntry,
        })
}

fn hash_regular_file(
    path: &Path,
    expected: &Metadata,
    limits: &SkillDirectoryLimitsV1,
    state: &mut State,
) -> Result<(String, u64), Failure> {
    let expected_key = stat_key(expected);
    let size = expected.size();
    if size > limits.max_file_bytes {
        return Err(Failure::MaxFileBytesExceeded);
    }
    if state.total_bytes.saturating_add(size) > limits.max_total_bytes {
        return Err(Failure::MaxTotalBytesExceeded);
    }
    let mut file = open_regular(path)?;
    let opened = file.metadata().map_err(|_| Failure::UnreadableEntry)?;
    if !opened.file_type().is_file() || stat_key(&opened) != expected_key {
        return Err(Failure::TreeChangedDuringHash);
    }
    let opened_key = stat_key(&opened);
    let mut total: u64 = 0;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; HASH_CHUNK_BYTES];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Failure::UnreadableEntry),
        };
        total += read as u64;
        if total > limits.max_file_bytes {
            return Err(Failure::MaxFileBytesExceeded);
        }
        if state.total_bytes.saturating_add(total) > limits.max_total_bytes {
            return Err(Failure::MaxTotalBytesExceeded);
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| Failure::UnreadableEntry)?;
    if total != opened.size() || stat_key(&after) != opened_key {
        return Err(Failure::TreeChangedDuringHash);
    }
    drop(file);
    if stat_key(&safe_lstat(path)?) != expected_key {
        return Err(Failure::TreeChangedDuringHash);
    }
    state.total_bytes += total;
    Ok((sha256_label(digest), total))
}

#[cfg(test)]
#[path = "skill_identity_race_tests.rs"]
mod race_tests;

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "hol-guard-skill-hash-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, b"first").unwrap();
        path
    }

    fn limits() -> SkillDirectoryLimitsV1 {
        SkillDirectoryLimitsV1 {
            max_depth: 32,
            max_entries: 4096,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
        }
    }

    #[test]
    fn file_replaced_after_listing_is_tree_changed() {
        let path = temp_file("changed");
        let listed = safe_lstat(&path).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"-grown").unwrap();
        drop(file);
        let outcome = hash_regular_file(&path, &listed, &limits(), &mut State::default());
        assert_eq!(outcome, Err(Failure::TreeChangedDuringHash));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unchanged_file_hashes_and_accounts_bytes() {
        let path = temp_file("stable");
        let listed = safe_lstat(&path).unwrap();
        let mut state = State::default();
        let (digest, size) = hash_regular_file(&path, &listed, &limits(), &mut state).unwrap();
        assert_eq!(size, 5);
        assert_eq!(state.total_bytes, 5);
        assert_eq!(
            digest,
            "sha256:a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e"
        );
        let _ = fs::remove_file(&path);
    }
}
