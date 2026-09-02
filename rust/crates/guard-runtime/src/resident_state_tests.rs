use super::*;

fn fixture_directory(path: &Path) {
    #[cfg(windows)]
    {
        ensure_private_directory(path, true).unwrap();
    }
    #[cfg(not(windows))]
    {
        fs::create_dir(path).unwrap();
    }
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    #[cfg(windows)]
    {
        use std::io::Write;
        let private_root = path.parent().unwrap_or(path);
        let mut file = private_file(path, true, private_root).unwrap();
        file.write_all(bytes).unwrap();
    }
    #[cfg(not(windows))]
    {
        fs::write(path, bytes).unwrap();
    }
}

fn test_scope(label: &str) -> PathBuf {
    let unique = format!(
        "hol-guard-resident-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    );
    let path = std::env::temp_dir().join(unique);
    fixture_directory(&path);
    path
}

#[test]
fn state_mac_rejects_endpoint_mutation() {
    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    let digest = runtime_digest().unwrap();
    let mut state = ResidentState {
        schema: STATE_SCHEMA.to_owned(),
        generation: 1,
        process_id: 1,
        process_start_marker: "linux:1".to_owned(),
        owner_process_id: 1,
        owner_process_start_marker: "linux:1".to_owned(),
        runtime_sha256: digest,
        transport: "loopback".to_owned(),
        endpoint: "127.0.0.1:1234".to_owned(),
        token_hex: hex_bytes(&token),
        created_ms: 1,
        state_mac: String::new(),
    };
    state.state_mac = state_mac(&state, &token);
    state.endpoint = "127.0.0.1:4321".to_owned();
    assert_ne!(state.state_mac, state_mac(&state, &token));
}

#[test]
fn process_identity_rejects_a_reused_same_binary_pid_marker() {
    let process_id = std::process::id();
    let marker = process_start_marker(process_id).unwrap();
    assert!(validate_package_process_identity(process_id, &marker).is_ok());
    assert!(validate_package_process_identity(process_id, "stale-process-start-marker").is_err());
}

#[test]
fn publishing_generations_retires_superseded_state() {
    let scope = test_scope("state-retention");
    let digest = runtime_digest().unwrap();
    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    for generation in 1..=70 {
        publish_state(
            &scope,
            generation,
            std::process::id(),
            &digest,
            "loopback",
            "127.0.0.1:1".to_owned(),
            &token,
        )
        .unwrap();
    }
    let states = discover_states(&scope, &digest).unwrap();
    assert_eq!(states.len(), RETAINED_STATE_FILES);
    assert_eq!(states[0].generation, 70);
    assert_eq!(states.last().unwrap().generation, 63);
    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn preferred_runtime_scope_is_found_after_the_fallback_scope_bound() {
    let base = test_scope("preferred-scope");
    let digest = runtime_digest().unwrap();
    let preferred_prefix = &digest[..16];
    let mut fallback_prefixes = Vec::new();
    for value in 0..32u64 {
        let prefix = format!("{value:016x}");
        if prefix != preferred_prefix && fallback_prefixes.len() < 15 {
            fallback_prefixes.push(prefix);
        }
    }
    while fallback_prefixes.len() < 15 {
        let value = 0x100 + fallback_prefixes.len() as u64;
        let prefix = format!("{value:016x}");
        if prefix != preferred_prefix && !fallback_prefixes.contains(&prefix) {
            fallback_prefixes.push(prefix);
        }
    }
    for prefix in fallback_prefixes {
        ensure_private_directory(&base.join(format!("resident-v3-{prefix}")), true).unwrap();
    }
    let preferred_scope =
        ensure_private_directory(&base.join(format!("resident-v3-{preferred_prefix}")), true)
            .unwrap();
    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    publish_state(
        &preferred_scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &token,
    )
    .unwrap();

    let states = discover_home_states_prefer(&base, Some(&digest)).unwrap();
    assert_eq!(
        states.first().map(|(_, state_digest, _)| state_digest),
        Some(&digest)
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn home_state_discovery_allows_nonmatching_entries_within_bound() {
    let base = test_scope("scope-entry-bound");
    for index in 0..64 {
        fixture_directory(&base.join(format!("unrelated-{index:03}")));
    }

    assert!(discover_home_states(&base).unwrap().is_empty());
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn home_state_discovery_fails_closed_on_total_entry_overflow() {
    let base = test_scope("scope-entry-overflow");
    for index in 0..=64 {
        fixture_directory(&base.join(format!("unrelated-{index:03}")));
    }

    assert_eq!(
        discover_home_states(&base).unwrap_err(),
        "native_resident_state_list_failed"
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn home_state_discovery_rejects_seventeenth_matching_scope() {
    let base = test_scope("matching-scope-overflow");
    for index in 0..=16 {
        ensure_private_directory(&base.join(format!("resident-v3-{index:016x}")), true).unwrap();
    }

    assert_eq!(
        discover_home_states(&base).unwrap_err(),
        "native_resident_state_list_failed"
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn home_state_discovery_fails_closed_on_many_state_entries() {
    let base = test_scope("state-entry-overflow");
    let digest = runtime_digest().unwrap();
    let scope =
        ensure_private_directory(&base.join(format!("resident-v3-{}", &digest[..16])), true)
            .unwrap();
    for generation in 0..=MAX_STATE_FILES {
        fixture_file(
            &scope.join(format!("generation-{generation:020}.json")),
            b"{}",
        );
    }

    assert_eq!(
        discover_home_states(&base).unwrap_err(),
        "native_resident_state_list_failed"
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn publishing_fails_closed_when_scope_entry_bound_is_exceeded() {
    let scope = test_scope("state-prune-entry-overflow");
    let digest = runtime_digest().unwrap();
    for index in 0..64 {
        fixture_file(&scope.join(format!("unrelated-{index:03}")), b"marker");
    }

    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    assert_eq!(
        publish_state(
            &scope,
            1,
            std::process::id(),
            &digest,
            "loopback",
            "127.0.0.1:1".to_owned(),
            &token,
        )
        .unwrap_err(),
        "native_resident_state_list_failed"
    );
    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn startup_lock_drop_preserves_stable_private_lockfile() {
    let scope = test_scope("startup-lock-stable");
    let path = scope.join("startup.lock");
    let lock = acquire_startup_lock(&scope).unwrap().unwrap();
    let before = fs::metadata(&path).unwrap();

    drop(lock);

    let after = fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(before.dev(), after.dev());
        assert_eq!(before.ino(), after.ino());
    }
    assert!(path.exists());
    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn startup_lock_holds_advisory_lock_until_drop() {
    let scope = test_scope("startup-lock-ownership");
    let path = scope.join("startup.lock");
    let lock = acquire_startup_lock(&scope).unwrap().unwrap();
    #[cfg(windows)]
    let (contender, contender_binding) = private_lock_file(&path, &scope).unwrap();
    #[cfg(not(windows))]
    let contender = private_lock_file(&path, &scope).unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&contender).is_err());
    drop(contender);
    #[cfg(windows)]
    drop(contender_binding);
    assert!(path.exists());

    drop(lock);

    assert!(path.exists());
    let reacquired = acquire_startup_lock(&scope).unwrap().unwrap();
    drop(reacquired);
    assert!(path.exists());
    fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn startup_lock_retains_directory_binding_until_drop() {
    let scope = test_scope("startup-lock-directory-binding");
    let renamed = scope.with_file_name(format!(
        "{}-renamed",
        scope.file_name().unwrap().to_string_lossy()
    ));
    let lock = acquire_startup_lock(&scope).unwrap().unwrap();

    assert!(fs::rename(&scope, &renamed).is_err());

    drop(lock);
    fs::rename(&scope, &renamed).unwrap();
    fs::remove_dir_all(renamed).unwrap();
}

#[cfg(windows)]
#[test]
fn newly_created_directory_binding_denies_rename_until_drop() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-resident-created-binding-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    let renamed = scope.with_file_name(format!(
        "{}-renamed",
        scope.file_name().unwrap().to_string_lossy()
    ));
    let binding = bind_windows_private_directory(&scope, &scope).unwrap();

    assert!(fs::rename(&scope, &renamed).is_err());

    drop(binding);
    fs::rename(&scope, &renamed).unwrap();
    fs::remove_dir_all(renamed).unwrap();
}

#[test]
fn stale_startup_lock_recovery_preserves_lockfile_for_reuse() {
    let scope = test_scope("startup-lock-recovery");
    let path = scope.join("startup.lock");
    let digest = runtime_digest().unwrap();
    #[cfg(windows)]
    let (mut stale, stale_binding) = private_lock_file(&path, &scope).unwrap();
    #[cfg(not(windows))]
    let mut stale = private_lock_file(&path, &scope).unwrap();
    stale
        .write_all(format!("4294967295:stale:{digest}:{}", "0".repeat(64)).as_bytes())
        .unwrap();
    stale.sync_all().unwrap();
    stale
        .set_modified(
            SystemTime::now()
                .checked_sub(LOCK_STALE_AFTER + Duration::from_secs(1))
                .unwrap(),
        )
        .unwrap();
    drop(stale);
    #[cfg(windows)]
    drop(stale_binding);
    let before = fs::metadata(&path).unwrap();
    assert!(before.len() <= MAX_STARTUP_LOCK_BYTES);

    assert!(clear_stale_startup_lock(&scope, &digest).unwrap());
    assert!(path.exists());
    let lock = acquire_startup_lock(&scope).unwrap().unwrap();
    let after = fs::metadata(&path).unwrap();
    assert!(after.len() <= MAX_STARTUP_LOCK_BYTES);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(before.dev(), after.dev());
        assert_eq!(before.ino(), after.ino());
    }
    drop(lock);
    assert!(path.exists());
    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn startup_lock_repeated_acquisition_rewrites_without_growth() {
    let scope = test_scope("startup-lock-repeated");
    let path = scope.join("startup.lock");
    let mut expected_len = None;
    #[cfg(unix)]
    let mut expected_identity = None;
    for _ in 0..8 {
        let lock = acquire_startup_lock(&scope).unwrap().unwrap();
        let metadata = fs::metadata(&path).unwrap();
        expected_len.get_or_insert(metadata.len());
        assert_eq!(Some(metadata.len()), expected_len);
        assert!(metadata.len() <= MAX_STARTUP_LOCK_BYTES);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let identity = (metadata.dev(), metadata.ino());
            expected_identity.get_or_insert(identity);
            assert_eq!(Some(identity), expected_identity);
        }
        drop(lock);
        assert!(path.exists());
    }
    fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_state_scope_and_token_state_are_owner_private() {
    let base = test_scope("windows-private-state");
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&base, &digest).unwrap();
    let token = [9u8; crate::AUTH_TOKEN_BYTES];
    publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &token,
    )
    .unwrap();
    assert_eq!(discover_states(&scope, &digest).unwrap().len(), 1);
    fs::remove_dir_all(base).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_create_new_rejects_existing_file_without_mutating_it() {
    let scope = test_scope("create-new-existing");
    let path = scope.join("existing-state");
    fixture_file(&path, b"must-remain-byte-for-byte");

    assert!(private_file(&path, true, &scope).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"must-remain-byte-for-byte");

    fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn private_lock_file_rejects_a_private_root_outside_the_target_scope() {
    let scope = test_scope("private-lock-root-boundary");
    let wrong_root = test_scope("private-lock-wrong-root");
    let path = scope.join("private.lock");

    assert!(private_lock_file(&path, &wrong_root).is_err());
    let (file, binding) = private_lock_file(&path, &scope).unwrap();
    drop(file);
    drop(binding);

    fs::remove_dir_all(scope).unwrap();
    fs::remove_dir_all(wrong_root).unwrap();
}

#[cfg(windows)]
#[test]
fn verify_windows_private_directory_accepts_the_configured_root() {
    let scope = test_scope("verify-private-root");
    verify_windows_private_path(&scope, true, &scope).unwrap();
    protect_windows_private_path(&scope, true, &scope).unwrap();
    fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn already_private_directory_allows_overlapping_binds() {
    let scope = test_scope("private-directory-overlap");
    drop((
        bind_windows_existing_directory(&scope, &scope).unwrap(),
        bind_windows_existing_directory(&scope, &scope).unwrap(),
    ));
    fs::remove_dir_all(scope).unwrap();
}
