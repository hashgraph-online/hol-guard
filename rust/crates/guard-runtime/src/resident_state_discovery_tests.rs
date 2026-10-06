use super::*;

fn test_home(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "hol-guard-discovery-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    ensure_private_directory(&path, true).unwrap()
}

#[test]
fn live_fallback_is_not_hidden_by_empty_older_runtime_scopes() {
    let base = test_home("empty-scopes");
    let digest = runtime_digest().unwrap();
    state_scope(&base, &digest).unwrap();
    for index in 0..32 {
        ensure_private_directory(&base.join(format!("resident-v3-{index:016x}")), true).unwrap();
    }
    let fallback_digest = "fe".repeat(32);
    let fallback = state_scope(&base, &fallback_digest).unwrap();
    publish_state(
        &fallback,
        1,
        std::process::id(),
        &fallback_digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &[9u8; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();

    let states = discover_home_states_prefer(&base, Some(&digest)).unwrap();
    assert!(states.iter().any(|(_, found, _)| found == &fallback_digest));
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn fallback_directory_work_is_bounded_across_scopes() {
    let base = test_home("aggregate-bound");
    let digest = runtime_digest().unwrap();
    state_scope(&base, &digest).unwrap();
    for index in 0..65 {
        let scope = state_scope(&base, &format!("{index:016x}{}", "0".repeat(48))).unwrap();
        for entry in 0..64 {
            let private_root = private_root_for_scope(&scope).unwrap();
            private_file(
                &scope.join(format!("unrelated-{entry}")),
                true,
                &private_root,
            )
            .unwrap();
        }
    }
    assert_eq!(
        discover_home_states_prefer(&base, Some(&digest)).unwrap_err(),
        "native_resident_state_list_failed"
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn a_verified_live_fallback_precedes_later_flooded_scopes() {
    let base = test_home("live-before-flood");
    let digest = runtime_digest().unwrap();
    let preferred_digest = "00".repeat(32);
    state_scope(&base, &preferred_digest).unwrap();
    let live = state_scope(&base, &digest).unwrap();
    publish_state(
        &live,
        1,
        std::process::id(),
        &digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &[9u8; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    let later = u64::from_str_radix(&digest[..16], 16)
        .unwrap()
        .checked_add(1)
        .unwrap();
    let flooded = state_scope(&base, &format!("{later:016x}{}", "0".repeat(48))).unwrap();
    let private_root = private_root_for_scope(&flooded).unwrap();
    for entry in 0..4097 {
        private_file(
            &flooded.join(format!("unrelated-{entry}")),
            true,
            &private_root,
        )
        .unwrap();
    }
    let states = discover_home_states_prefer(&base, Some(&preferred_digest)).unwrap();
    assert!(states.iter().any(|(_, found, _)| found == &digest));
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn preferred_and_fallback_scopes_share_one_entry_budget() {
    let base = test_home("shared-preferred-budget");
    let digest = runtime_digest().unwrap();
    let preferred = state_scope(&base, &digest).unwrap();
    let fallback = state_scope(&base, &"fe".repeat(32)).unwrap();
    for (scope, count) in [(preferred, 2048), (fallback, 2049)] {
        let private_root = private_root_for_scope(&scope).unwrap();
        for entry in 0..count {
            private_file(
                &scope.join(format!("unrelated-{entry}")),
                true,
                &private_root,
            )
            .unwrap();
        }
    }
    assert_eq!(
        discover_home_states_prefer(&base, Some(&digest)).unwrap_err(),
        "native_resident_state_list_failed"
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn a_verified_live_fallback_survives_the_retained_state_cap() {
    let base = test_home("live-after-retained-cap");
    let digest = runtime_digest().unwrap();
    let token = [9u8; crate::AUTH_TOKEN_BYTES];
    let preferred_digest = "ff".repeat(32);
    state_scope(&base, &preferred_digest).unwrap();
    for index in 0..16 {
        let stale_digest = format!("{index:016x}{}", "0".repeat(48));
        let scope = state_scope(&base, &stale_digest).unwrap();
        let mut state = publish_state(
            &scope,
            0,
            std::process::id(),
            &stale_digest,
            "loopback",
            "127.0.0.1:1".to_owned(),
            &token,
        )
        .unwrap();
        state.process_start_marker = "stale-process-marker".to_owned();
        let private_root = private_root_for_scope(&scope).unwrap();
        for generation in 1..=64 {
            state.generation = generation;
            state.state_mac = state_mac(&state, &token);
            let path = scope.join(format!("generation-{generation:020}.json"));
            let mut file = private_file(&path, true, &private_root).unwrap();
            file.write_all(&serde_json::to_vec(&state).unwrap())
                .unwrap();
        }
    }
    let live = state_scope(&base, &digest).unwrap();
    publish_state(
        &live,
        1,
        std::process::id(),
        &digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &token,
    )
    .unwrap();
    let states = discover_home_states_prefer(&base, Some(&preferred_digest)).unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].1, digest);
    fs::remove_dir_all(base).unwrap();
}
