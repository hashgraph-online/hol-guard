use super::*;

fn test_scope(label: &str) -> PathBuf {
    let unique = format!(
        "hol-guard-resident-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    );
    let path = std::env::temp_dir().join(unique);
    fs::create_dir(&path).unwrap();
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
        owner_process_id: 1,
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
