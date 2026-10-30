//! The published manifest is what a client reads before it trusts a resident,
//! so a reader that only checked the MAC would accept any manifest the writer
//! chose to sign. Every case here signs the manifest correctly and then asks
//! whether validation still refuses it, which is the only way to tell the MAC
//! apart from the field checks it protects.

use super::*;

fn signed(state: &mut ResidentState, token: &[u8]) {
    state.state_mac = String::new();
    state.state_mac = state_mac(state, token);
}

fn manifest(digest: &str, token: &[u8]) -> ResidentState {
    let mut state = ResidentState {
        schema: STATE_SCHEMA.to_owned(),
        generation: 4,
        process_id: 11,
        process_start_marker: "test:11".to_owned(),
        owner_process_id: 12,
        owner_process_start_marker: "test:12".to_owned(),
        runtime_sha256: digest.to_owned(),
        transport: "loopback".to_owned(),
        endpoint: "127.0.0.1:9311".to_owned(),
        unix_endpoint_identity: None,
        token_hex: hex_bytes(token),
        created_ms: 7,
        state_mac: String::new(),
    };
    signed(&mut state, token);
    state
}

#[test]
fn a_correctly_signed_manifest_with_a_wrong_field_is_still_refused() {
    let token = [5u8; crate::AUTH_TOKEN_BYTES];
    let digest = runtime_digest().unwrap();
    let scope = Path::new("/nonexistent-manifest-scope");

    assert!(validate_state(scope, &manifest(&digest, &token), &digest).is_ok());

    let mutations: Vec<(&str, Box<dyn Fn(&mut ResidentState)>)> = vec![
        (
            "schema",
            Box::new(|state: &mut ResidentState| state.schema = "resident-state.v0".to_owned()),
        ),
        (
            "generation",
            Box::new(|state: &mut ResidentState| state.generation = 0),
        ),
        (
            "process id",
            Box::new(|state: &mut ResidentState| state.process_id = 0),
        ),
        (
            "owner process id",
            Box::new(|state: &mut ResidentState| state.owner_process_id = 0),
        ),
        (
            "start marker",
            Box::new(|state: &mut ResidentState| state.process_start_marker.clear()),
        ),
        (
            "owner start marker",
            Box::new(|state: &mut ResidentState| state.owner_process_start_marker.clear()),
        ),
        (
            "runtime digest",
            Box::new(|state: &mut ResidentState| state.runtime_sha256 = "b".repeat(64)),
        ),
        (
            "transport",
            Box::new(|state: &mut ResidentState| state.transport = "tcp".to_owned()),
        ),
        (
            "endpoint length",
            Box::new(|state: &mut ResidentState| state.endpoint = "a".repeat(32 * 1024 + 1)),
        ),
    ];

    for (label, mutate) in mutations {
        let mut state = manifest(&digest, &token);
        mutate(&mut state);
        signed(&mut state, &token);
        assert_eq!(
            validate_state(scope, &state, &digest),
            Err("native_resident_state_invalid".to_owned()),
            "a signed manifest with a bad {label} was accepted"
        );
    }
}

#[test]
fn a_signed_manifest_naming_an_endpoint_outside_the_scope_is_refused() {
    let token = [6u8; crate::AUTH_TOKEN_BYTES];
    let digest = runtime_digest().unwrap();
    let scope = Path::new("/nonexistent-manifest-scope");
    let mut state = manifest(&digest, &token);
    state.transport = "unix".to_owned();
    state.endpoint = "/tmp/somewhere-else/resident.sock".to_owned();
    signed(&mut state, &token);

    #[cfg(unix)]
    let expected = "native_resident_state_endpoint_invalid";
    #[cfg(not(unix))]
    let expected = "native_resident_state_transport_invalid";
    assert_eq!(
        validate_state(scope, &state, &digest),
        Err(expected.to_owned())
    );
}

#[test]
fn a_loopback_manifest_carrying_unix_endpoint_identity_is_refused() {
    let token = [8u8; crate::AUTH_TOKEN_BYTES];
    let digest = runtime_digest().unwrap();
    let scope = Path::new("/nonexistent-manifest-scope");
    let mut state = manifest(&digest, &token);
    state.unix_endpoint_identity = Some(crate::resident_endpoint::UnixEndpointIdentity {
        device: 1,
        inode: 2,
        owner: 3,
    });
    signed(&mut state, &token);

    assert_eq!(
        validate_state(scope, &state, &digest),
        Err("native_resident_state_invalid".to_owned())
    );
}
