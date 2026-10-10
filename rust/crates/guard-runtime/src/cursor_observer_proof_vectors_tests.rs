//! Parity vectors recorded from the retired Python Cursor after-observer proof
//! helpers (`normalize_cursor_shell_command`, `verify_cursor_after_observer_proof`
//! and the pending-proof comparison of `cursor_after_observer_trusted`).

use std::fs;
use std::path::PathBuf;

use guard_command::cursor_shell_command::{
    normalize_cursor_shell_command, CursorShellNormalization,
};
use guard_contracts::{CursorObserverProofRequestV1, CURSOR_OBSERVER_PROOF_REQUEST_SCHEMA};

use super::{read_attestation_key, verify};
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/cursor_observer_proof_vectors.json.gz");

fn scratch_home(label: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("cursor-proof-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join("secrets")).expect("secrets dir");
    home
}

#[cfg(unix)]
fn write_key(home: &std::path::Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let path = home.join("secrets").join("cursor-hook-attestation.key");
    fs::write(&path, bytes).expect("write key");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod key");
}

#[test]
fn normalisation_matches_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    for (index, case) in vectors["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .enumerate()
    {
        let command = case["command"].as_str().expect("command");
        let actual = normalize_cursor_shell_command(command);
        match case["expected"].get("ok").and_then(|value| value.as_str()) {
            Some(expected) => assert_eq!(
                actual,
                CursorShellNormalization::Command(expected.to_owned()),
                "command {index}: {command:?}"
            ),
            None => assert_eq!(
                actual,
                CursorShellNormalization::Unnormalizable,
                "command {index}: {command:?}"
            ),
        }
    }
}

#[cfg(unix)]
#[test]
fn proof_verdicts_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let secret = hex::decode(vectors["secret_hex"].as_str().expect("secret")).expect("hex");
    let home = scratch_home("vectors");
    write_key(&home, &secret, 0o600);
    let cases = vectors["proofs"].as_array().expect("proofs");
    assert!(cases.len() > 5000);
    let mut valid = 0;
    for (index, case) in cases.iter().enumerate() {
        let text = |key: &str| case[key].as_str().expect(key).to_owned();
        let request = CursorObserverProofRequestV1 {
            schema: CURSOR_OBSERVER_PROOF_REQUEST_SCHEMA.to_owned(),
            request_id: "vector".to_owned(),
            guard_home: home.to_string_lossy().into_owned(),
            conversation_id: text("conversation_id"),
            command: text("command"),
            approval_binding: text("approval_binding"),
            observer_event: text("observer_event"),
            proof: text("proof"),
            require_pending_match: case["require_pending_match"].as_bool().expect("flag"),
            pending_proof: case["pending_proof"].as_str().map(str::to_owned),
        };
        let expected = case["expected"].as_bool().expect("expected");
        valid += usize::from(expected);
        assert_eq!(verify(&request), expected, "case {index}: {case}");
    }
    assert!(valid > 500, "vector set must cover valid proofs");
    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn an_unusable_attestation_key_never_verifies() {
    let home = scratch_home("keys");
    assert!(read_attestation_key(&home).is_none(), "missing key");
    write_key(&home, b"", 0o600);
    assert!(read_attestation_key(&home).is_none(), "empty key");
    write_key(&home, b"secret-bytes", 0o644);
    assert!(
        read_attestation_key(&home).is_none(),
        "group/world readable key"
    );
    write_key(&home, b"secret-bytes", 0o600);
    assert_eq!(
        read_attestation_key(&home).as_deref(),
        Some(&b"secret-bytes"[..])
    );
    let key = home.join("secrets").join("cursor-hook-attestation.key");
    let moved = home.join("secrets").join("real.key");
    fs::rename(&key, &moved).expect("move");
    std::os::unix::fs::symlink(&moved, &key).expect("symlink");
    assert!(read_attestation_key(&home).is_none(), "symlinked key");
    fs::remove_file(&key).expect("unlink symlink");
    fs::create_dir(&key).expect("directory key");
    assert!(read_attestation_key(&home).is_none(), "directory key");
    fs::remove_dir(&key).expect("remove directory key");
    write_key(&home, &vec![b'k'; (super::MAX_KEY_BYTES as usize) + 1], 0o600);
    assert!(read_attestation_key(&home).is_none(), "oversize key");
    let _ = fs::remove_dir_all(&home);
}
