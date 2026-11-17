use super::*;
use crate::policy_store::tests::{fixture_directory, signed_snapshot, test_root};
use guard_policy_snapshot::policy_digest;
use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const KEY: [u8; 32] = [7; 32];

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn sidecar(generation: u64, digest: &str, postures: &[(&str, &str)]) -> Sidecar {
    let harness_postures: BTreeMap<String, String> = postures
        .iter()
        .map(|(harness, posture)| ((*harness).to_owned(), (*posture).to_owned()))
        .collect();
    let mut sidecar = Sidecar {
        schema: SIDECAR_SCHEMA.to_owned(),
        generation,
        policy_digest: digest.to_owned(),
        harness_postures,
        mac: String::new(),
    };
    let mut message = SIDECAR_DOMAIN.to_vec();
    message.extend_from_slice(sidecar_body(&sidecar).unwrap().as_bytes());
    sidecar.mac = hex::encode(hmac_sha256_raw(&KEY, &message));
    sidecar
}

fn sidecar_json(sidecar: &Sidecar) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": sidecar.schema,
        "generation": sidecar.generation,
        "policy_digest": sidecar.policy_digest,
        "harness_postures": sidecar.harness_postures,
        "mac": sidecar.mac,
    }))
    .unwrap()
}

fn snapshot_in_mode(home: &Path, mode: &str) -> PolicySnapshotV3 {
    let mut snapshot = signed_snapshot(5, &KEY, home);
    snapshot.mode = mode.to_owned();
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &KEY).unwrap();
    snapshot
}

/// A Guard home whose daemon left `snapshot` ACKed and, when given, the
/// posture sidecar beside it.
fn guard_home(label: &str, snapshot: &PolicySnapshotV3, sidecar: Option<&[u8]>) -> PathBuf {
    let home = test_root(&format!("watch-{label}"));
    write_posture_state(&home, snapshot, sidecar);
    home
}

/// Leave the signed state of a daemon that ACKed a snapshot in `mode` and,
/// when `postures` is not empty, signed those per-harness overrides, in the
/// existing private Guard home `home`.
pub(crate) fn sign_postures(home: &Path, mode: &str, postures: &[(&str, &str)]) {
    let snapshot = snapshot_in_mode(home, mode);
    let signed = (!postures.is_empty()).then(|| {
        sidecar_json(&sidecar(
            snapshot.generation,
            &snapshot.policy_digest,
            postures,
        ))
    });
    write_posture_state(home, &snapshot, signed.as_deref());
}

fn write_posture_state(home: &Path, snapshot: &PolicySnapshotV3, sidecar: Option<&[u8]>) {
    let state = home.join(STATE_DIRECTORY);
    fixture_directory(&state);
    #[cfg(unix)]
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&state.join("policy-verifier.key"), &KEY);
    let record = json!({
        "schema": AUTHORITY_SCHEMA,
        "generation_floor": snapshot.generation,
        "policy_digest": snapshot.policy_digest,
        "floor_mac": "0".repeat(64),
        "snapshot": snapshot,
    });
    private_file(
        &state.join(AUTHORITY_FILE_NAME),
        &serde_json::to_vec(&record).unwrap(),
    );
    if let Some(bytes) = sidecar {
        private_file(&state.join(SIDECAR_FILE_NAME), bytes);
    }
}

#[test]
fn the_signed_body_matches_what_the_python_publisher_signs() {
    // json.dumps(..., separators=(",", ":"), sort_keys=True) and
    // hmac.new(key, b"hol-guard/harness-postures/v1\0" + body, sha256).
    let sidecar = sidecar(
        5,
        &"ab".repeat(32),
        &[("cursor", "protected"), ("claude-code", "watch")],
    );
    assert_eq!(
        sidecar_body(&sidecar).unwrap(),
        format!(
            "{{\"generation\":5,\"harness_postures\":{{\"claude-code\":\"watch\",\"cursor\":\"protected\"}},\"policy_digest\":\"{}\"}}",
            "ab".repeat(32)
        )
    );
    assert_eq!(
        sidecar.mac,
        "0f2764370e191ddaa576f457b59595f179625a1c269c105c4943afc0bbde2957"
    );
}

#[test]
fn a_signed_watch_override_proves_watch_for_that_harness_only() {
    let probe = test_root("watch-probe");
    let snapshot = snapshot_in_mode(&probe, "enforce");
    let signed = sidecar(
        snapshot.generation,
        &snapshot.policy_digest,
        &[("claude-code", "watch"), ("cursor", "protected")],
    );
    let home = guard_home("override", &snapshot, Some(&sidecar_json(&signed)));
    assert!(harness_in_watch(&home, "claude-code"));
    assert!(!harness_in_watch(&home, "cursor"));
    // No override: the enforcing snapshot mode decides.
    assert!(!harness_in_watch(&home, "codex"));
}

#[test]
fn a_global_watch_holds_unless_a_harness_is_overridden_away_from_it() {
    let probe = test_root("watch-global-probe");
    let snapshot = snapshot_in_mode(&probe, "observe");
    let bare = guard_home("global", &snapshot, None);
    assert!(harness_in_watch(&bare, "claude-code"));
    let signed = sidecar(
        snapshot.generation,
        &snapshot.policy_digest,
        &[("claude-code", "protected")],
    );
    let overridden = guard_home("global-override", &snapshot, Some(&sidecar_json(&signed)));
    assert!(!harness_in_watch(&overridden, "claude-code"));
    assert!(harness_in_watch(&overridden, "cursor"));
}

#[test]
fn an_unproven_watch_proves_nothing() {
    let probe = test_root("watch-unproven-probe");
    let snapshot = snapshot_in_mode(&probe, "enforce");
    let watch = [("claude-code", "watch")];

    let mut forged = sidecar(snapshot.generation, &snapshot.policy_digest, &watch);
    forged.mac = "0".repeat(64);
    let stale = sidecar(snapshot.generation + 1, &snapshot.policy_digest, &watch);
    let other_digest = sidecar(snapshot.generation, &"cd".repeat(32), &watch);
    for (label, bytes) in [
        ("forged", sidecar_json(&forged)),
        ("stale", sidecar_json(&stale)),
        ("digest", sidecar_json(&other_digest)),
        ("malformed", b"{\"schema\":".to_vec()),
    ] {
        let home = guard_home(label, &snapshot, Some(&bytes));
        assert!(!harness_in_watch(&home, "claude-code"), "{label}");
    }

    // A snapshot that fails its integrity MAC proves no posture at all.
    let mut tampered = snapshot_in_mode(&probe, "observe");
    tampered.mode = "observe".to_owned();
    tampered.integrity.mac = "0".repeat(64);
    let home = guard_home("tampered", &tampered, None);
    assert!(!harness_in_watch(&home, "claude-code"));

    // No verifier key, no proof.
    let signed = sidecar(snapshot.generation, &snapshot.policy_digest, &watch);
    let home = guard_home("keyless", &snapshot, Some(&sidecar_json(&signed)));
    fs::remove_file(home.join(STATE_DIRECTORY).join("policy-verifier.key")).unwrap();
    assert!(!harness_in_watch(&home, "claude-code"));

    // No Guard state at all.
    assert!(!harness_in_watch(&test_root("watch-empty"), "claude-code"));
}

#[test]
fn an_unsignable_override_proves_nothing() {
    let probe = test_root("watch-unsignable-probe");
    let snapshot = snapshot_in_mode(&probe, "observe");
    for postures in [vec![("Claude Code", "watch")], vec![("claude-code", "off")]] {
        let unsignable = Sidecar {
            schema: SIDECAR_SCHEMA.to_owned(),
            generation: snapshot.generation,
            policy_digest: snapshot.policy_digest.clone(),
            harness_postures: postures
                .iter()
                .map(|(harness, posture)| ((*harness).to_owned(), (*posture).to_owned()))
                .collect(),
            mac: "0".repeat(64),
        };
        assert!(sidecar_body(&unsignable).is_none());
        assert!(!watch_for(
            &snapshot,
            Some(&unsignable),
            "claude-code",
            &KEY
        ));
    }
}
