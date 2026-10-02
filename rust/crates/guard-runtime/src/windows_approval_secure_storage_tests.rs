use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    state_base: std::path::PathBuf,
    account: String,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let state_base = std::env::temp_dir().join(format!(
            "hol-guard-windows-secure-storage-{}-{nonce}",
            std::process::id()
        ));
        crate::resident_state::ensure_private_directory(&state_base, true).unwrap();
        let account = format!(
            "test-{}",
            digest_bytes(state_base.to_string_lossy().as_bytes())
        );
        Self {
            state_base,
            account,
        }
    }

    fn max_bytes(&self) -> usize {
        32 * 1024
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = guard_runtime_windows_process::credential_delete(&target_for_anchor(&self.account));
        let _ = guard_runtime_windows_process::credential_delete(&target_for_device(&self.account));
        let _ = fs::remove_dir_all(&self.state_base);
    }
}

fn anchor_for(bytes: &[u8]) -> Anchor {
    Anchor {
        schema: STORE_SCHEMA.to_owned(),
        version: STORE_VERSION,
        sequence: 1,
        ciphertext_digest: ciphertext_digest(bytes),
        ciphertext_len: bytes.len() as u64,
        plaintext_len: 1,
    }
}

#[test]
fn absent_anchor_is_distinct_from_missing_referenced_blob() {
    let fixture = Fixture::new();
    assert!(read_anchor(&fixture.account, fixture.max_bytes())
        .unwrap()
        .is_none());

    write(
        &fixture.state_base,
        &fixture.account,
        "current",
        fixture.max_bytes(),
    )
    .unwrap();
    let (anchor, _) = read_anchor(&fixture.account, fixture.max_bytes())
        .unwrap()
        .unwrap();
    let (scope, private_root) = store_paths(&fixture.state_base, &fixture.account, false).unwrap();
    let path = blob_path(&scope, &anchor.ciphertext_digest);
    assert!(crate::resident_state::remove_windows_private_file(&path, &private_root).unwrap());
    assert_eq!(
        read(&fixture.state_base, &fixture.account, fixture.max_bytes()),
        Err(UNAVAILABLE.to_owned())
    );
}

#[test]
fn state_larger_than_credential_blob_limit_round_trips_through_dpapi_file() {
    let fixture = Fixture::new();
    let value = "windows-state-marker-".to_owned() + &"x".repeat(4 * 1024);
    write(
        &fixture.state_base,
        &fixture.account,
        &value,
        fixture.max_bytes(),
    )
    .unwrap();
    assert_eq!(
        read(&fixture.state_base, &fixture.account, fixture.max_bytes()),
        Ok(Some(value))
    );
}

#[test]
fn escape_heavy_value_at_declared_limit_stays_within_ciphertext_budget() {
    let fixture = Fixture::new();
    let max_bytes = fixture.max_bytes();
    let mut value = String::with_capacity(max_bytes);
    while value.len() + 2 <= max_bytes {
        value.push('"');
        value.push('\\');
    }
    if value.len() < max_bytes {
        value.push('"');
    }
    assert_eq!(value.len(), max_bytes);

    let encoded = encode_value(&fixture.account, &value, max_bytes).unwrap();
    let maximum_ciphertext = maximum_ciphertext_bytes(max_bytes).unwrap();
    assert!(encoded.len() <= maximum_ciphertext);
    assert_eq!(
        encoded.len(),
        1 + (3 * FRAME_LENGTH_BYTES) + STORE_SCHEMA.len() + fixture.account.len() + max_bytes
    );
}

#[test]
fn tampered_current_blob_is_invalid_and_orphan_cannot_replace_current_anchor() {
    let fixture = Fixture::new();
    write(
        &fixture.state_base,
        &fixture.account,
        "old",
        fixture.max_bytes(),
    )
    .unwrap();
    let (old_anchor, _) = read_anchor(&fixture.account, fixture.max_bytes())
        .unwrap()
        .unwrap();
    let (scope, private_root) = store_paths(&fixture.state_base, &fixture.account, false).unwrap();
    let old_path = blob_path(&scope, &old_anchor.ciphertext_digest);
    let old_ciphertext = read_blob(
        &old_path,
        maximum_ciphertext_bytes(fixture.max_bytes()).unwrap(),
        &private_root,
    )
    .unwrap();

    write(
        &fixture.state_base,
        &fixture.account,
        "new",
        fixture.max_bytes(),
    )
    .unwrap();
    let (new_anchor, _) = read_anchor(&fixture.account, fixture.max_bytes())
        .unwrap()
        .unwrap();
    assert_ne!(old_anchor.ciphertext_digest, new_anchor.ciphertext_digest);
    persist_blob(&old_path, &old_ciphertext, &private_root).unwrap();
    assert_eq!(
        read(&fixture.state_base, &fixture.account, fixture.max_bytes()),
        Ok(Some("new".to_owned()))
    );

    let new_path = blob_path(&scope, &new_anchor.ciphertext_digest);
    let mut tampered = read_blob(
        &new_path,
        maximum_ciphertext_bytes(fixture.max_bytes()).unwrap(),
        &private_root,
    )
    .unwrap();
    tampered[0] ^= 0x80;
    persist_blob(&new_path, &tampered, &private_root).unwrap();
    assert_eq!(
        read(&fixture.state_base, &fixture.account, fixture.max_bytes()),
        Err(INVALID.to_owned())
    );
}

#[test]
fn orphan_cleanup_keeps_verified_current_blob() {
    let fixture = Fixture::new();
    write(
        &fixture.state_base,
        &fixture.account,
        "current",
        fixture.max_bytes(),
    )
    .unwrap();
    let (anchor, _) = read_anchor(&fixture.account, fixture.max_bytes())
        .unwrap()
        .unwrap();
    let (scope, private_root) = store_paths(&fixture.state_base, &fixture.account, false).unwrap();
    let orphan_ciphertext =
        guard_runtime_windows_process::dpapi_protect(b"orphan", &entropy_for(&fixture.account))
            .unwrap();
    let orphan_digest = ciphertext_digest(&orphan_ciphertext);
    let orphan_path = blob_path(&scope, &orphan_digest);
    persist_blob(&orphan_path, &orphan_ciphertext, &private_root).unwrap();
    garbage_collect(&scope, &private_root, &anchor.ciphertext_digest);
    assert!(!orphan_path.exists());
    assert!(blob_path(&scope, &anchor.ciphertext_digest).exists());
}

#[test]
fn uncertain_write_requires_exact_authoritative_anchor_readback() {
    let bytes = anchor_bytes(&anchor_for(b"ciphertext")).unwrap();
    let exact = Some((anchor_for(b"ciphertext"), bytes.clone()));
    assert_eq!(
        anchor_write_committed(Err(UNAVAILABLE.to_owned()), Ok(exact), &bytes),
        Ok(())
    );

    let old = Some((
        anchor_for(b"old"),
        anchor_bytes(&anchor_for(b"old")).unwrap(),
    ));
    assert_eq!(
        anchor_write_committed(Err(UNAVAILABLE.to_owned()), Ok(old), &bytes),
        Err(UNAVAILABLE.to_owned())
    );
}

#[test]
fn plaintext_is_not_written_to_state_files_or_anchor() {
    let fixture = Fixture::new();
    let value = "unique-windows-plaintext-marker-9f3b".repeat(100);
    write(
        &fixture.state_base,
        &fixture.account,
        &value,
        fixture.max_bytes(),
    )
    .unwrap();
    let (anchor, anchor_bytes) = read_anchor(&fixture.account, fixture.max_bytes())
        .unwrap()
        .unwrap();
    assert!(!anchor_bytes
        .windows("unique-windows-plaintext-marker-9f3b".len())
        .any(|window| window == b"unique-windows-plaintext-marker-9f3b"));
    let (scope, private_root) = store_paths(&fixture.state_base, &fixture.account, false).unwrap();
    let ciphertext = read_blob(
        &blob_path(&scope, &anchor.ciphertext_digest),
        maximum_ciphertext_bytes(fixture.max_bytes()).unwrap(),
        &private_root,
    )
    .unwrap();
    assert!(!ciphertext
        .windows("unique-windows-plaintext-marker-9f3b".len())
        .any(|window| window == b"unique-windows-plaintext-marker-9f3b"));
}
