//! A resident counts its cold-start band only once its transport is serving.

use std::cell::Cell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::*;
use crate::policy_store::PolicySnapshotStore;
use crate::resident_state::state_scope;

const GENERATION: u64 = 7;

struct Fixture {
    base: PathBuf,
    scope: PathBuf,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "hgr-ready-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let key = base.join("policy-verifier.key");
        fs::write(&key, [23u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let digest = "a".repeat(64);
        let scope = state_scope(&base, &digest).unwrap();
        Self {
            base,
            scope,
            digest,
        }
    }

    fn store(&self) -> Arc<PolicySnapshotStore> {
        Arc::new(PolicySnapshotStore::new(&self.base, &self.digest).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn a_start_whose_socket_cannot_bind_is_never_counted_ready() {
    let fixture = Fixture::new();
    let owner_lock = super::super::acquire_managed_owner_lock(&fixture.base).unwrap();
    let socket = socket_directory(&fixture.scope, &fixture.digest)
        .unwrap()
        .join(format!(
            "h3-{}-{GENERATION:016x}.sock",
            &fixture.digest[..8]
        ));
    fs::write(&socket, []).unwrap();
    let ready = Cell::new(false);
    let served = serve_unix_managed(
        (&fixture.scope, &owner_lock),
        fixture.store(),
        GENERATION,
        std::process::id(),
        &fixture.digest,
        [0; crate::AUTH_TOKEN_BYTES],
        Arc::new(AtomicBool::new(true)),
        || ready.set(true),
    );
    assert!(served.is_err());
    assert!(!ready.get());
}

#[test]
fn a_start_is_counted_ready_once_its_transport_has_published() {
    let fixture = Fixture::new();
    let ready = Cell::new(false);
    let served = serve_loopback_managed(
        &fixture.scope,
        fixture.store(),
        GENERATION,
        std::process::id(),
        &fixture.digest,
        [0; crate::AUTH_TOKEN_BYTES],
        Arc::new(AtomicBool::new(false)),
        || ready.set(true),
    );
    assert_eq!(served, Ok(()));
    assert!(ready.get());
}
