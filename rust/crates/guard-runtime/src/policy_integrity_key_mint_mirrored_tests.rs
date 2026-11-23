use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::{locked_mint_mirrored, ARMED_FILES, NATIVE_RUNTIME_STATE_DIRECTORY};
use super::*;
use crate::policy_integrity_resolver::{build_scoped_secret_ref, POLICY_INTEGRITY_KEY_REF};

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str) -> Home {
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).expect("random");
    let path = std::env::temp_dir().join(format!("key-mint-mirror-{name}-{}", hex::encode(raw)));
    fs::create_dir_all(&path).expect("home");
    Home(fs::canonicalize(&path).expect("resolved"))
}

/// A keyring that counts its calls; `unreadable`/`unwritable` make that call
/// fail the way a locked or absent Secret Service does.
#[derive(Default)]
struct FakeKeyring {
    items: RefCell<HashMap<String, String>>,
    unreadable: bool,
    unreadable_after_write: bool,
    unwritable: bool,
    stalled: bool,
    calls: RefCell<usize>,
}

impl Primary for FakeKeyring {
    fn get(&self, secret_id: &str) -> Result<Option<String>, ()> {
        *self.calls.borrow_mut() += 1;
        if self.unreadable || (self.unreadable_after_write && !self.items.borrow().is_empty()) {
            return Err(());
        }
        Ok(self.items.borrow().get(secret_id).cloned())
    }

    fn set(&self, secret_id: &str, value: &str) -> Result<(), WriteFailure> {
        *self.calls.borrow_mut() += 1;
        if self.unwritable {
            return Err(WriteFailure::Refused);
        }
        if self.stalled {
            return Err(WriteFailure::Unsettled);
        }
        self.items
            .borrow_mut()
            .insert(secret_id.to_owned(), value.to_owned());
        Ok(())
    }
}

fn key_ref(home: &Path) -> String {
    build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, home)
}

fn marker(home: &Path) -> String {
    format!("{FALLBACK_PREFERENCE_PREFIX}{}", key_ref(home))
}

fn vault(home: &Path) -> EncryptedFileSecretStore {
    EncryptedFileSecretStore::new(home)
}

fn mint_with(home: &Path, keyring: &FakeKeyring) -> Minted {
    locked_mint_mirrored(home, Instant::now() + Duration::from_secs(4), keyring)
}

#[cfg(unix)]
#[test]
fn a_fresh_key_goes_to_the_keyring_and_the_vault() {
    let home = home("fresh");
    let keyring = FakeKeyring::default();
    assert_eq!(mint_with(&home.0, &keyring), Minted::Present);
    let in_keyring = keyring.items.borrow().get(&key_ref(&home.0)).cloned();
    assert!(in_keyring.is_some());
    assert_eq!(vault(&home.0).get_secret(&key_ref(&home.0)), in_keyring);
    assert_eq!(vault(&home.0).get_secret(&marker(&home.0)), None);
}

#[cfg(unix)]
#[test]
fn a_refused_keyring_write_leaves_the_vault_authoritative() {
    let home = home("unwritable");
    let keyring = FakeKeyring {
        unwritable: true,
        ..FakeKeyring::default()
    };
    assert_eq!(mint_with(&home.0, &keyring), Minted::Present);
    assert!(vault(&home.0).get_secret(&key_ref(&home.0)).is_some());
    assert_eq!(
        vault(&home.0).get_secret(&marker(&home.0)).as_deref(),
        Some("1")
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_keyring_mints_nothing() {
    let home = home("unreadable");
    let keyring = FakeKeyring {
        unreadable: true,
        ..FakeKeyring::default()
    };
    assert_eq!(mint_with(&home.0, &keyring), Minted::Unavailable);
    assert_eq!(vault(&home.0).get_secret(&key_ref(&home.0)), None);
}

/// A vault whose `secrets` path is a regular file: every write fails, even
/// for root, and every read finds nothing.
fn broken_vault(home: &Path) -> EncryptedFileSecretStore {
    fs::write(home.join("secrets"), b"").expect("secrets file");
    EncryptedFileSecretStore::new(home)
}

#[cfg(unix)]
#[test]
fn a_written_key_the_keyring_cannot_read_back_is_busy() {
    let home = home("unconfirmed");
    let keyring = FakeKeyring {
        unreadable_after_write: true,
        ..FakeKeyring::default()
    };
    let mut vault = broken_vault(&home.0);
    let minted = mint(&home.0, &key_ref(&home.0), &mut vault, &keyring);
    assert_eq!(minted, Minted::Busy);
    let written = keyring.items.borrow().get(&key_ref(&home.0)).cloned();
    assert!(written.is_some());
}

#[cfg(unix)]
#[test]
fn a_timed_out_keyring_write_with_no_vault_copy_is_busy() {
    let home = home("pending");
    let keyring = FakeKeyring {
        stalled: true,
        ..FakeKeyring::default()
    };
    let mut vault = broken_vault(&home.0);
    let minted = mint(&home.0, &key_ref(&home.0), &mut vault, &keyring);
    assert_eq!(minted, Minted::Busy);
}

#[cfg(unix)]
#[test]
fn a_refused_keyring_write_with_no_vault_copy_leaves_python_to_mint() {
    let home = home("refused");
    let keyring = FakeKeyring {
        unwritable: true,
        ..FakeKeyring::default()
    };
    let mut vault = broken_vault(&home.0);
    let minted = mint(&home.0, &key_ref(&home.0), &mut vault, &keyring);
    assert_eq!(minted, Minted::Unavailable);
    assert!(keyring.items.borrow().is_empty());
}

#[cfg(unix)]
#[test]
fn a_key_in_either_copy_is_never_replaced() {
    let keyring_home = home("keyring-key");
    let keyring = FakeKeyring::default();
    keyring
        .items
        .borrow_mut()
        .insert(key_ref(&keyring_home.0), "kept".to_owned());
    assert_eq!(mint_with(&keyring_home.0, &keyring), Minted::Present);
    assert_eq!(
        keyring
            .items
            .borrow()
            .get(&key_ref(&keyring_home.0))
            .map(String::as_str),
        Some("kept")
    );
    assert_eq!(
        vault(&keyring_home.0).get_secret(&key_ref(&keyring_home.0)),
        None
    );

    let vault_home = home("vault-key");
    assert_eq!(
        mint_with(&vault_home.0, &FakeKeyring::default()),
        Minted::Present
    );
    let first = vault(&vault_home.0).get_secret(&key_ref(&vault_home.0));
    let empty = FakeKeyring::default();
    assert_eq!(mint_with(&vault_home.0, &empty), Minted::Present);
    assert!(empty.items.borrow().is_empty());
    assert_eq!(
        vault(&vault_home.0).get_secret(&key_ref(&vault_home.0)),
        first
    );
}

#[cfg(unix)]
#[test]
fn a_marked_vault_answers_alone() {
    let home = home("marked");
    let keyring = FakeKeyring {
        unwritable: true,
        ..FakeKeyring::default()
    };
    assert_eq!(mint_with(&home.0, &keyring), Minted::Present);
    let probe = FakeKeyring {
        unreadable: true,
        ..FakeKeyring::default()
    };
    assert_eq!(mint_with(&home.0, &probe), Minted::Present);
    assert_eq!(*probe.calls.borrow(), 0, "the keyring is not asked");

    vault(&home.0).delete_secret(&key_ref(&home.0));
    assert_eq!(mint_with(&home.0, &probe), Minted::Unavailable);
    assert_eq!(*probe.calls.borrow(), 0);
    assert_eq!(vault(&home.0).get_secret(&key_ref(&home.0)), None);
}

#[cfg(unix)]
#[test]
fn armed_controls_mint_nothing_in_either_copy() {
    let home = home("armed");
    let state = home.0.join(NATIVE_RUNTIME_STATE_DIRECTORY);
    fs::create_dir_all(&state).expect("state");
    fs::write(state.join(ARMED_FILES[0]), b"{}").expect("armed");
    let keyring = FakeKeyring::default();
    assert_eq!(mint_with(&home.0, &keyring), Minted::Armed);
    assert!(keyring.items.borrow().is_empty());
    assert_eq!(vault(&home.0).get_secret(&key_ref(&home.0)), None);
}

#[cfg(unix)]
#[test]
fn a_keyring_write_clears_a_stale_marker() {
    let home = home("stale-marker");
    let mut store = vault(&home.0);
    store.ensure_ready().expect("ready");
    store.set_secret(&marker(&home.0), "0").expect("marker");
    assert_eq!(mint_with(&home.0, &FakeKeyring::default()), Minted::Present);
    assert_eq!(vault(&home.0).get_secret(&marker(&home.0)), None);
}

#[test]
fn a_control_state_mirrors_only_into_a_keyring_copy_python_would_prefer() {
    assert!(mirror_control_state(Existing::Absent, || false, || false));
    assert!(mirror_control_state(Existing::Present, || true, || false));
    assert!(!mirror_control_state(Existing::Present, || false, || true));
    assert!(!mirror_control_state(
        Existing::Unreadable,
        || true,
        || true
    ));
    // No Secret Service: the vault write stands only once the vault is
    // marked as the copy Python reads.
    assert!(mirror_control_state(Existing::NoService, || false, || true));
    assert!(!mirror_control_state(
        Existing::NoService,
        || true,
        || false
    ));
}

#[cfg(unix)]
#[test]
fn a_vault_marked_preferred_is_the_copy_python_reads() {
    let home = home("prefer-vault");
    let mut store = vault(&home.0);
    store.ensure_ready().expect("ready");
    assert!(prefer_vault(&mut store, &key_ref(&home.0)));
    assert_eq!(
        vault(&home.0).get_secret(&marker(&home.0)).as_deref(),
        Some("1")
    );
    assert!(prefer_vault(&mut store, &key_ref(&home.0)));
}
