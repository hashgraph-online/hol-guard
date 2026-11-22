use std::path::PathBuf;

use serde_json::Value;

use super::*;

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str) -> Home {
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).expect("random");
    let path = std::env::temp_dir().join(format!("key-mint-{name}-{}", hex::encode(raw)));
    fs::create_dir_all(&path).expect("home");
    Home(path)
}

fn stored(path: &Path) -> Option<String> {
    let resolved = fs::canonicalize(path).expect("resolved");
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, &resolved);
    EncryptedFileSecretStore::new(&resolved).get_secret(&key_ref)
}

fn answer(request: &str) -> Result<Value, String> {
    run_command(request.as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer json"))
}

#[cfg(unix)]
#[test]
fn a_fresh_home_gets_one_32_byte_key() {
    let home = home("fresh");
    assert_eq!(mint_once(&home.0), Minted::Present);
    let key = stored(&home.0).expect("key stored");
    let raw = crate::encrypted_secret_store::b64url_decode(key.as_bytes()).expect("b64");
    assert_eq!(raw.len(), KEY_BYTES);
    assert!(key.ends_with('='), "padded like urlsafe_b64encode");
}

#[cfg(unix)]
#[test]
fn a_stored_key_is_never_replaced() {
    let home = home("stored");
    assert_eq!(mint_once(&home.0), Minted::Present);
    let first = stored(&home.0);
    assert_eq!(mint_once(&home.0), Minted::Present);
    assert_eq!(stored(&home.0), first);
}

#[cfg(unix)]
#[test]
fn armed_controls_without_a_readable_key_mint_nothing() {
    for name in ARMED_FILES {
        let home = home("armed");
        let state = home.0.join(NATIVE_RUNTIME_STATE_DIRECTORY);
        fs::create_dir_all(&state).expect("state");
        fs::write(state.join(name), b"x").expect("armed file");
        assert_eq!(mint_once(&home.0), Minted::Armed, "{name}");
        assert_eq!(stored(&home.0), None);
    }
}

#[cfg(unix)]
#[test]
fn a_held_mint_lock_answers_busy() {
    let home = home("busy");
    let lock = lock_options()
        .open(home.0.join(MINT_LOCK_FILE_NAME))
        .expect("lock");
    fs2::FileExt::lock_exclusive(&lock).expect("held");
    let path = home.0.clone();
    let started = Instant::now();
    let state = std::thread::spawn(move || mint_once(&path))
        .join()
        .expect("mint thread");
    assert_eq!(state, Minted::Busy);
    assert!(started.elapsed() >= MINT_LOCK_TIMEOUT);
    assert_eq!(stored(&home.0), None);
}

#[cfg(unix)]
#[test]
fn the_mint_lock_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let home = home("mode");
    assert_eq!(mint_once(&home.0), Minted::Present);
    let resolved = fs::canonicalize(&home.0).expect("resolved");
    let mode = fs::metadata(resolved.join(MINT_LOCK_FILE_NAME))
        .expect("lock file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
}

#[cfg(unix)]
#[test]
fn concurrent_mints_agree_on_one_key() {
    let home = home("race");
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let path = home.0.clone();
            std::thread::spawn(move || mint_once(&path))
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().expect("mint thread"), Minted::Present);
    }
    let key = stored(&home.0).expect("key stored");
    assert_eq!(mint_once(&home.0), Minted::Present);
    assert_eq!(stored(&home.0), Some(key));
}

#[cfg(unix)]
#[test]
fn the_answer_names_a_state_and_never_the_key() {
    let home = home("answer");
    let request = serde_json::to_string(&serde_json::json!({
        "guard_home": home.0.to_string_lossy(),
    }))
    .expect("request");
    let answer = answer(&request).expect("answer");
    assert_eq!(answer, serde_json::json!({"state": "present"}));
    let key = stored(&home.0).expect("key stored");
    assert!(!answer.to_string().contains(&key));
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        "",
        "{}",
        "[]",
        r#"{"guard_home": ""}"#,
        r#"{"guard_home": "/x", "y": 1}"#,
    ] {
        assert!(answer(request).is_err(), "{request}");
    }
    let large = format!(r#"{{"guard_home": "{}"}}"#, "a".repeat(9000));
    assert!(answer(&large).is_err());
}

#[test]
fn only_its_own_command_is_claimed() {
    assert!(is_command("policy-integrity-key-mint"));
    assert!(!is_command("trust-attestation-key"));
}
