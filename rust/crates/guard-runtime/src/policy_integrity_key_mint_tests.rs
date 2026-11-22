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
    let resolved = resolved_home(path).expect("resolved");
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, &resolved);
    EncryptedFileSecretStore::new(&resolved).get_secret(&key_ref)
}

fn answer(request: &str) -> Result<Value, String> {
    run_command(request.as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer json"))
}

#[test]
fn a_fresh_home_gets_one_32_byte_key() {
    let home = home("fresh");
    assert_eq!(mint_once(&home.0), Minted::Present);
    let key = stored(&home.0).expect("key stored");
    let raw = crate::encrypted_secret_store::b64url_decode(key.as_bytes()).expect("b64");
    assert_eq!(raw.len(), KEY_BYTES);
    assert!(key.ends_with('='), "padded like urlsafe_b64encode");
}

#[test]
fn a_stored_key_is_never_replaced() {
    let home = home("stored");
    assert_eq!(mint_once(&home.0), Minted::Present);
    let first = stored(&home.0);
    assert_eq!(mint_once(&home.0), Minted::Present);
    assert_eq!(stored(&home.0), first);
}

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
    assert!(started.elapsed() >= MINT_LOCK_BUDGET);
    assert_eq!(stored(&home.0), None);
}

#[test]
fn both_lock_waits_share_one_budget() {
    let home = home("budget");
    let resolved = fs::canonicalize(&home.0).expect("resolved");
    let secrets = resolved.join(SECRETS_DIRECTORY);
    fs::create_dir_all(&secrets).expect("secrets");
    let init = lock_options()
        .open(secrets.join(KEY_INIT_LOCK_FILE_NAME))
        .expect("init lock");
    fs2::FileExt::lock_exclusive(&init).expect("held");
    let path = home.0.clone();
    let started = Instant::now();
    let state = std::thread::spawn(move || mint_once(&path))
        .join()
        .expect("mint thread");
    assert_eq!(state, Minted::Busy);
    assert!(started.elapsed() < MINT_LOCK_BUDGET + Duration::from_secs(2));
    assert!(!secrets.join(STORE_KEY_FILE_NAME).exists());
}

#[test]
fn an_empty_store_key_is_never_replaced() {
    for contents in [&b""[..], &b"  \n"[..]] {
        let home = home("empty");
        let resolved = fs::canonicalize(&home.0).expect("resolved");
        let secrets = resolved.join(SECRETS_DIRECTORY);
        fs::create_dir_all(&secrets).expect("secrets");
        let key_path = secrets.join(STORE_KEY_FILE_NAME);
        fs::write(&key_path, contents).expect("empty key");
        assert_eq!(mint_once(&home.0), Minted::Unavailable);
        assert_eq!(fs::read(&key_path).expect("key"), contents);
    }
}

#[test]
fn the_store_key_is_created_under_the_python_init_lock() {
    let home = home("init");
    let resolved = fs::canonicalize(&home.0).expect("resolved");
    let secrets = resolved.join(SECRETS_DIRECTORY);
    fs::create_dir_all(&secrets).expect("secrets");
    let init = lock_options()
        .open(secrets.join(KEY_INIT_LOCK_FILE_NAME))
        .expect("init lock");
    fs2::FileExt::lock_exclusive(&init).expect("held");
    let path = home.0.clone();
    let mint = std::thread::spawn(move || mint_once(&path));
    std::thread::sleep(Duration::from_millis(200));
    let key_path = secrets.join(STORE_KEY_FILE_NAME);
    assert!(!key_path.exists(), "no store key while Python initializes");
    // Python's initializer writes its own key, then releases the lock.
    let python_key = crate::encrypted_secret_store::b64url_encode(&[3u8; 32]);
    fs::write(&key_path, &python_key).expect("python key");
    fs2::FileExt::unlock(&init).expect("released");
    assert_eq!(mint.join().expect("mint thread"), Minted::Present);
    assert_eq!(fs::read_to_string(&key_path).expect("key"), python_key);
    assert!(stored(&home.0).is_some());
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

#[test]
fn a_keyring_request_names_only_the_policy_integrity_service() {
    for request in [
        r#"{"guard_home":"/x","keyring":{"service_name":"other"}}"#,
        r#"{"guard_home":"/x","keyring":{"service_name":"hol-guard.policy-integrity","collection":"login"}}"#,
        r#"{"guard_home":"/x","keyring":{}}"#,
    ] {
        assert_eq!(
            answer(request),
            Err("policy_integrity_key_mint_request_invalid".to_owned())
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn a_keyring_request_off_linux_is_unavailable() {
    let home = home("keyring-off-linux");
    let request = serde_json::json!({
        "guard_home": home.0,
        "keyring": {"service_name": KEYRING_SERVICE_NAME},
    });
    let state = answer(&request.to_string()).expect("answer");
    assert_eq!(state, serde_json::json!({"state": "unavailable"}));
    assert_eq!(stored(&home.0), None);
}

#[test]
fn the_key_ref_uses_the_home_as_python_spells_it() {
    assert_eq!(
        without_verbatim_prefix(PathBuf::from(r"\\?\C:\Users\example\.hol-guard")),
        PathBuf::from(r"C:\Users\example\.hol-guard")
    );
    assert_eq!(
        without_verbatim_prefix(PathBuf::from(r"\\?\UNC\server\share\guard")),
        PathBuf::from(r"\\server\share\guard")
    );
    assert_eq!(
        without_verbatim_prefix(PathBuf::from(r"\\?\Volume{0000}\guard")),
        PathBuf::from(r"\\?\Volume{0000}\guard")
    );
    assert_eq!(
        without_verbatim_prefix(PathBuf::from(r"\\?\C:")),
        PathBuf::from(r"\\?\C:")
    );
    assert_eq!(
        without_verbatim_prefix(PathBuf::from("/home/example/.hol-guard")),
        PathBuf::from("/home/example/.hol-guard")
    );
    let home = home("spelling");
    let resolved = resolved_home(&home.0).expect("resolved");
    assert!(!resolved.to_string_lossy().starts_with(r"\\?\"));
}

/// Python's mint lock on Windows, `msvcrt.locking` on the first byte, keeps
/// the native mint waiting until Python releases it.
#[cfg(windows)]
#[test]
fn a_python_mint_lock_keeps_the_native_mint_waiting() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    let home = home("python-lock");
    let lock = home.0.join(MINT_LOCK_FILE_NAME);
    let script = "import msvcrt, sys\n\
        handle = open(sys.argv[1], 'a+b')\n\
        handle.seek(0)\n\
        if not handle.read(1):\n    handle.write(b'0')\n    handle.flush()\n\
        handle.seek(0)\n\
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)\n\
        print('held', flush=True)\n\
        sys.stdin.read()\n";
    let mut python = Command::new("python")
        .args(["-c", script])
        .arg(&lock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python");
    let mut line = String::new();
    BufReader::new(python.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("held line");
    assert_eq!(line.trim(), "held");
    assert_eq!(mint_once(&home.0), Minted::Busy);
    assert_eq!(stored(&home.0), None);
    python
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"")
        .expect("release");
    assert!(python.wait().expect("python exit").success());
    assert_eq!(mint_once(&home.0), Minted::Present);
}
