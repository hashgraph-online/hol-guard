#![forbid(unsafe_code)]
//! `totp.py` — local TOTP helpers for the HOL Guard approval gate.
//!
//! RFC 6238 TOTP over RFC 4648 base32 (uppercase, padded), SHA-1 HMAC, dynamic
//! truncation, 6 digits, 30s period, skew ±1 counter. `TotpSecretStore` is a
//! Fernet-backed store under `guard_home/totp-secrets/` (distinct from
//! `EncryptedFileSecretStore`'s `secrets/` root — different directory, `.secret`
//! suffix, `[alnum-_]` id sanitization). `generate_totp_secret` uses 24 random
//! bytes → base32 (padding stripped) — NOT `random_base32()`.
//!
//! PBKDF2 `verify_password` is included here because it is the approval-gate
//! verification leaf (`approval_gate.py:806-827`) — a self-contained crypto
//! primitive the (c)/(013) verify arm consumes.

use std::path::{Path, PathBuf};

use base32ct::{Base32Upper, Encoding};
use hmac::{Hmac, Mac};

pub const TOTP_PERIOD_SECONDS: u64 = 30;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_ALGORITHM: &str = "SHA1";
pub const TOTP_ISSUER: &str = "HOL Guard";

/// `APPROVAL_GATE_*` constants (`approval_gate.py:69-73`).
pub const APPROVAL_GATE_GRANT_TTL_SECONDS: u64 = 30;
pub const APPROVAL_GATE_HASH_ITERATIONS: u32 = 310_000;
pub const APPROVAL_GATE_TOTP_SKEW_STEPS: i64 = 1;
pub const APPROVAL_GATE_TOTP_PENDING_TTL_SECONDS: u64 = 600;
#[allow(dead_code)]
pub const APPROVAL_GATE_TOTP_RECENT_TTL_SECONDS: u64 = 60;
#[allow(dead_code)]
pub const APPROVAL_GATE_HASH_ALGORITHM: &str = "pbkdf2_sha256";
pub const APPROVAL_GATE_MIN_PASSWORD_LENGTH: usize = 8;

/// RFC 6238 forbidden `counter` — `-for_counter` must be a non-negative int.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TotpError(pub String);

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<sha1::Sha1>>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// `_normalize_base32` (`totp.py:163-166`): strip, drop spaces/dashes, uppercase,
/// repad to a multiple of 8.
fn normalize_base32(value: &str) -> String {
    let normalized: String = value.trim().replace([' ', '-'], "").to_uppercase();
    let pad = (8 - normalized.len() % 8) % 8;
    format!("{}{}", normalized, "=".repeat(pad))
}

/// `generate_totp_secret` (`totp.py:103-104`) — 20 random bytes → base32, no padding.
/// Returns `None` if the OS RNG fails (fail-closed; caller re-prompts).
pub fn generate_totp_secret() -> Option<String> {
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).ok()?;
    let mut buf = vec![0u8; Base32Upper::encoded_len(&bytes)];
    let encoded = Base32Upper::encode(&bytes, &mut buf).ok()?;
    Some(encoded.trim_end_matches('=').to_owned())
}

/// `totp_code_at_counter` (`totp.py:147-160`) — HOTP(SHA-1) dynamic truncation.
/// Invalid base32 → empty string (Python raises `binascii.Error`; the caller
/// treats any non-equal as no-match, so an empty code is fail-closed).
pub fn totp_code_at_counter(secret: &str, counter: u64) -> String {
    let normalized = normalize_base32(secret);
    let secret_bytes = match Base32Upper::decode_vec(&normalized) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let message = counter.to_be_bytes(); // 8-byte big-endian
    let digest = hmac_sha1(&secret_bytes, &message);
    let offset = (digest[19] & 0x0F) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7F) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", binary % modulus, width = TOTP_DIGITS as usize)
}

/// `totp_counter` (`totp.py:122-123`) — `int(now_epoch // 30)`.
fn totp_counter(now_epoch: f64) -> i64 {
    (now_epoch / TOTP_PERIOD_SECONDS as f64).floor() as i64
}

/// `verify_totp_code` (`totp.py:126-149`).
///
/// `now_epoch` is unix epoch seconds (float, matching Python `time.time()`).
/// `code` must be exactly `TOTP_DIGITS` ASCII digits. Iterates
/// `range(-skew_steps, skew_steps+1)` ascending so the earliest in-window
/// counter wins. `last_accepted_counter`/`allow_last_counter` implement
/// replay-wind-down. Returns the matched counter, or `None`.
pub fn verify_totp_code(
    secret: &str,
    code: &str,
    now_epoch: f64,
    skew_steps: i64,
    last_accepted_counter: Option<i64>,
    allow_last_counter: bool,
) -> Option<i64> {
    let normalized = code.trim().replace(' ', "");
    if normalized.len() != TOTP_DIGITS as usize || !normalized.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let current = totp_counter(now_epoch);
    for offset in -skew_steps..=skew_steps {
        let counter = current + offset;
        if counter < 0 {
            continue;
        }
        if let Some(last) = last_accepted_counter {
            if counter < last {
                continue;
            }
            if counter == last && !allow_last_counter {
                continue;
            }
        }
        let produced = totp_code_at_counter(secret, counter as u64);
        if !produced.is_empty() && produced == normalized {
            return Some(counter);
        }
    }
    None
}

/// `build_otpauth_uri` (`totp.py:107-120`) — `otpauth://totp/{safe_label}?{params}`.
/// `safe_label = quote("HOL Guard:{device_label}", safe=":")`; params use
/// `urlencode(quote_via=quote)` → space encodes as `%20`, not `+`.
pub fn build_otpauth_uri(secret: &str, device_label: &str) -> String {
    use std::fmt::Write;
    let label = format!("{TOTP_ISSUER}:{device_label}");
    let safe_label = quote_label(&label);
    let params = format!(
        "secret={}&issuer={}&algorithm={}&digits={}&period={}",
        quote_param(secret),
        quote_param(TOTP_ISSUER),
        TOTP_ALGORITHM,
        TOTP_DIGITS,
        TOTP_PERIOD_SECONDS
    );
    let mut uri = String::with_capacity(96);
    let _ = write!(uri, "otpauth://totp/{safe_label}?{params}");
    uri
}

/// `urllib.parse.quote(s, safe=":")` — unreserved + `:` survive; all else
/// percent-encodes (space → `%20`).
fn quote_label(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b':' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// `urllib.parse.quote` default safe set — unreserved survive; `:` encodes.
fn quote_param(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

// ---- PBKDF2 password verifier ------------------------------------------------
// `approval_gate_state.py:85-96` `verify_password` is ported in
// `crate::approval_gate_state::verify_password` (PBKDF2-HMAC-SHA256, base64
// salt/hash, 310_000 iterations, constant-time compare). It lives there — not
// here — because the verifier record is an approval-gate state concern, not a
// TOTP concern. See `APPROVAL_GATE_HASH_ITERATIONS` above.

/// Length-aware constant-time equality — XOR-fold, no early exit.
#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- TotpSecretStore ---------------------------------------------------------
// `totp.py:23-65`. Fernet-backed store at `guard_home/totp-secrets/`; each
// secret at `{sanitized_id}.secret`, encrypted with a locally-managed Fernet key.

fn sanitize_secret_id(secret_id: &str) -> String {
    secret_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `TotpSecretStore` — thin wrapper over a `Fernet` key under
/// `{guard_home}/totp-secrets/key.bin`.
pub struct TotpSecretStore {
    base_dir: PathBuf,
    key_path: PathBuf,
    fernet_key: Option<Vec<u8>>, // raw 32-byte urlsafe-b64-decoded key? see below
}

impl TotpSecretStore {
    pub fn new(guard_home: &Path) -> Self {
        let base_dir = guard_home.join("totp-secrets");
        let key_path = base_dir.join("key.bin");
        Self {
            base_dir,
            key_path,
            fernet_key: None,
        }
    }

    fn path_for(&self, secret_id: &str) -> PathBuf {
        let safe = sanitize_secret_id(secret_id);
        self.base_dir.join(format!("{safe}.secret"))
    }

    /// Read `key.bin` via the shared Fernet loader (raw 32-byte key decoded
    /// from the on-disk b64). Lazily generates + persists on first use.
    /// `_ensure_ready` (`totp.py:33-42`): chmod 0o700 dir, b64 `key.bin`, 0o600.
    pub fn ensure_ready(&mut self) -> Result<Vec<u8>, std::io::Error> {
        if let Some(k) = &self.fernet_key {
            return Ok(k.clone());
        }
        std::fs::create_dir_all(&self.base_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.base_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let raw = crate::encrypted_secret_store::load_or_create_fernet_key(&self.key_path)?;
        self.fernet_key = Some(raw.clone());
        Ok(raw)
    }

    /// `set_secret` — Fernet-encrypt `value`, atomic-write `{id}.secret` raw.
    /// Matches `EncryptedFileSecretStore`'s fernet but writes the bare token
    /// (Python `totp.py:44-48` writes `fernet.encrypt(...)` bytes directly).
    pub fn set_secret(&mut self, secret_id: &str, value: &str) -> Result<(), String> {
        let key = self.ensure_ready().map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let token = crate::encrypted_secret_store::fernet_encrypt(&key, value.as_bytes(), now)
            .map_err(|e| e.to_string())?;
        crate::encrypted_secret_store::atomic_write_bytes(
            &self.path_for(secret_id),
            token.as_bytes(),
            0o600,
        )
        .map_err(|e| e.to_string())
    }

    /// `get_secret` — read + Fernet-decrypt; `None` if missing/invalid.
    pub fn get_secret(&mut self, secret_id: &str) -> Option<String> {
        let key = self.ensure_ready().ok()?;
        let path = self.path_for(secret_id);
        let payload = std::fs::read(&path).ok()?;
        let plain = crate::encrypted_secret_store::fernet_decrypt(&key, &payload, None).ok()?;
        String::from_utf8(plain).ok()
    }

    /// `delete_secret` — remove the file; `Ok(())` when absent.
    pub fn delete_secret(&self, secret_id: &str) -> Result<(), std::io::Error> {
        let path = self.path_for(secret_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 base32 of b"12345678901234567890" — classic HOTP/TOTP test secret.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn totp_code_matches_rfc_and_python_oracle() {
        // Oracle values produced by the Python `totp.py` reference against the
        // same secret/counters (HMAC-SHA1, 6 digits).
        assert_eq!(totp_code_at_counter(SECRET, 0), "755224");
        assert_eq!(totp_code_at_counter(SECRET, 1), "287082");
        assert_eq!(totp_code_at_counter(SECRET, 59), "083773");
        assert_eq!(totp_code_at_counter(SECRET, 37037037), "050471");
    }

    #[test]
    fn normalize_base32_recovers_padded_form() {
        // spaces/dashes/lowercase tolerated; padding re-derived.
        assert_eq!(normalize_base32("gezd gnbv-gy3t qojq"), "GEZDGNBVGY3TQOJQ");
        assert_eq!(normalize_base32("JBSWY3DP"), "JBSWY3DP");
    }

    #[test]
    fn verify_totp_code_accepts_current_window() {
        // counter = now/30; build a code for `now`, verify within skew 1.
        let now = 1690000000.0f64;
        let counter = (now / 30.0).floor() as u64;
        let code = totp_code_at_counter(SECRET, counter);
        assert_eq!(code.len(), 6);
        assert_eq!(
            verify_totp_code(SECRET, &code, now, 1, None, false),
            Some(counter as i64)
        );
        // Off-window (skew 0, code for +2) → rejected.
        let future = totp_code_at_counter(SECRET, counter + 2);
        assert_eq!(verify_totp_code(SECRET, &future, now, 0, None, false), None);
        // Malformed (not 6 digits) → None.
        assert_eq!(verify_totp_code(SECRET, "12", now, 1, None, false), None);
    }

    #[test]
    fn verify_totp_code_replay_wind_down() {
        let now = 1690000000.0f64;
        let counter = (now / 30.0).floor() as i64;
        let code = totp_code_at_counter(SECRET, counter as u64);
        // Same counter as last accepted + disallow → rejected.
        assert_eq!(
            verify_totp_code(SECRET, &code, now, 1, Some(counter), false),
            None
        );
        // allow_last_counter → re-accepts.
        assert_eq!(
            verify_totp_code(SECRET, &code, now, 1, Some(counter), true),
            Some(counter)
        );
        // A future last-accepted counter blocks older codes.
        assert_eq!(
            verify_totp_code(SECRET, &code, now, 1, Some(counter + 5), true),
            None
        );
    }

    #[test]
    fn generate_totp_secret_shape() {
        let s = generate_totp_secret().expect("rng");
        // 20 bytes → 32 base32 chars, padding stripped.
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!s.contains('='));
    }

    #[test]
    fn build_otpauth_uri_format() {
        let uri = build_otpauth_uri(SECRET, "alice laptop");
        // label: quote("HOL Guard:alice laptop", safe=":") → space→%20, colon kept.
        assert!(uri.starts_with("otpauth://totp/HOL%20Guard:alice%20laptop?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=HOL%20Guard"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn totp_secret_store_round_trip() {
        let home = std::env::temp_dir().join(format!("totp-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let mut store = TotpSecretStore::new(&home);
        store.set_secret("dev-1", "seed-value").unwrap();
        assert_eq!(store.get_secret("dev-1").as_deref(), Some("seed-value"));
        // Sanitization: `a/b:c` → `a_b_c.secret`.
        store.set_secret("a/b:c", "v2").unwrap();
        assert!(home.join("totp-secrets/a_b_c.secret").exists());
        assert_eq!(store.get_secret("a/b:c").as_deref(), Some("v2"));
        store.delete_secret("dev-1").unwrap();
        assert!(store.get_secret("dev-1").is_none());
        let _ = std::fs::remove_dir_all(&home);
    }
}
