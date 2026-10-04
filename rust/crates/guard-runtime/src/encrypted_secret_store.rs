//! `store_base.py` `EncryptedFileSecretStore` — encrypted file-based Guard
//! credential storage, ported to Rust.
//!
//! File layout is byte-compatible so Rust and Python share the same
//! `~/.hol-guard/secrets/` directory: each secret is `<normalized_id>.enc`
//! holding `{version:"fernet-v1", ciphertext:<fernet-token>}`. The Fernet key
//! lives at `secrets/key.bin` (urlsafe-b64 32 bytes; raw 32-byte keys are
//! upgraded to b64 on first read, matching `_load_fernet_key`).
//!
//! Fernet v1 (cryptography 50.x): token = b64url(`0x80 || ts8be || iv16 ||
//! AES-128-CBC-PKCS7(pt) || hmac-sha256(signing_key, prefix)`); key splits
//! signing=key[..16], encryption=key[16..]. Decrypt verifies the HMAC first
//! (constant-time) then CBC-decrypts + strips PKCS7. A legacy XOR keystream
//! (`_expand_keystream`) fallback handles pre-Fernet payloads.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

const FERNET_VERSION_BYTE: u8 = 0x80;
const FERNET_KEY_LEN: usize = 32;

/// `EncryptedFileSecretStore` — the per-user encrypted-file backend.
pub struct EncryptedFileSecretStore {
    base_dir: PathBuf,
    key_path: PathBuf,
    /// Lazily loaded Fernet key (the 32 decoded bytes), matching
    /// `self._fernet` once `_ensure_ready` succeeds. `None` until first use.
    fernet_key: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl EncryptedFileSecretStore {
    /// `__init__` — `base_dir = guard_home / "secrets"`, `key_path = key.bin`.
    pub fn new(guard_home: &Path) -> Self {
        let base_dir = guard_home.join("secrets");
        Self {
            key_path: base_dir.join("key.bin"),
            base_dir,
            fernet_key: None,
        }
    }

    /// `_ensure_ready` — create the secrets dir (0700) and load/generate the
    /// Fernet key. Mirrors Python: on a missing key it generates one under an
    /// init lock. Callers that only *read* still get the key material needed
    /// to decrypt.
    pub fn ensure_ready(&mut self) -> std::io::Result<()> {
        if self.fernet_key.is_some() {
            return Ok(());
        }
        fs::create_dir_all(&self.base_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.base_dir, fs::Permissions::from_mode(0o700));
        }
        let key = self.load_or_create_fernet_key()?;
        self.fernet_key = Some(key);
        Ok(())
    }

    /// `_load_fernet_key` — read `key.bin`; if absent, generate + persist a new
    /// 32-byte key (b64-encoded on disk). Raw 32-byte keys upgrade to b64.
    fn load_or_create_fernet_key(&self) -> std::io::Result<Vec<u8>> {
        let existing = match fs::read(&self.key_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let existing: Vec<u8> = existing.iter().take(4096).copied().collect();
        let stripped: Vec<u8> = existing
            .iter()
            .copied()
            .skip_while(|b| b.is_ascii_whitespace())
            .collect();
        let stripped: Vec<u8> = {
            let mut v = stripped;
            while matches!(v.last(), Some(b) if b.is_ascii_whitespace()) {
                v.pop();
            }
            v
        };
        if !stripped.is_empty() {
            if let Ok(decoded) = b64url_decode(&stripped) {
                if decoded.len() == FERNET_KEY_LEN {
                    // Already-b64 key: Fernet uses the *encoded* string as the
                    // b64-decoded 32 bytes; Python returns `existing` (the b64
                    // bytes) which it b64-decodes at use. Store decoded form.
                    return Ok(decoded);
                }
            }
            if stripped.len() == FERNET_KEY_LEN {
                let upgraded = b64url_encode(&stripped);
                let _ = self.atomic_write_bytes(&self.key_path, upgraded.as_bytes(), 0o600);
                return Ok(stripped);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted Guard secret key is invalid",
            ));
        }
        // Missing/empty → generate (b64 on disk, decoded in memory).
        let raw = random_bytes(FERNET_KEY_LEN);
        let encoded = b64url_encode(&raw);
        self.atomic_write_bytes(&self.key_path, encoded.as_bytes(), 0o600)?;
        Ok(raw)
    }

    /// `_path_for` — `/` and `:` → `_`, suffix `.enc`.
    fn path_for(&self, secret_id: &str) -> PathBuf {
        let normalized: String = secret_id
            .chars()
            .map(|c| if c == '/' || c == ':' { '_' } else { c })
            .collect();
        self.base_dir.join(format!("{normalized}.enc"))
    }

    /// `get_secret` — decrypt `fernet-v1`, else legacy keystream → re-encrypt
    /// as fernet and return.
    pub fn get_secret(&mut self, secret_id: &str) -> Option<String> {
        self.ensure_ready().ok()?;
        let path = self.path_for(secret_id);
        if !path.exists() {
            return None;
        }
        let payload: Value = serde_json::from_str(&fs::read_to_string(&path).ok()?).ok()?;
        if !payload.is_object() {
            return None;
        }
        if let Some(v) = self.decrypt_fernet(&payload) {
            return Some(v);
        }
        let legacy = self.decrypt_legacy_payload(&payload)?;
        let _ = self.set_secret(secret_id, &legacy);
        Some(legacy)
    }

    /// `set_secret` — Fernet-encrypt + atomic-write `{version,ciphertext}`.
    pub fn set_secret(&mut self, secret_id: &str, value: &str) -> std::io::Result<()> {
        self.ensure_ready()?;
        let payload = self.encrypt_fernet(value)?;
        let path = self.path_for(secret_id);
        self.atomic_write_bytes(&path, serde_json::to_string(&payload)?.as_bytes(), 0o600)
    }

    /// `delete_secret`.
    pub fn delete_secret(&mut self, secret_id: &str) {
        if self.ensure_ready().is_err() {
            return;
        }
        let path = self.path_for(secret_id);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }

    /// `_encrypt_fernet` → `{version:"fernet-v1", ciphertext:<token>}`.
    fn encrypt_fernet(&self, value: &str) -> std::io::Result<Value> {
        let key = self
            .fernet_key
            .as_ref()
            .ok_or_else(|| std::io::Error::other("secret store is not initialized"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let token = fernet_encrypt(key, value.as_bytes(), now)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(serde_json::json!({"version":"fernet-v1","ciphertext":token}))
    }

    /// `_decrypt_fernet` — returns `None` on any mismatch (Python swallows
    /// `InvalidToken/ValueError/TypeError`).
    fn decrypt_fernet(&self, payload: &Value) -> Option<String> {
        if payload.get("version").and_then(Value::as_str) != Some("fernet-v1") {
            return None;
        }
        let ciphertext = payload.get("ciphertext")?.as_str()?;
        let key = self.fernet_key.as_ref()?;
        let plaintext = fernet_decrypt(key, ciphertext.as_bytes(), None).ok()?;
        String::from_utf8(plaintext).ok()
    }

    /// `_decrypt_legacy_payload` — XOR keystream over `{nonce,ciphertext}`.
    fn decrypt_legacy_payload(&self, payload: &Value) -> Option<String> {
        let nonce = payload.get("nonce")?.as_str()?;
        let ciphertext = payload.get("ciphertext")?.as_str()?;
        let nonce = b64url_decode(nonce.as_bytes()).ok()?;
        let ciphertext = b64url_decode(ciphertext.as_bytes()).ok()?;
        let key = self.fernet_key.as_ref()?;
        let keystream = expand_keystream(key, &nonce, ciphertext.len());
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();
        String::from_utf8(plaintext).ok()
    }

    /// `_atomic_write_bytes` — write `.name.<rand>.tmp`, fsync, chmod, rename.
    fn atomic_write_bytes(&self, path: &Path, payload: &[u8], _mode: u32) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_file_name(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
            hex::encode(random_bytes(16))
        ));
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp)?;
            f.write_all(payload)?;
            f.flush()?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(_mode));
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Free `_atomic_write_bytes` for non-store callers (e.g. `TotpSecretStore`).
/// `.name.<rand>.tmp`, fsync, chmod, rename.
pub(crate) fn atomic_write_bytes(path: &Path, payload: &[u8], _mode: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        hex::encode(random_bytes(16))
    ));
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(payload)?;
        f.flush()?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(_mode));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Free `_load_fernet_key` — read `key.bin`; if absent generate + persist a new
/// 32-byte key (b64 on disk, decoded in memory). Raw 32-byte keys upgrade.
/// Shared by `EncryptedFileSecretStore` and `TotpSecretStore`.
pub(crate) fn load_or_create_fernet_key(key_path: &Path) -> std::io::Result<Vec<u8>> {
    let existing = match fs::read(key_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let existing: Vec<u8> = existing.iter().take(4096).copied().collect();
    let mut stripped: Vec<u8> = existing
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .collect();
    while matches!(stripped.last(), Some(b) if b.is_ascii_whitespace()) {
        stripped.pop();
    }
    if !stripped.is_empty() {
        if let Ok(decoded) = b64url_decode(&stripped) {
            if decoded.len() == FERNET_KEY_LEN {
                return Ok(decoded);
            }
        }
        if stripped.len() == FERNET_KEY_LEN {
            let upgraded = b64url_encode(&stripped);
            let _ = atomic_write_bytes(key_path, upgraded.as_bytes(), 0o600);
            return Ok(stripped);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted Guard secret key is invalid",
        ));
    }
    let raw = random_bytes(FERNET_KEY_LEN);
    let encoded = b64url_encode(&raw);
    atomic_write_bytes(key_path, encoded.as_bytes(), 0o600)?;
    Ok(raw)
}

/// `Fernet.generate_key` equivalent — random 32-byte urlsafe-b64 key material.
pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("getrandom");
    buf
}

pub(crate) fn b64url_encode(b: &[u8]) -> String {
    use base64ct::{Base64Url, Encoding};
    let mut buf = vec![0u8; b.len().div_ceil(3) * 4];
    let out = Base64Url::encode(b, &mut buf).expect("b64 encode");
    out.to_owned()
}

pub(crate) fn b64url_decode(b: &[u8]) -> Result<Vec<u8>, &'static str> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    // Fernet uses urlsafe b64; Python's urlsafe_b64decode tolerates padding.
    let s = std::str::from_utf8(b).map_err(|_| "invalid b64")?;
    let unpadded = s.trim().trim_end_matches('=');
    let mut buf = vec![0u8; (unpadded.len() * 3) / 4 + 4];
    let out = Base64UrlUnpadded::decode(unpadded, &mut buf).map_err(|_| "invalid b64")?;
    Ok(out.to_vec())
}

/// `_expand_keystream` (:1169-1179) — SHA256(key|nonce|counter32be) chain.
fn expand_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(key);
        h.update(nonce);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

/// `Fernet._encrypt_from_parts` — 0x80 | ts8be | iv | AES-128-CBC-PKCS7 | HMAC.
pub(crate) fn fernet_encrypt(
    key: &[u8],
    data: &[u8],
    current_time: u64,
) -> Result<String, &'static str> {
    if key.len() != FERNET_KEY_LEN {
        return Err("fernet key must be 32 bytes");
    }
    let signing_key = &key[..16];
    let encryption_key: [u8; 16] = key[16..32].try_into().map_err(|_| "bad enc key")?;
    let iv: [u8; 16] = random_bytes(16).try_into().map_err(|_| "iv")?;

    let mut buf = vec![0u8; data.len() + 16];
    buf[..data.len()].copy_from_slice(data);
    let ct = Aes128CbcEnc::new(&encryption_key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .map_err(|_| "encrypt")?
        .to_vec();

    let mut parts = Vec::with_capacity(9 + 16 + ct.len());
    parts.push(FERNET_VERSION_BYTE);
    parts.extend_from_slice(&current_time.to_be_bytes());
    parts.extend_from_slice(&iv);
    parts.extend_from_slice(&ct);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key).map_err(|_| "hmac key")?;
    mac.update(&parts);
    let tag = mac.finalize().into_bytes();
    parts.extend_from_slice(&tag);
    Ok(b64url_encode(&parts))
}

/// `Fernet._decrypt_data` — HMAC-verify then AES-128-CBC-PKCS7 decrypt.
/// `ttl` enforces the `timestamp + ttl >= now` freshness window.
pub(crate) fn fernet_decrypt(
    key: &[u8],
    token: &[u8],
    ttl: Option<u64>,
) -> Result<Vec<u8>, &'static str> {
    if key.len() != FERNET_KEY_LEN {
        return Err("fernet key must be 32 bytes");
    }
    let signing_key = &key[..16];
    let encryption_key: [u8; 16] = key[16..32].try_into().map_err(|_| "bad enc key")?;
    let data = b64url_decode(token)?;
    if data.len() < 9 + 16 + 16 + 32 || data[0] != FERNET_VERSION_BYTE {
        return Err("invalid token");
    }
    let timestamp = u64::from_be_bytes(data[1..9].try_into().map_err(|_| "ts")?);
    if let Some(ttl) = ttl {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if timestamp.saturating_add(ttl) < now {
            return Err("token expired");
        }
        const MAX_CLOCK_SKEW: u64 = 60;
        if now.saturating_add(MAX_CLOCK_SKEW) < timestamp {
            return Err("token from future");
        }
    }
    let iv: [u8; 16] = data[9..25].try_into().map_err(|_| "iv")?;
    let ciphertext = &data[25..data.len() - 32];
    let tag = &data[data.len() - 32..];

    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key).map_err(|_| "hmac key")?;
    mac.update(&data[..data.len() - 32]);
    mac.verify_slice(tag).map_err(|_| "hmac mismatch")?;

    let mut buf = ciphertext.to_vec();
    let pt = Aes128CbcDec::new(&encryption_key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "bad padding")?
        .to_vec();
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORACLE: &str = include_str!("../testdata/secret_store_oracle.json");

    /// Byte-parity with `cryptography.fernet`: decrypt a real Python-generated
    /// Fernet token (both random-IV variants), and the `fernet-v1` file payload.
    #[test]
    fn fernet_python_oracle() {
        let oracle: Value = serde_json::from_str(ORACLE).unwrap();
        let key = b64url_decode(oracle["key_b64"].as_str().unwrap().as_bytes()).unwrap();
        let want = oracle["secret"].as_str().unwrap();

        for tok in ["fernet_token", "fernet_token2"] {
            let token = oracle[tok].as_str().unwrap();
            let pt = fernet_decrypt(&key, token.as_bytes(), None).expect("decrypt");
            assert_eq!(String::from_utf8(pt).unwrap(), want);
        }
        // Tampered token (bad HMAC) → Err.
        let mut bad = oracle["fernet_token"].as_str().unwrap().as_bytes().to_vec();
        let n = bad.len();
        bad[n - 2] = if bad[n - 2] == b'A' { b'B' } else { b'A' };
        assert!(fernet_decrypt(&key, &bad, None).is_err());
    }

    /// `EncryptedFileSecretStore` reads a Python-written `<id>.enc` file from a
    /// real guard_home, and `set_secret`/`get_secret` round-trip.
    #[test]
    fn store_reads_python_file() {
        let oracle: Value = serde_json::from_str(ORACLE).unwrap();
        let dir = std::env::temp_dir().join(format!("hg-sec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let secrets = dir.join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("key.bin"), oracle["key_b64"].as_str().unwrap()).unwrap();
        fs::write(
            secrets.join("svc_token.enc"),
            serde_json::to_string(&oracle["file_payload"]).unwrap(),
        )
        .unwrap();

        let mut store = EncryptedFileSecretStore::new(&dir);
        let got = store.get_secret("svc:token").expect("get_secret");
        assert_eq!(got, oracle["secret"].as_str().unwrap());

        // Round-trip via our own encrypt → decrypt through Python-parity path.
        store.set_secret("svc:new", "fresh-value").unwrap();
        assert_eq!(store.get_secret("svc:new").as_deref(), Some("fresh-value"));
        // Missing id → None.
        assert_eq!(store.get_secret("svc:nope"), None);

        let _ = fs::remove_dir_all(&dir);
    }

    /// Legacy keystream payload decrypts (and re-encrypts to fernet on read).
    #[test]
    fn legacy_keystream_fallback() {
        let oracle: Value = serde_json::from_str(ORACLE).unwrap();
        let dir = std::env::temp_dir().join(format!("hg-leg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let secrets = dir.join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("key.bin"), oracle["key_b64"].as_str().unwrap()).unwrap();

        // Build a legacy payload by hand: nonce + ciphertext = pt ^ keystream.
        let key = b64url_decode(oracle["key_b64"].as_str().unwrap().as_bytes()).unwrap();
        let secret = "legacy-secret";
        let nonce = random_bytes(16);
        let ks = expand_keystream(&key, &nonce, secret.len());
        let ct: Vec<u8> = secret.bytes().zip(ks.iter()).map(|(b, k)| b ^ k).collect();
        let payload = serde_json::json!({
            "nonce": b64url_encode(&nonce),
            "ciphertext": b64url_encode(&ct),
        });
        fs::write(
            secrets.join("svc_legacy.enc"),
            serde_json::to_string(&payload).unwrap(),
        )
        .unwrap();

        let mut store = EncryptedFileSecretStore::new(&dir);
        assert_eq!(
            store.get_secret("svc:legacy").as_deref(),
            Some("legacy-secret")
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
