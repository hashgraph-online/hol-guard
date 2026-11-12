//! A separate home-local installation key. Never used for remote catalogs or
//! execution approvals; provisioning belongs only to an explicit install write.
use super::*;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    schema: String,
    purpose: String,
    home_sha256: String,
    key_hex: String,
}
impl Drop for KeyRecord {
    fn drop(&mut self) {
        self.key_hex.zeroize();
    }
}
fn location(home: &Path) -> Result<PathBuf, String> {
    let directory = root(home, false)?;
    Ok(directory
        .parent()
        .ok_or_else(|| error("installation_key_unavailable"))?
        .join("installation-authority.json"))
}
fn home_binding(home: &Path) -> Result<String, String> {
    let path = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let text = path.to_str().ok_or_else(|| error("home_invalid"))?;
    let mut digest = Sha256::new();
    digest.update(b"guard-cigar-installation-home.v1\0");
    digest.update(text.as_bytes());
    Ok(format!("{:x}", digest.finalize()))
}
pub(super) fn read(home: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let path = location(home)?;
    let (_, bytes) = read_private_json(&path, 4096, "cigar_installation_key", home)
        .map_err(|_| error("installation_key_invalid"))?
        .ok_or_else(|| error("installation_key_unavailable"))?;
    let bytes = Zeroizing::new(bytes);
    let stable = guard_secure_fs::read_stable(&path, 4096, false)
        .map_err(|_| error("installation_key_invalid"))?;
    if stable.identity.mode & 0o077 != 0 {
        return Err(error("installation_key_invalid"));
    }
    if stable.bytes.as_slice() != bytes.as_slice() {
        return Err(error("installation_key_invalid"));
    }
    let _stable_bytes = Zeroizing::new(stable.bytes);
    let record: KeyRecord = crate::strict_json_value(&bytes).and_then(|value| {
        crate::strict_json::from_value(value).map_err(|_| error("installation_key_invalid"))
    })?;
    if record.schema != "guard-cigar-installation-key.v1"
        || record.purpose != "cigar_installation"
        || record.home_sha256 != home_binding(home)?
        || !is_lower_hex(&record.key_hex, 64)
    {
        return Err(error("installation_key_invalid"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&record.key_hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| error("installation_key_invalid"))?;
    }
    Ok(key)
}
/// The caller must own registry.lock. Missing keys are never created by reads.
pub(super) fn provision_locked(home: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let path = location(home)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => return read(home),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(error("installation_key_invalid")),
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| error("installation_key_unavailable"))?;
    let record = KeyRecord {
        schema: "guard-cigar-installation-key.v1".into(),
        purpose: "cigar_installation".into(),
        home_sha256: home_binding(home)?,
        key_hex: hex::encode(key.as_ref()),
    };
    let bytes = Zeroizing::new(
        serde_json::to_vec(&record).map_err(|_| error("installation_key_unavailable"))?,
    );
    persist_private_bytes(&path, &bytes, 4096, "cigar_installation_key", home)
        .map_err(|_| error("installation_key_write_failed"))?;
    // Reopen through the protected reader before publishing any receipt.
    let observed = read(home)?;
    if observed.as_ref() != key.as_ref() {
        return Err(error("installation_key_invalid"));
    }
    Ok(observed)
}
