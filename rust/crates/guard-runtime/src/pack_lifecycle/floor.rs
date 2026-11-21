use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Floor {
    pub schema: String,
    pub source: String,
    pub authority: u64,
    pub revocation: u64,
    pub installed: Option<Identity>,
    pub remote: Option<Identity>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    floor: Floor,
    mac: String,
}

fn authenticator(floor: &Floor, key: &[u8]) -> Result<Hmac<Sha256>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "pack_lifecycle_key_invalid")?;
    mac.update(b"hol-guard.command-pack-protected-floor.v1\0");
    mac.update(&serde_json::to_vec(floor).map_err(|_| "pack_lifecycle_floor_invalid")?);
    Ok(mac)
}

pub(super) fn encode(floor: &Floor, key: &[u8]) -> Result<String, String> {
    let mac = hex::encode(authenticator(floor, key)?.finalize().into_bytes());
    serde_json::to_string(&Record {
        floor: floor.clone(),
        mac,
    })
    .map_err(|_| "pack_lifecycle_floor_invalid".into())
}

pub(super) fn decode(encoded: &str, key: &[u8]) -> Result<Floor, String> {
    if encoded.is_empty() || encoded.len() > 8192 {
        return Err("pack_lifecycle_floor_invalid".into());
    }
    let record: Record =
        serde_json::from_str(encoded).map_err(|_| "pack_lifecycle_floor_invalid")?;
    let mac = hex::decode(&record.mac).map_err(|_| "pack_lifecycle_floor_invalid")?;
    authenticator(&record.floor, key)?
        .verify_slice(&mac)
        .map_err(|_| "pack_lifecycle_floor_authentication_failed")?;
    let floor = record.floor;
    if floor.schema != "guard.command-pack-floor.v1"
        || !hex(&floor.source, 40)
        || floor.authority == 0
        || floor.installed.is_none()
    {
        return Err("pack_lifecycle_floor_invalid".into());
    }
    for identity in [&floor.installed, &floor.remote].into_iter().flatten() {
        identity.validate()?;
        if identity.authority > floor.authority || identity.revocation > floor.revocation {
            return Err("pack_lifecycle_floor_invalid".into());
        }
    }
    if floor
        .installed
        .as_ref()
        .is_some_and(|i| i.profile != "installed")
        || floor.remote.as_ref().is_some_and(|i| i.profile != "remote")
    {
        return Err("pack_lifecycle_floor_invalid".into());
    }
    Ok(floor)
}
