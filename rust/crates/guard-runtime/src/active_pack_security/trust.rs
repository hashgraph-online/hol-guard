//! Select only an active identity's authenticated transport/native path.
use super::{
    proofs::{self, Failure},
    *,
};
use std::path::Path;
type Result<T> = std::result::Result<T, Failure>;
fn invalid() -> Failure {
    Failure::Invalid("active_security_trust_proof_invalid")
}
fn unlocated(value: &Value) -> Value {
    let mut result = value.clone();
    if let Some(map) = result.as_object_mut() {
        map.remove("location");
    }
    result
}

pub(super) fn latest(directory: &Path, root: &Value, id: &str) -> Result<Option<Value>> {
    let native_root = &root["policy"]["root"];
    let mut native = native_root["index"].clone();
    let mut transport = root["policy"]["transport"].clone();
    let hash = hex::encode(Sha256::digest(id.as_bytes()));
    let mut delivery = None;
    for depth in 0..=64 {
        let wrapper = proofs::object(directory, &transport)?;
        if wrapper["schema"] != "guard.policy-transport.v2"
            || unlocated(&wrapper["native"]) != native
        {
            return Err(invalid());
        }
        let page = proofs::object(directory, &wrapper["native"])?;
        if wrapper["kind"] != page["kind"] {
            return Err(invalid());
        }
        if page["kind"] == "leaf" {
            let rows = page["entries"].as_array().ok_or_else(invalid)?;
            let records = wrapper["records"].as_array().ok_or_else(invalid)?;
            if rows.len() != records.len() || rows.len() > 64 {
                return Err(invalid());
            }
            for (row, record) in rows.iter().zip(records) {
                if row[0] != record[0] {
                    return Err(invalid());
                }
                if row[0] == id {
                    delivery = Some(record[1].clone());
                }
            }
            break;
        }
        let rows = page["children"].as_array().ok_or_else(invalid)?;
        let children = wrapper["children"].as_array().ok_or_else(invalid)?;
        if rows.len() != children.len() || rows.len() > 16 {
            return Err(invalid());
        }
        let mut next = None;
        for (row, child) in rows.iter().zip(children) {
            if row[0] != child[0] || row[1] != child[1] {
                return Err(invalid());
            }
            let prefix = row[0].as_str().ok_or_else(invalid)?;
            if hash.starts_with(prefix) {
                next = Some((row[2].clone(), child[2].clone()));
            }
        }
        match next {
            Some((n, t)) if depth < 64 => {
                native = n;
                transport = t;
            }
            _ => break,
        }
    }
    // The shared native proof traversal validates every count, prefix, sibling
    // ownership and complete absence after the located path has been fetched.
    let manifest = proofs::lookup(
        directory,
        &native_root["index"],
        native_root["extensions"].as_u64().ok_or_else(invalid)?,
        id,
    )?;
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    let delivery = proofs::object(directory, &delivery.ok_or_else(invalid)?)?;
    if delivery["schema"] != "guard.policy-delivery.v2"
        || delivery["extension_id"] != id
        || delivery["manifest"] != manifest
    {
        return Err(invalid());
    }
    let path = directory.join("objects").join(format!(
        "{}.json",
        manifest["sha256"].as_str().ok_or_else(invalid)?
    ));
    if !path.exists() {
        let archives = delivery["archives"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 64)
            .ok_or_else(invalid)?;
        for archive in archives {
            if archive["sha256"].as_str().is_none_or(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            }) || archive["length"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > 32 * 1024 * 1024)
            {
                return Err(invalid());
            }
        }
        return Err(Failure::Archives(delivery["archives"].clone()));
    }
    let value = proofs::object(directory, &manifest)?;
    if value["schema"] != "guard.command-policy-pack.v1"
        || value["extension_id"] != id
        || !value["trust_digest"].is_string()
    {
        return Err(invalid());
    }
    Ok(Some(value))
}
