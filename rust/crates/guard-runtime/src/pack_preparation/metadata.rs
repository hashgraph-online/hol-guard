//! Availability, defaults and revocation proofs do not grant activation.
use super::*;
fn unlocated(value: &Value) -> Value {
    let mut v = value.clone();
    if let Some(m) = v.as_object_mut() {
        m.remove("location");
    }
    v
}
pub(super) fn entries(
    directory: &Path,
    reference: &Value,
    count: u64,
) -> Result<BTreeMap<String, Value>> {
    fn walk(
        directory: &Path,
        reference: &Value,
        count: u64,
        prefix: &str,
        out: &mut BTreeMap<String, Value>,
    ) -> Result<()> {
        if prefix.len() > 64 || count == 0 || count > MAX_SELECTED as u64 {
            return Err(invalid());
        }
        let page = proofs::object(directory, reference)?;
        if page["schema"] != "guard.pack-index.v1" || page["prefix"] != prefix {
            return Err(invalid());
        }
        if page["kind"] == "leaf" {
            let rows = page["entries"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 64 && a.len() as u64 == count)
                .ok_or_else(invalid)?;
            let mut previous = "";
            for row in rows {
                let id = row[0]
                    .as_str()
                    .filter(|s| valid_id(s))
                    .ok_or_else(invalid)?;
                if row.as_array().is_none_or(|a| a.len() != 2)
                    || id <= previous
                    || !hash(id.as_bytes()).starts_with(prefix)
                    || out.insert(id.into(), row[1].clone()).is_some()
                {
                    return Err(invalid());
                }
                previous = id;
            }
        } else if page["kind"] == "branch" {
            let children = page["children"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 16)
                .ok_or_else(invalid)?;
            let mut sum = 0;
            let mut previous = String::new();
            for row in children {
                let key = row[0].as_str().ok_or_else(invalid)?;
                let size = row[1].as_u64().ok_or_else(invalid)?;
                if key.len() != prefix.len() + 1
                    || !key.starts_with(prefix)
                    || key <= previous.as_str()
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid());
                }
                sum += size;
                previous = key.into();
                walk(directory, &row[2], size, key, out)?;
            }
            if sum != count {
                return Err(invalid());
            }
        } else {
            return Err(invalid());
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    if count > 0 {
        walk(directory, reference, count, "", &mut out)?;
    }
    Ok(out)
}
pub(super) fn lookup(
    directory: &Path,
    root: &Value,
    id: &str,
    default: Option<&Value>,
) -> Result<Option<Value>> {
    let native_root = &root["policy"]["root"];
    let mut native = native_root["index"].clone();
    let mut transport = root["policy"]["transport"].clone();
    let mut count = native_root["extensions"].as_u64().ok_or_else(invalid)?;
    let mut prefix = String::new();
    let hashed = hash(id.as_bytes());
    for _ in 0..=64 {
        let wrapper = proofs::object(directory, &transport)?;
        if wrapper.as_object().is_none_or(|m| m.len() != 4) {
            return Err(invalid());
        }
        if wrapper["schema"] != "guard.policy-transport.v2"
            || unlocated(&wrapper["native"]) != native
        {
            return Err("policy transport does not match native root".into());
        }
        let page = proofs::object(directory, &wrapper["native"])?;
        if page["schema"] != "guard.pack-index.v1"
            || page["prefix"] != prefix
            || wrapper["kind"] != page["kind"]
        {
            return Err(invalid());
        }
        if page["kind"] == "leaf" {
            let rows = page["entries"].as_array().ok_or_else(invalid)?;
            let records = wrapper["records"].as_array().ok_or_else(invalid)?;
            if rows.len() != records.len()
                || rows.len() as u64 != count
                || rows.len() > 64
                || rows.is_empty()
            {
                return Err(invalid());
            }
            let mut found = None;
            for (row, record) in rows.iter().zip(records) {
                if row.as_array().is_none_or(|a| a.len() != 2)
                    || record.as_array().is_none_or(|a| a.len() != 2)
                {
                    return Err(invalid());
                }
                proofs::located(&record[1])?;
                if row[0] != record[0] {
                    return Err(invalid());
                }
                if row[0] == id {
                    found = Some(record[1].clone());
                }
            }
            // Authenticate the entire native path, including absence.
            let manifest = proofs::lookup(
                directory,
                &native_root["index"],
                native_root["extensions"].as_u64().ok_or_else(invalid)?,
                id,
            )?;
            let Some(manifest) = manifest else {
                return Ok(None);
            };
            let reference = found.ok_or_else(invalid)?;
            if default.is_some_and(|d| *d != reference) {
                return Err("default policy reference differs from authenticated transport".into());
            }
            let record = proofs::object(directory, &reference)?;
            validate(&record, id, &manifest)?;
            return Ok(Some(record));
        }
        let rows = page["children"].as_array().ok_or_else(invalid)?;
        let children = wrapper["children"].as_array().ok_or_else(invalid)?;
        if rows.len() != children.len() || rows.len() > 16 {
            return Err(invalid());
        }
        let mut next = None;
        for (row, child) in rows.iter().zip(children) {
            if row.as_array().is_none_or(|a| a.len() != 3)
                || child.as_array().is_none_or(|a| a.len() != 3)
            {
                return Err(invalid());
            }
            proofs::located(&child[2])?;
            if row[0] != child[0] || row[1] != child[1] {
                return Err(invalid());
            }
            let key = row[0].as_str().ok_or_else(invalid)?;
            if hashed.starts_with(key) {
                next = Some((
                    key.to_owned(),
                    row[1].as_u64().ok_or_else(invalid)?,
                    row[2].clone(),
                    child[2].clone(),
                ));
            }
        }
        match next {
            Some((p, c, n, t)) => {
                prefix = p;
                count = c;
                native = n;
                transport = t;
            }
            None => {
                if proofs::lookup(
                    directory,
                    &native_root["index"],
                    native_root["extensions"].as_u64().ok_or_else(invalid)?,
                    id,
                )?
                .is_some()
                {
                    return Err(invalid());
                }
                return Ok(None);
            }
        }
    }
    Err(invalid())
}
fn validate(record: &Value, id: &str, manifest: &Value) -> Result<()> {
    proofs::located(&record["catalog_metadata"])?;
    if record.as_object().is_none_or(|m| m.len() != 10)
        || record["schema"] != "guard.policy-delivery.v2"
        || record["extension_id"] != id
        || record["manifest"] != *manifest
    {
        return Err("policy delivery differs from native index".into());
    }
    if !record["required"].is_boolean()
        || !matches!(record["activation"].as_str(), Some("opt-in" | "default-on"))
        || !matches!(
            record["trust_class"].as_str(),
            Some("external" | "trusted-library" | "first-party")
        )
    {
        return Err("policy availability metadata invalid".into());
    }
    for field in ["dependencies", "related_interfaces"] {
        let values = record[field].as_array().ok_or_else(invalid)?;
        if ids(&record[field], "policy interface metadata invalid")?.len() != values.len() {
            return Err("policy interface metadata invalid".into());
        }
    }
    let archives = record["archives"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 64)
        .ok_or_else(invalid)?;
    let mut seen = BTreeSet::new();
    for archive in archives {
        let sha = archive["sha256"]
            .as_str()
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(invalid)?;
        if !seen.insert(sha)
            || archive.as_object().is_none_or(|m| m.len() != 3)
            || archive["length"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > 32 * 1024 * 1024)
            || !archive["location"].is_object()
        {
            return Err("policy archive reference invalid".into());
        }
        proofs::location(&archive["location"], sha, "pack")?;
    }
    Ok(())
}
pub(super) fn revocation(directory: &Path, root: &Value, id: &str, manifest: &Value) -> Result<()> {
    let rev = &root["policy"]["revocations"];
    let count = rev["count"].as_u64().ok_or_else(invalid)?;
    if count == 0 {
        return Ok(());
    }
    let manifest = manifest["sha256"].as_str().ok_or_else(invalid)?;
    for (kind, target) in [("extension", ""), ("pack", manifest)] {
        let key =
            hash(format!("hol-guard.extension-revocation.v1\0{kind}\0{id}\0{target}").as_bytes());
        if let Some(reference) = proofs::lookup(directory, &rev["index"], count, &key)? {
            let value = proofs::object(directory, &reference)?;
            let epoch = value["epoch"]
                .as_u64()
                .filter(|e| *e > 0 && rev["epoch"].as_u64().is_some_and(|max| *e <= max))
                .ok_or_else(invalid)?;
            if value
                .as_object()
                .is_none_or(|m| m.len() != if kind == "pack" { 7 } else { 6 })
                || value["schema"] != "guard.extension-revocation.v1"
                || value["extension_id"] != id
                || value["kind"] != kind
                || (kind == "pack" && value["manifest_sha256"] != target)
                || !matches!(value["state"].as_str(), Some("revoked" | "restored"))
                || value["reason"]
                    .as_str()
                    .is_none_or(|s| s.is_empty() || s.chars().count() > 1024)
            {
                return Err("authenticated revocation record is invalid".into());
            }
            if value["state"] == "revoked" {
                return Err(Failure::Revoked(id.into(), epoch));
            }
        }
    }
    Ok(())
}
