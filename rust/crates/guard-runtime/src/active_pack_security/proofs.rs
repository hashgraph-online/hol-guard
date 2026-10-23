//! Native completeness/absence proofs. A transport may fill only the requested
//! immutable object; it cannot choose active identities or interpretation.
use super::*;
use std::path::Path;

pub(crate) enum Failure {
    Need(Value),
    Archives(Value),
    Invalid(&'static str),
}
type Result<T> = std::result::Result<T, Failure>;
fn invalid() -> Failure {
    Failure::Invalid("active_security_proof_invalid")
}
fn decode(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let canonical = canonical_json_bytes(&value).map_err(|_| invalid())?;
    if bytes != canonical && bytes.strip_suffix(b"\n") != Some(canonical.as_slice()) {
        return Err(invalid());
    }
    Ok(value)
}

fn reference(value: &Value) -> Result<(String, usize, usize)> {
    let map = value.as_object().ok_or_else(invalid)?;
    if map.len() != 4 + usize::from(map.contains_key("location"))
        || !["sha256", "length", "expanded_length", "kind"]
            .iter()
            .all(|k| map.contains_key(*k))
    {
        return Err(invalid());
    }
    let sha = value["sha256"]
        .as_str()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .ok_or_else(invalid)?
        .to_owned();
    let length = value["length"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 65536)
        .ok_or_else(invalid)? as usize;
    let expanded = value["expanded_length"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 8 * 1024 * 1024)
        .ok_or_else(invalid)? as usize;
    if !matches!(value["kind"].as_str(), Some("data" | "concat"))
        || (value["kind"] == "data" && length != expanded)
    {
        return Err(invalid());
    }
    Ok((sha, length, expanded))
}

fn bytes(directory: &Path, value: &Value, depth: usize) -> Result<Vec<u8>> {
    if depth > 4 {
        return Err(invalid());
    }
    let (sha, length, expanded) = reference(value)?;
    let path = directory.join("objects").join(format!("{sha}.json"));
    let raw = match guard_secure_fs::read_bounded(&path, 65536) {
        Ok(read) => read.bytes,
        Err(_) => {
            if !path.exists() && value.get("location").is_some() {
                return Err(Failure::Need(value.clone()));
            }
            return Err(Failure::Invalid("active_security_proof_unavailable"));
        }
    };
    if raw.len() != length || hex::encode(Sha256::digest(&raw)) != sha {
        return Err(invalid());
    }
    if value["kind"] == "data" {
        return Ok(raw);
    }
    let concat = decode(&raw)?;
    if !matches!(
        concat["schema"].as_str(),
        Some("guard.pack-concat.v1" | "guard.delivery-concat.v2")
    ) {
        return Err(invalid());
    }
    let parts = concat["parts"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 64)
        .ok_or_else(invalid)?;
    let mut all = Vec::new();
    for part in parts {
        let part = bytes(directory, part, depth + 1)?;
        if all.len() + part.len() > expanded {
            return Err(invalid());
        }
        all.extend(part);
    }
    if all.len() != expanded {
        return Err(invalid());
    }
    Ok(all)
}
pub(crate) fn object(directory: &Path, value: &Value) -> Result<Value> {
    decode(&bytes(directory, value, 0)?)
}

pub(crate) fn lookup(
    directory: &Path,
    reference_value: &Value,
    count: u64,
    id: &str,
) -> Result<Option<Value>> {
    let hash = hex::encode(Sha256::digest(id.as_bytes()));
    let mut target = reference_value.clone();
    let mut count = count;
    let mut prefix = String::new();
    for _ in 0..=64 {
        let (_, _, size) = reference(&target)?;
        if size > 65536 {
            return Err(invalid());
        }
        let page = object(directory, &target)?;
        if page["schema"] != "guard.pack-index.v1" || page["prefix"] != prefix {
            return Err(invalid());
        }
        let map = page.as_object().ok_or_else(invalid)?;
        if page["kind"] == "leaf" {
            let rows = page["entries"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 64 && a.len() as u64 == count)
                .ok_or_else(invalid)?;
            if map.len() != 4 {
                return Err(invalid());
            }
            let mut previous = "";
            let mut found = None;
            for row in rows {
                let row = row
                    .as_array()
                    .filter(|a| a.len() == 2)
                    .ok_or_else(invalid)?;
                let key = row[0]
                    .as_str()
                    .filter(|s| s.is_ascii() && !s.is_empty() && s.len() <= 256)
                    .ok_or_else(invalid)?;
                if key <= previous
                    || !hex::encode(Sha256::digest(key.as_bytes())).starts_with(&prefix)
                {
                    return Err(invalid());
                }
                previous = key;
                reference(&row[1])?;
                if key == id {
                    found = Some(row[1].clone());
                }
            }
            return Ok(found);
        }
        if page["kind"] != "branch" || map.len() != 4 {
            return Err(invalid());
        }
        let rows = page["children"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 16)
            .ok_or_else(invalid)?;
        let mut sum = 0u64;
        let mut previous = "";
        let mut found = None;
        for row in rows {
            let row = row
                .as_array()
                .filter(|a| a.len() == 3)
                .ok_or_else(invalid)?;
            let key = row[0].as_str().ok_or_else(invalid)?;
            let size = row[1].as_u64().filter(|n| *n > 0).ok_or_else(invalid)?;
            if key <= previous
                || key.len() != prefix.len() + 1
                || !key.starts_with(&prefix)
                || !key
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err(invalid());
            }
            reference(&row[2])?;
            sum = sum.checked_add(size).ok_or_else(invalid)?;
            previous = key;
            if hash.starts_with(key) {
                found = Some((key.to_owned(), size, row[2].clone()));
            }
        }
        if sum != count {
            return Err(invalid());
        }
        match found {
            Some((key, size, next)) => {
                prefix = key;
                count = size;
                target = next;
            }
            None => return Ok(None),
        }
    }
    Err(invalid())
}

pub(super) fn complete(state: &mut Security, header: &Value, directory: &Path) -> Result<()> {
    let old_root = object(directory, &header["distribution"])?;
    if header["distribution"]["sha256"] != header["root_digest"] {
        return Err(invalid());
    }
    let mut selected = BTreeSet::new();
    let mut target = header["selection"].clone();
    let mut visited = BTreeSet::new();
    let count = header["selected_count"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 32768)
        .ok_or_else(invalid)? as usize;
    while !target.is_null() {
        if !visited.insert(target["sha256"].clone().to_string()) || visited.len() > count {
            return Err(invalid());
        }
        let page = object(directory, &target)?;
        let ids = page["ids"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 64)
            .ok_or_else(invalid)?;
        if page["schema"] != "guard.command-pack-selection-page.v1" {
            return Err(invalid());
        }
        for id in ids {
            let id = id
                .as_str()
                .filter(|s| s.is_ascii() && s.starts_with("command.") && s.len() <= 256)
                .ok_or_else(invalid)?;
            if selected
                .last()
                .is_some_and(|last: &String| last.as_str() >= id)
                || selected.len() >= count
            {
                return Err(invalid());
            }
            selected.insert(id.to_owned());
        }
        target = page["next"].clone();
    }
    if selected.len() != count {
        return Err(invalid());
    }
    let index = &old_root["policy"]["root"];
    let total = index["extensions"].as_u64().ok_or_else(invalid)?;
    let revocations = &state.root["policy"]["revocations"];
    let rev_count = revocations["count"].as_u64().ok_or_else(invalid)?;
    state.quarantine.clear();
    state.applied.clear();
    for id in selected {
        let manifest = lookup(directory, &index["index"], total, &id)?.ok_or_else(invalid)?;
        let manifest_digest = manifest["sha256"].as_str().ok_or_else(invalid)?;
        let old_manifest = object(directory, &manifest)?;
        let mut denied = state.authority
            > header["authority_epoch"].as_u64().ok_or_else(invalid)?
            || state.root["engine"] != header["engine"];
        // A publisher can change reviewed trust without revoking the entire
        // extension. Only the active identity's authenticated native path is
        // traversed; inactive policy payload never participates.
        if !denied {
            match super::trust::latest(directory, &state.root, &id)? {
                Some(latest) => {
                    let incompatible = latest["trust_digest"] != old_manifest["trust_digest"]
                        || latest["engine"] != old_manifest["engine"]
                        || latest["semantic_profile"] != old_manifest["semantic_profile"];
                    denied |= incompatible;
                    if incompatible {
                        state.applied.insert(format!("trust:{id}"), json!({
                        "trust":latest["trust_digest"],"engine":latest["engine"],"semantics":latest["semantic_profile"]}));
                    }
                }
                None => denied = true,
            }
        }
        if state.authority > header["authority_epoch"].as_u64().ok_or_else(invalid)?
            || state.root["engine"] != header["engine"]
        {
            state.applied.insert(
                format!("floor:{id}"),
                json!({"authority":state.authority,"engine":state.root["engine"]}),
            );
        }
        for (kind, hash) in [("extension", ""), ("pack", manifest_digest)] {
            let mut hasher = Sha256::new();
            hasher.update(b"hol-guard.extension-revocation.v1\0");
            hasher.update(kind.as_bytes());
            hasher.update(b"\0");
            hasher.update(id.as_bytes());
            hasher.update(b"\0");
            hasher.update(hash.as_bytes());
            let key = hex::encode(hasher.finalize());
            let proof = if rev_count == 0 {
                if !revocations["index"].is_null() {
                    return Err(invalid());
                }
                None
            } else {
                lookup(directory, &revocations["index"], rev_count, &key)?
            };
            if let Some(proof) = proof {
                let record = object(directory, &proof)?;
                let epoch = record["epoch"]
                    .as_u64()
                    .filter(|n| *n > 0 && *n <= state.epoch)
                    .ok_or_else(invalid)?;
                if record["schema"] != "guard.extension-revocation.v1"
                    || record["extension_id"] != id
                    || record["kind"] != kind
                    || (kind == "pack" && record["manifest_sha256"] != hash)
                    || !matches!(record["state"].as_str(), Some("revoked" | "restored"))
                {
                    return Err(invalid());
                }
                let fields = record.as_object().ok_or_else(invalid)?;
                if fields.len() != if kind == "pack" { 7 } else { 6 }
                    || record["reason"]
                        .as_str()
                        .is_none_or(|reason| reason.is_empty() || reason.len() > 1024)
                {
                    return Err(invalid());
                }
                // The lookup key already binds kind, owner and manifest. Keep
                // only security semantics; publisher prose is not an approval
                // identity and must not exhaust protected observation storage.
                let record = json!({"epoch":epoch,"state":record["state"]});
                if let Some(old) = state.facts.get(&key) {
                    let old_epoch = old["epoch"].as_u64().ok_or_else(invalid)?;
                    if epoch < old_epoch || (epoch == old_epoch && record != *old) {
                        return Err(invalid());
                    }
                }
                state.facts.insert(key.clone(), record);
                if state.facts.len() > 1024 {
                    return Err(Failure::Invalid("active_security_facts_capacity"));
                }
            }
            denied |= state
                .facts
                .get(&key)
                .is_some_and(|record| record["state"] == "revoked");
            if let Some(record) = state.facts.get(&key) {
                state.applied.insert(key, record.clone());
            }
        }
        if denied {
            state.quarantine.insert(id);
        }
    }
    state.pending = false;
    Ok(())
}
