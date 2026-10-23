//! Read-only legacy metadata admission from the authenticated installed Root.
//! Located bytes use the existing native concat/hash/transfer verifier.
use super::*;
use crate::native_command_program::source::MetadataExchange;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

const MAX_BYTES: usize = 512 * 1024 * 1024;
const BAD_INDEX: &str = "installed compatibility metadata index count or shape invalid";

fn page<R: BufRead, W: Write>(
    io: &mut MetadataExchange<R, W>,
    reference: &Value,
    count: u64,
    prefix: &str,
    pending: &mut Vec<(Value, u64, String)>,
    records: &mut BTreeMap<String, Value>,
) -> Result<()> {
    if count == 0
        || prefix.len() > 64
        || reference["expanded_length"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > 65536)
    {
        return Err(BAD_INDEX);
    }
    let value = strict_json::decode(&io.located(reference, 0)?)?;
    let leaf = value["kind"] == "leaf";
    let key = if leaf { "entries" } else { "children" };
    if !fields(&value, &["schema", "kind", "prefix", key])
        || value["schema"] != "guard.pack-index.v1"
        || value["prefix"] != prefix
        || (!leaf && (value["kind"] != "branch" || prefix.len() == 64))
    {
        return Err(BAD_INDEX);
    }
    let rows = value[key].as_array().ok_or(BAD_INDEX)?;
    if rows.is_empty()
        || rows.len() > if leaf { 64 } else { 16 }
        || (leaf && rows.len() as u64 != count)
    {
        return Err(BAD_INDEX);
    }
    let mut previous = "";
    let mut total = 0u64;
    for row in rows {
        let row = row
            .as_array()
            .filter(|row| row.len() == if leaf { 2 } else { 3 })
            .ok_or(BAD_INDEX)?;
        let id = row[0].as_str().ok_or(BAD_INDEX)?;
        if id <= previous {
            return Err(BAD_INDEX);
        }
        previous = id;
        if leaf {
            if id.is_empty()
                || id.len() > 256
                || !id.is_ascii()
                || !hex::encode(Sha256::digest(id.as_bytes())).starts_with(prefix)
                || records.insert(id.to_owned(), row[1].clone()).is_some()
            {
                return Err(BAD_INDEX);
            }
        } else {
            let size = row[1].as_u64().filter(|n| *n > 0).ok_or(BAD_INDEX)?;
            if id.len() != prefix.len() + 1
                || !id.starts_with(prefix)
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err(BAD_INDEX);
            }
            total = total.checked_add(size).ok_or(BAD_INDEX)?;
            if total > count {
                return Err(BAD_INDEX);
            }
            pending.push((row[2].clone(), size, id.to_owned()));
        }
    }
    if !leaf && total != count {
        return Err(BAD_INDEX);
    }
    Ok(())
}

fn read<R: BufRead, W: Write>(io: &mut MetadataExchange<R, W>, input: &Value) -> Result<Value> {
    let family = input["family"]
        .as_str()
        .ok_or("unknown compatibility metadata family")?;
    let (prefix, schema) = match family {
        "commands" => ("command", "guard.extension-contribution.v2"),
        "mcp" => ("mcp", "guard.mcp-server-contribution.v1"),
        _ => return Err("unknown compatibility metadata family"),
    };
    let source = input["source_sha"].as_str().ok_or(INVALID)?;
    let root = root(
        input["data"].as_str().ok_or(INVALID)?,
        source,
        input["engine"].as_str().ok_or(INVALID)?,
    )?;
    let Some(compatibility) = root.get("compatibility") else {
        return Ok(json!({"kind":"compatibility","available":false}));
    };
    let row = &compatibility[family];
    let count = row["count"].as_u64().ok_or(BAD_INDEX)?;
    let mut pending = Vec::new();
    if count > 0 {
        pending.push((row["index"].clone(), count, String::new()));
    }
    let mut records = BTreeMap::new();
    let mut visits = 0usize;
    while let Some((reference, count, prefix)) = pending.pop() {
        visits += 1;
        if visits > 300_000 {
            return Err("installed compatibility metadata index budget exceeded");
        }
        page(io, &reference, count, &prefix, &mut pending, &mut records)?;
    }
    if records.len() as u64 != count {
        return Err(BAD_INDEX);
    }
    let byte_limit = input["max_bytes"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_BYTES as u64)
        .ok_or(INVALID)?;
    let mut expanded = 0u64;
    let pattern =
        regex::Regex::new(&format!(r"\A{prefix}\.[a-z0-9]+(?:[.-][a-z0-9]+)*\z")).unwrap();
    // Validate the whole inventory before publishing any admitted records.
    let mut payloads = Vec::new();
    for (identity, reference) in records {
        expanded = expanded
            .checked_add(reference["expanded_length"].as_u64().ok_or(INVALID)?)
            .ok_or(INVALID)?;
        if expanded > byte_limit {
            return Err("installed compatibility metadata exceeds expanded byte budget");
        }
        let payload = strict_json::decode(&io.located(&reference, 0)?)?;
        if !pattern.is_match(&identity)
            || !payload.is_object()
            || payload["id"] != identity
            || payload["schemaVersion"] != schema
        {
            return Err("installed compatibility metadata identity invalid");
        }
        payloads.push(payload);
    }
    for payload in payloads {
        io.event(&json!({"kind":"compatibility-record","payload":payload}))?;
    }
    Ok(json!({"kind":"compatibility","available":true}))
}

/// Whether this installation advertises an installed bundle. Only genuine
/// legacy absence (no bundle data and both release manifests predating the
/// bundle field) may skip loading; anything else must load and fail closed.
pub(super) fn presence(input: &Value) -> Result<Value> {
    let manifests = input["manifests"].as_array().filter(|rows| rows.len() == 2);
    let (Some(bundle), Some(manifests)) = (input["bundle"].as_bool(), manifests) else {
        return Err(INVALID);
    };
    if !fields(input, &["operation", "bundle", "manifests"]) {
        return Err(INVALID);
    }
    let legacy = |value: &Value, schema: &str| {
        value.is_object() && value["schema"] == schema && value.get("command_pack_bundle").is_none()
    };
    let absent = !bundle
        && (manifests.iter().all(Value::is_null)
            || (legacy(&manifests[0], "hol-guard-native-runtime.v1")
                && legacy(&manifests[1], "hol-guard-native-source-compiler.v2")));
    Ok(json!({"advertised": !absent}))
}

pub(crate) fn stream() -> Result<Value> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut io = MetadataExchange::installed(stdin.lock(), stdout.lock(), String::new(), MAX_BYTES);
    let input = strict_json::decode(&io.line_bytes()?)?;
    let source = input["source_sha"]
        .as_str()
        .filter(|s| hex(&json!(s), 40))
        .ok_or(INVALID)?
        .to_owned();
    let limit = input["max_bytes"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_BYTES as u64)
        .ok_or(INVALID)? as usize;
    io.bind_installed(source, limit);
    read(&mut io, &input)
}

#[cfg(test)]
#[path = "bundle_metadata_compatibility_tests.rs"]
mod tests;
