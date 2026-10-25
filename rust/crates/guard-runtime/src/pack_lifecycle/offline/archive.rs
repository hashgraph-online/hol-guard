//! Strict stored-ZIP admissibility before the Python archive IO adapter runs.
use super::*;
use crate::delivery_object::stored_zip as zip;
const ENTRY_BYTES: usize = 115;
const NAME_BYTES: usize = 69;
pub(super) fn members(bytes: &[u8]) -> Result<Vec<(String, usize, usize)>> {
    if bytes.len() < 22 || bytes.len() > 32 * 1024 * 1024 {
        return Err(invalid());
    }
    let end = zip::end(bytes)
        .filter(|end| end.count <= 2048 && end.central == end.count * ENTRY_BYTES)
        .ok_or_else(invalid)?;
    let mut result = Vec::new();
    let mut names = BTreeSet::new();
    let mut offset = 0;
    for i in 0..end.count {
        let entry = zip::entry(bytes, end.start + i * ENTRY_BYTES).ok_or_else(invalid)?;
        let sha = entry
            .name
            .strip_suffix(".json")
            .filter(|s| hex(s, 64))
            .ok_or_else(invalid)?;
        if entry.flags != 0
            || entry.method != 0
            || entry.name.len() != NAME_BYTES
            || entry.extra != 0
            || entry.comment != 0
            || entry.disk != 0
            || !entry.regular()
            || entry.header != offset
            || entry.size == 0
            || entry.size > 65536
            || entry.packed != entry.size
            || !names.insert(sha.to_owned())
        {
            return Err(invalid());
        }
        let range = zip::data(bytes, &entry, end.start).ok_or_else(invalid)?;
        if hash(&bytes[range.clone()]) != sha {
            return Err(invalid());
        }
        result.push((sha.to_owned(), range.start, entry.size));
        offset = range.end;
    }
    if offset != end.start {
        return Err(invalid());
    }
    Ok(result)
}
pub(super) fn admit(input: &Value) -> Result<Value> {
    let bytes = read(
        Path::new(input["path"].as_str().ok_or_else(invalid)?),
        32 * 1024 * 1024,
    )?;
    if input["sha256"] != hash(&bytes) || input["length"].as_u64() != Some(bytes.len() as u64) {
        return Err(invalid());
    }
    let admitted = members(&bytes)?;
    if input["include_data"].as_bool() == Some(true) {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let objects: Vec<_> = admitted
            .iter()
            .map(|(identity, offset, size)| {
                json!([identity, STANDARD.encode(&bytes[*offset..*offset + *size])])
            })
            .collect();
        return Ok(json!({"members":admitted,"objects":objects}));
    }
    Ok(json!({"members":admitted}))
}
