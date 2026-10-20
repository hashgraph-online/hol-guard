//! Strict stored-ZIP admissibility before the Python archive IO adapter runs.
use super::*;
fn u16at(b: &[u8], n: usize) -> Result<usize> {
    Ok(u16::from_le_bytes(
        b.get(n..n + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize)
}
fn u32at(b: &[u8], n: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(
        b.get(n..n + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize)
}
pub(super) fn members(bytes: &[u8]) -> Result<Vec<(String, usize, usize)>> {
    if bytes.len() < 22 || bytes.len() > 32 * 1024 * 1024 {
        return Err(invalid());
    }
    let e = bytes.len() - 22;
    if &bytes[e..e + 4] != b"PK\x05\x06"
        || u16at(bytes, e + 4)? != 0
        || u16at(bytes, e + 6)? != 0
        || u16at(bytes, e + 20)? != 0
    {
        return Err(invalid());
    }
    let count = u16at(bytes, e + 10)?;
    let start = u32at(bytes, e + 16)?;
    if count == 0
        || count > 2048
        || u16at(bytes, e + 8)? != count
        || u32at(bytes, e + 12)? != count * 115
        || start.checked_add(count * 115) != Some(e)
    {
        return Err(invalid());
    }
    let mut result = Vec::new();
    let mut names = BTreeSet::new();
    let mut offset = 0;
    for i in 0..count {
        let c = start + i * 115;
        if bytes.get(c..c + 4) != Some(b"PK\x01\x02")
            || u16at(bytes, c + 8)? != 0
            || u16at(bytes, c + 10)? != 0
            || u16at(bytes, c + 28)? != 69
            || u16at(bytes, c + 30)? != 0
            || u16at(bytes, c + 32)? != 0
            || u16at(bytes, c + 34)? != 0
            || (u32at(bytes, c + 38)? >> 16) & 0o170000 != 0o100000
            || u32at(bytes, c + 42)? != offset
        {
            return Err(invalid());
        }
        let name = std::str::from_utf8(bytes.get(c + 46..c + 115).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let sha = name
            .strip_suffix(".json")
            .filter(|s| hex(s, 64))
            .ok_or_else(invalid)?;
        let size = u32at(bytes, c + 24)?;
        if size == 0
            || size > 65536
            || u32at(bytes, c + 20)? != size
            || !names.insert(sha.to_owned())
            || bytes.get(offset..offset + 4) != Some(b"PK\x03\x04")
            || u16at(bytes, offset + 6)? != 0
            || u16at(bytes, offset + 8)? != 0
            || u32at(bytes, offset + 14)? != u32at(bytes, c + 16)?
            || u32at(bytes, offset + 18)? != size
            || u32at(bytes, offset + 22)? != size
            || u16at(bytes, offset + 26)? != 69
            || u16at(bytes, offset + 28)? != 0
            || bytes.get(offset + 30..offset + 99) != Some(name.as_bytes())
        {
            return Err(invalid());
        }
        let begin = offset + 99;
        let end = begin + size;
        if end > start || hash(bytes.get(begin..end).ok_or_else(invalid)?) != sha {
            return Err(invalid());
        }
        let mut crc = flate2::Crc::new();
        crc.update(&bytes[begin..end]);
        if crc.sum() as usize != u32at(bytes, c + 16)? {
            return Err(invalid());
        }
        result.push((sha.to_owned(), begin, size));
        offset = end;
    }
    if offset != start {
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
