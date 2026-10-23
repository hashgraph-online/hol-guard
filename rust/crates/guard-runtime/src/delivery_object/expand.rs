//! Expansion of stored delivery objects into the blobs they describe.
//!
//! An object is a `data` object, whose bytes are the blob, or a `concat`
//! object, whose bytes list the parts to join. Every object read is checked
//! against the length and digest its reference declares, and the declared
//! expansion is checked before any child is retained. A located reference also
//! carries where to fetch the object from: an object missing from the cache is
//! reported to the caller, which fetches it and asks again.
use super::{files, location, request, Outcome};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

const OBJECT_BYTES: usize = 64 * 1024;
const BLOB_BYTES: usize = 8 * 1024 * 1024;
const MAX_PARTS: usize = 64;
const MAX_DEPTH: usize = 4;
/// Missing objects reported in one round, so a reply stays small.
const NEED_LIMIT: usize = 256;
const CACHE_OBJECT: &str = "pack cache object type or length invalid";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Objects already in a cache directory, referenced by digest alone.
    Pack,
    /// Objects that may be fetched, referenced with their release location.
    Located,
}

#[derive(Clone, Copy)]
struct Words {
    shape: &'static str,
    bounds: &'static str,
    expansion: &'static str,
    length: &'static str,
    kind: &'static str,
    concat: &'static str,
    part: &'static str,
    schema: &'static str,
}

impl Mode {
    fn keys(self) -> &'static [&'static str] {
        match self {
            Mode::Pack => &["sha256", "length", "expanded_length", "kind"],
            Mode::Located => &["sha256", "length", "expanded_length", "kind", "location"],
        }
    }

    fn words(self) -> Words {
        match self {
            Mode::Pack => Words {
                shape: "invalid pack object reference",
                bounds: "pack object reference bounds invalid",
                expansion: "pack expansion length invalid",
                length: "pack expansion length invalid",
                kind: "pack object kind invalid",
                concat: "pack concat invalid",
                part: "pack expansion length invalid",
                schema: "guard.pack-concat.v1",
            },
            Mode::Located => Words {
                shape: "located delivery reference invalid",
                bounds: "located delivery reference bounds invalid",
                expansion: "located delivery expansion invalid",
                length: "located delivery length invalid",
                kind: "located delivery reference bounds invalid",
                concat: "located delivery concatenation invalid",
                part: "located delivery part invalid",
                schema: "guard.delivery-concat.v2",
            },
        }
    }
}

fn int(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn bounded(value: &Value, most: usize) -> Option<usize> {
    int(value)
        .and_then(|number| usize::try_from(number).ok())
        .filter(|number| (1..=most).contains(number))
}

/// Concatenation objects are written canonically, which also rules out
/// duplicate fields and non-finite numbers.
fn decode(bytes: &[u8]) -> Option<Value> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let canonical = guard_policy_snapshot::canonical_json_bytes(&value).ok()?;
    (bytes == canonical || bytes.strip_suffix(b"\n") == Some(canonical.as_slice())).then_some(value)
}

struct Walk {
    mode: Mode,
    words: Words,
    directory: PathBuf,
    reads: BTreeSet<String>,
    need: Vec<Value>,
}

impl Walk {
    fn halted(&self) -> bool {
        self.need.len() >= NEED_LIMIT
    }

    fn missing(&mut self, sha: &str, length: usize, location: Option<&Value>) {
        if self.need.iter().all(|row| row["sha256"] != sha) {
            self.need
                .push(json!({"sha256": sha, "length": length, "location": location}));
        }
    }

    /// The object's bytes, or None when it is not in the cache yet.
    fn object(
        &mut self,
        sha: &str,
        length: usize,
        location: Option<&Value>,
    ) -> Result<Option<Vec<u8>>, String> {
        let path = self.directory.join(format!("{sha}.json"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.missing(sha, length, location);
                return Ok(None);
            }
            Err(_) => return Err(CACHE_OBJECT.into()),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("pack object must not be a symlink".into())
            }
            Ok(_) => {}
        }
        let bytes = files::read(&path, OBJECT_BYTES)
            .ok()
            .filter(|bytes| !bytes.is_empty())
            .ok_or(CACHE_OBJECT)?;
        self.reads.insert(sha.to_owned());
        if bytes.len() != length || hex::encode(Sha256::digest(&bytes)) != sha {
            return Err("pack object integrity invalid".into());
        }
        Ok(Some(bytes))
    }

    fn blob(&mut self, reference: &Value, depth: usize) -> Result<Option<Vec<u8>>, String> {
        let (mode, words) = (self.mode, self.words);
        let required = mode.keys();
        let map = reference
            .as_object()
            .filter(|map| {
                map.len() == required.len() && required.iter().all(|key| map.contains_key(*key))
            })
            .ok_or(words.shape)?;
        let kind = map["kind"].as_str();
        let sha = map["sha256"]
            .as_str()
            .filter(|sha| location::lower_hex(sha, 64));
        let length = bounded(&map["length"], OBJECT_BYTES);
        let expanded = bounded(&map["expanded_length"], BLOB_BYTES);
        let admitted = match mode {
            Mode::Pack => {
                depth <= MAX_DEPTH && sha.is_some() && length.is_some() && expanded.is_some()
            }
            Mode::Located => {
                sha.is_some() && matches!(kind, Some("data" | "concat")) && length.is_some()
            }
        };
        if !admitted {
            return Err(words.bounds.into());
        }
        if mode == Mode::Located && (depth > MAX_DEPTH || expanded.is_none()) {
            return Err(words.expansion.into());
        }
        let (Some(sha), Some(length), Some(expanded)) = (sha, length, expanded) else {
            return Err(words.bounds.into());
        };
        let place = map.get("location");
        if let Some(place) = place {
            location::check(place, sha, "object")?;
        }
        let Some(bytes) = self.object(sha, length, place)? else {
            return Ok(None);
        };
        match kind {
            Some("data") if bytes.len() == expanded => return Ok(Some(bytes)),
            Some("data") => return Err(words.length.into()),
            Some("concat") => {}
            _ => return Err(words.kind.into()),
        }
        let parts = decode(&bytes)
            .as_ref()
            .and_then(Value::as_object)
            .filter(|map| {
                map.len() == 2 && map.get("schema").and_then(Value::as_str) == Some(words.schema)
            })
            .and_then(|map| map.get("parts"))
            .and_then(Value::as_array)
            .filter(|parts| (1..=MAX_PARTS).contains(&parts.len()))
            .cloned()
            .ok_or(words.concat)?;
        let ceiling = expanded as i128;
        let mut joined = Vec::new();
        let mut total: i128 = 0;
        let mut complete = true;
        for part in &parts {
            let size = part
                .as_object()
                .and_then(|map| map.get("expanded_length"))
                .and_then(int)
                .ok_or(words.part)?;
            total += size;
            // Check the declared expansion before retaining any child data.
            if !(1..=ceiling).contains(&total) {
                return Err(words.expansion.into());
            }
            match self.blob(part, depth + 1)? {
                Some(child) if complete => joined.extend(child),
                Some(_) => {}
                None => complete = false,
            }
            if self.halted() {
                return Ok(None);
            }
        }
        if total != ceiling {
            return Err(words.expansion.into());
        }
        Ok(complete.then_some(joined))
    }
}

pub(super) fn run(input: &Value) -> Outcome {
    let mode = match input["mode"].as_str() {
        Some("pack") => Mode::Pack,
        Some("located") => Mode::Located,
        _ => return Err(request()),
    };
    let directory = input["directory"].as_str().ok_or_else(request)?;
    let depth = match input.get("depth") {
        None => 0,
        Some(depth) => depth
            .as_u64()
            .and_then(|depth| usize::try_from(depth).ok())
            .ok_or_else(request)?,
    };
    let mut walk = Walk {
        mode,
        words: mode.words(),
        directory: Path::new(directory).to_path_buf(),
        reads: BTreeSet::new(),
        need: Vec::new(),
    };
    let data = walk.blob(&input["reference"], depth)?;
    if !walk.need.is_empty() {
        return Ok(json!({"need": walk.need}));
    }
    let data = data.ok_or_else(request)?;
    Ok(json!({"data": STANDARD.encode(data), "reads": walk.reads}))
}

#[cfg(test)]
#[path = "expand_tests.rs"]
mod tests;
