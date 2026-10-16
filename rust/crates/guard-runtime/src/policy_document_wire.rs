//! Bounded, transient policy-only byte transport. No partial upload evaluates.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::request_context_op::Budget;

const LIMIT: usize = 64 * 1024 * 1024;
const CHUNK: usize = 512 * 1024;
const CACHE_LIMIT: usize = 128 * 1024 * 1024;
const INVALID: &str = "native_policy_document_wire_invalid";

#[cfg(test)]
#[path = "policy_document_wire_tests.rs"]
mod tests;

enum Transfer {
    Upload {
        query: String,
        size: usize,
        digest: String,
        bytes: Vec<u8>,
    },
    Download {
        bytes: Vec<u8>,
        digest: String,
    },
}

struct Entry {
    home: String,
    touched: Instant,
    transfer: Transfer,
}

impl Entry {
    fn size(&self) -> usize {
        match &self.transfer {
            Transfer::Upload { bytes, .. } | Transfer::Download { bytes, .. } => bytes.len(),
        }
    }
}

fn cache() -> &'static Mutex<BTreeMap<String, Entry>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, Entry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn prune(cache: &mut BTreeMap<String, Entry>) {
    cache.retain(|_, entry| entry.touched.elapsed() < Duration::from_secs(60));
}

fn reserve(cache: &BTreeMap<String, Entry>, extra: usize) -> Result<(), &'static str> {
    if cache.len() >= 8
        || cache
            .values()
            .map(Entry::size)
            .sum::<usize>()
            .saturating_add(extra)
            > CACHE_LIMIT
    {
        Err("native_policy_document_wire_capacity")
    } else {
        Ok(())
    }
}

fn new_handle() -> Result<String, &'static str> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "native_policy_document_wire_entropy")?;
    Ok(hex::encode(bytes))
}

fn keys(input: &Value, expected: &[&str]) -> Result<(), &'static str> {
    let object = input.as_object().ok_or(INVALID)?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        Err(INVALID)
    } else {
        Ok(())
    }
}

fn handle(input: &Value) -> Result<&str, &'static str> {
    input["handle"]
        .as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(INVALID)
}

pub(super) fn operation(
    query: &str,
    input: &Value,
    home: &str,
    budget: &Budget,
) -> Result<Value, &'static str> {
    budget.check()?;
    match query {
        "wire_start" => {
            keys(input, &["query", "size", "sha256"])?;
            let query = input["query"]
                .as_str()
                .filter(|q| q.len() <= 32 && !q.starts_with("wire_"))
                .ok_or(INVALID)?;
            let size = input["size"]
                .as_u64()
                .filter(|n| *n <= LIMIT as u64)
                .ok_or(INVALID)? as usize;
            let digest = input["sha256"]
                .as_str()
                .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or(INVALID)?;
            let token = new_handle()?;
            let mut cache = cache().lock().map_err(|_| INVALID)?;
            prune(&mut cache);
            reserve(&cache, size)?;
            cache.insert(
                token.clone(),
                Entry {
                    home: home.into(),
                    touched: Instant::now(),
                    transfer: Transfer::Upload {
                        query: query.into(),
                        size,
                        digest: digest.into(),
                        bytes: Vec::new(),
                    },
                },
            );
            Ok(json!({"wire_upload":{"handle":token,"offset":0}}))
        }
        "wire_append" => {
            keys(input, &["handle", "offset", "bytes"])?;
            let token = handle(input)?;
            let offset = input["offset"].as_u64().ok_or(INVALID)? as usize;
            let encoded = input["bytes"]
                .as_str()
                .filter(|s| s.len() <= CHUNK * 2)
                .ok_or(INVALID)?;
            let chunk = Base64::decode_vec(encoded).map_err(|_| INVALID)?;
            if chunk.is_empty() || chunk.len() > CHUNK {
                return Err(INVALID);
            }
            let mut cache = cache().lock().map_err(|_| INVALID)?;
            prune(&mut cache);
            if cache
                .values()
                .map(Entry::size)
                .sum::<usize>()
                .saturating_add(chunk.len())
                > CACHE_LIMIT
            {
                return Err("native_policy_document_wire_capacity");
            }
            let entry = cache
                .get_mut(token)
                .filter(|entry| entry.home == home)
                .ok_or(INVALID)?;
            let Transfer::Upload { size, bytes, .. } = &mut entry.transfer else {
                return Err(INVALID);
            };
            if offset != bytes.len() || chunk.len() > size.saturating_sub(bytes.len()) {
                return Err(INVALID);
            }
            bytes.extend(chunk);
            entry.touched = Instant::now();
            Ok(json!({"wire_upload":{"handle":token,"offset":bytes.len()}}))
        }
        "wire_finish" => {
            keys(input, &["handle"])?;
            let token = handle(input)?;
            // An expired budget must not consume the finished upload.
            budget.check()?;
            let entry = {
                let mut cache = cache().lock().map_err(|_| INVALID)?;
                prune(&mut cache);
                if cache.get(token).is_none_or(|entry| entry.home != home) {
                    return Err(INVALID);
                }
                cache.remove(token).ok_or(INVALID)?
            };
            let Transfer::Upload {
                query,
                size,
                digest,
                bytes,
            } = entry.transfer
            else {
                return Err(INVALID);
            };
            if bytes.len() != size || hex::encode(Sha256::digest(&bytes)) != digest {
                return Err(INVALID);
            }
            let input: Value = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
            budget.check()?;
            let result =
                guard_command::policy_document::evaluate(&query, &input, budget.deadline())
                    .map_err(|_| "native_request_context_policy_document_unavailable")?;
            result_wire(result, home, budget)
        }
        "wire_read" => {
            keys(input, &["handle", "offset"])?;
            let token = handle(input)?;
            let offset = input["offset"].as_u64().ok_or(INVALID)? as usize;
            let mut cache = cache().lock().map_err(|_| INVALID)?;
            prune(&mut cache);
            let entry = cache
                .get_mut(token)
                .filter(|entry| entry.home == home)
                .ok_or(INVALID)?;
            let Transfer::Download { bytes, digest } = &entry.transfer else {
                return Err(INVALID);
            };
            if offset >= bytes.len() || offset % CHUNK != 0 {
                return Err(INVALID);
            }
            let end = offset.saturating_add(CHUNK).min(bytes.len());
            let result = json!({"wire_download":{"handle":token,"offset":offset,"total":bytes.len(),
                "sha256":digest,"bytes":Base64::encode_string(&bytes[offset..end])}});
            entry.touched = Instant::now();
            if end == bytes.len() {
                cache.remove(token);
            }
            Ok(result)
        }
        _ => Err(INVALID),
    }
}

pub(super) fn result_wire(
    result: Value,
    home: &str,
    budget: &Budget,
) -> Result<Value, &'static str> {
    let bytes = serde_json::to_vec(&result).map_err(|_| INVALID)?;
    if bytes.len() <= CHUNK {
        return Ok(result);
    }
    if bytes.len() > LIMIT {
        return Err("native_policy_document_result_too_large");
    }
    let token = new_handle()?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let response = json!({"wire_download":{"handle":token,"offset":0,"total":bytes.len(),
        "sha256":digest,"bytes":Base64::encode_string(&bytes[..CHUNK])}});
    budget.check()?;
    let mut cache = cache().lock().map_err(|_| INVALID)?;
    prune(&mut cache);
    reserve(&cache, bytes.len())?;
    cache.insert(
        token,
        Entry {
            home: home.into(),
            touched: Instant::now(),
            transfer: Transfer::Download { bytes, digest },
        },
    );
    Ok(response)
}
