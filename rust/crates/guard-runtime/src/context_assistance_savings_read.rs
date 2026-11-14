//! Reads an app's own session record to learn what a helped session used and
//! whether the agent opened, anyway, a file CIGAR had already shown it.
//!
//! Only records the app keeps in its usual place are read: the path must be
//! absolute, end in `.jsonl`, hold no `..`, and still sit under one of the
//! roots after links are followed. Results are cached by path, size and
//! change time, so a page refresh reads nothing new.
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

const MAX_LINE_BYTES: usize = 4 << 20;
const MAX_CACHE: usize = 512;
const RECENT_IDS: usize = 1_024;

/// What one session record says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    /// Every token the app sent or got back, cached reads included.
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
    /// Shown files a tool call named afterwards.
    pub(crate) opened: Vec<String>,
}

type Key = (PathBuf, u64, SystemTime, usize);

fn cache() -> &'static Mutex<HashMap<Key, Usage>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<Key, Usage>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The record's real path when it is one Guard may read.
pub(crate) fn allowed(path: &str, roots: &[PathBuf]) -> Option<PathBuf> {
    let raw = Path::new(path);
    let plain = raw.is_absolute()
        && raw.extension().is_some_and(|ext| ext == "jsonl")
        && raw
            .components()
            .all(|part| !matches!(part, Component::ParentDir));
    if !plain || !roots.iter().any(|root| raw.starts_with(root)) {
        return None;
    }
    let real = raw.canonicalize().ok()?;
    let inside = roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| real.starts_with(root));
    (inside && real.is_file()).then_some(real)
}

/// Reads one record, or `None` when it is gone or not allowed.
pub(crate) fn usage(path: &str, roots: &[PathBuf], files: &[String]) -> Option<Usage> {
    let real = allowed(path, roots)?;
    let meta = std::fs::metadata(&real).ok()?;
    let key = (real.clone(), meta.len(), meta.modified().ok()?, files.len());
    if let Some(hit) = cache().lock().ok().and_then(|held| held.get(&key).cloned()) {
        return Some(hit);
    }
    let read = scan(&real, files).ok()?;
    if let Ok(mut held) = cache().lock() {
        if held.len() >= MAX_CACHE {
            held.clear();
        }
        held.insert(key, read.clone());
    }
    Some(read)
}

fn scan(path: &Path, files: &[String]) -> std::io::Result<Usage> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    let mut usage = Usage::default();
    let mut opened = vec![false; files.len()];
    let mut ids: Vec<String> = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        // A last line with no newline is still being written.
        if line.last() != Some(&b'\n') || line.len() > MAX_LINE_BYTES {
            continue;
        }
        let Ok(record) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        line_usage(&record, &mut usage, &mut ids);
        for text in calls(&record) {
            for (index, file) in files.iter().enumerate() {
                opened[index] = opened[index] || names(&text, file);
            }
        }
    }
    usage.opened = files
        .iter()
        .zip(opened)
        .filter(|(_, hit)| *hit)
        .map(|(file, _)| file.clone())
        .collect();
    Ok(usage)
}

fn count(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

fn line_usage(record: &Value, usage: &mut Usage, ids: &mut Vec<String>) {
    let kind = record.get("type").and_then(Value::as_str);
    if kind == Some("token_usage_record") {
        let used = &record["payload"]["usage"];
        // OpenAI counts cached input inside `input_tokens`.
        usage.tokens += count(used.get("input_tokens"))
            + count(used.get("cache_write_input_tokens"))
            + count(used.get("output_tokens"));
        usage.requests += 1;
        return;
    }
    let message = &record["message"];
    let Some(used) = message.get("usage").filter(|_| kind == Some("assistant")) else {
        return;
    };
    // Claude Code writes one line per content block, each with the same usage.
    if let Some(id) = message.get("id").and_then(Value::as_str) {
        if ids.iter().any(|seen| seen == id) {
            return;
        }
        if ids.len() == RECENT_IDS {
            ids.remove(0);
        }
        ids.push(id.to_owned());
    }
    usage.tokens += count(used.get("input_tokens"))
        + count(used.get("cache_read_input_tokens"))
        + count(used.get("cache_creation_input_tokens"))
        + count(used.get("output_tokens"));
    usage.requests += 1;
}

/// The text of each tool call on this line.
fn calls(record: &Value) -> Vec<String> {
    let payload = &record["payload"];
    match payload.get("type").and_then(Value::as_str) {
        Some("function_call") => return text(payload.get("arguments")).into_iter().collect(),
        Some("custom_tool_call") => return text(payload.get("input")).into_iter().collect(),
        _ => {}
    }
    let Some(blocks) = record["message"]["content"].as_array() else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
        .filter_map(|block| text(block.get("input")))
        .collect()
}

fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Whether `text` names `file` as a whole path, not as part of a longer name.
pub(crate) fn names(text: &str, file: &str) -> bool {
    let part = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.');
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(found) = text[from..].find(file) {
        let start = from + found;
        let end = start + file.len();
        let clean_start = start == 0 || !part(bytes[start - 1]);
        let clean_end =
            end == bytes.len() || !part(bytes[end]) || bytes[end] == b'.' && end + 1 == bytes.len();
        if clean_start && clean_end {
            return true;
        }
        from = start + 1;
        while !text.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}
