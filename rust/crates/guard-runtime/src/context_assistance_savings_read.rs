//! Reads an app's own session record to learn what a helped session used and
//! whether the agent opened, anyway, a file CIGAR had already shown it.
//!
//! Only records the app keeps in its usual place are read: the path must be
//! absolute, end in `.jsonl`, hold no `..`, and still sit under one of the
//! roots after links are followed. Only lines dated on or after `since`
//! count, and a tool call counts as opening a file only when it came after
//! CIGAR showed that file. Each record is read once: a later read starts
//! where the last one stopped, unless the file was replaced or the question
//! changed. A line longer than `MAX_LINE_BYTES` is skipped without being held.
use super::Shown;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

#[path = "context_assistance_savings_time.rs"]
mod time;

const METER_FILE: &str = "context-usage-meter.json";
const MAX_LINE_BYTES: usize = 4 << 20;
const MAX_CACHE: usize = 512;
const RECENT_IDS: usize = 1_024;

/// What one session record says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    /// Every token the app sent or got back, cached reads included.
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
    /// Shown files a tool call named after they were shown.
    pub(crate) opened: Vec<String>,
    /// A line too long to read was passed over, so a file not seen opened
    /// may still have been opened there.
    pub(crate) skipped: bool,
}

/// How far one record was read, and what it said up to there.
struct Progress {
    identity: Option<u128>,
    offset: u64,
    since: u64,
    files: Vec<Shown>,
    usage: Usage,
    opened: Vec<bool>,
    ids: Vec<String>,
}

type Cache = Mutex<HashMap<PathBuf, Progress>>;

fn cache() -> &'static Cache {
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Tells a replaced file from one that only grew.
fn identity(meta: &std::fs::Metadata) -> Option<u128> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((u128::from(meta.dev()) << 64) | u128::from(meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let born = meta.created().ok()?;
        born.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|elapsed| elapsed.as_nanos())
    }
}

/// Records Guard's usage meter already found. The meter runs where the
/// user's own settings (such as `CODEX_HOME`) are known; Guard's background
/// service may start without them. Each listed record counts as its own root.
pub(crate) fn metered(guard_home: &Path) -> Vec<PathBuf> {
    let Ok(bytes) = std::fs::read(guard_home.join(METER_FILE)) else {
        return Vec::new();
    };
    let Ok(meter) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    let Some(files) = meter.get("files").and_then(Value::as_object) else {
        return Vec::new();
    };
    files
        .keys()
        .filter_map(|key| key.split_once(':').map(|(_, path)| path))
        .filter(|path| Path::new(path).is_absolute())
        .take(MAX_CACHE)
        .map(PathBuf::from)
        .collect()
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

/// Whether a read of `known` answers the question for `files`. Only the path
/// and when a file was first shown change what a read finds; the last time
/// it was shown does not, so showing a file again keeps the read going.
pub(super) fn same_files(known: &[Shown], files: &[Shown]) -> bool {
    known.len() == files.len()
        && known
            .iter()
            .zip(files)
            .all(|(known, file)| known.path == file.path && known.at == file.at)
}

/// Reads one record, or `None` when it is gone or not allowed.
pub(crate) fn usage(path: &str, roots: &[PathBuf], since: u64, files: &[Shown]) -> Option<Usage> {
    let real = allowed(path, roots)?;
    let meta = std::fs::metadata(&real).ok()?;
    let mut held = cache().lock().ok()?;
    let reusable = held.get(&real).is_some_and(|known| {
        known.identity == identity(&meta)
            && known.offset <= meta.len()
            && known.since == since
            && same_files(&known.files, files)
    });
    if !reusable {
        if held.len() >= MAX_CACHE {
            held.clear();
        }
        let fresh = Progress {
            identity: identity(&meta),
            offset: 0,
            since,
            files: files.to_vec(),
            usage: Usage::default(),
            opened: vec![false; files.len()],
            ids: Vec::new(),
        };
        held.insert(real.clone(), fresh);
    }
    let progress = held.get_mut(&real)?;
    if scan(&real, progress).is_err() {
        held.remove(&real);
        return None;
    }
    let mut usage = progress.usage.clone();
    usage.opened = progress
        .files
        .iter()
        .zip(&progress.opened)
        .filter(|(_, hit)| **hit)
        .map(|(file, _)| file.path.clone())
        .collect();
    Some(usage)
}

/// Reads the next line into `line`. Returns the bytes it passed over and
/// whether `line` holds one whole line worth reading; `None` at the end.
/// Passing over nothing means the rest is a line still being written.
fn next_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> std::io::Result<Option<(u64, bool)>> {
    line.clear();
    let limit = MAX_LINE_BYTES as u64 + 1;
    let read = reader.by_ref().take(limit).read_until(b'\n', line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        return Ok(Some((read as u64, true)));
    }
    if line.len() <= MAX_LINE_BYTES {
        return Ok(Some((0, false)));
    }
    let mut passed = read as u64;
    line.clear();
    line.shrink_to(MAX_LINE_BYTES);
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(Some((0, false)));
        }
        let (used, done) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(end) => (end + 1, true),
            None => (buffer.len(), false),
        };
        reader.consume(used);
        passed += used as u64;
        if done {
            return Ok(Some((passed, false)));
        }
    }
}

fn scan(path: &Path, progress: &mut Progress) -> std::io::Result<()> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(progress.offset))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    while let Some((passed, whole)) = next_line(&mut reader, &mut line)? {
        if passed == 0 {
            break;
        }
        progress.offset += passed;
        progress.usage.skipped |= !whole;
        let parsed = whole.then(|| serde_json::from_slice::<Value>(&line).ok());
        let Some(record) = parsed.flatten() else {
            continue;
        };
        // An undated line counts: leaving it out could only flatter CIGAR.
        let when = record
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(time::parse);
        if when.is_some_and(|when| when < progress.since) {
            continue;
        }
        line_usage(&record, &mut progress.usage, &mut progress.ids);
        for text in calls(&record) {
            for (index, file) in progress.files.iter().enumerate() {
                let after = when.is_none_or(|when| when >= file.at);
                progress.opened[index] |= after && names(&text, &file.path);
            }
        }
    }
    Ok(())
}

fn count(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

fn line_usage(record: &Value, usage: &mut Usage, ids: &mut Vec<String>) {
    let kind = record.get("type").and_then(Value::as_str);
    if kind == Some("token_usage_record") {
        let used = &record["payload"]["usage"];
        // OpenAI counts cached reads and cache writes inside `input_tokens`.
        usage.tokens += count(used.get("input_tokens")) + count(used.get("output_tokens"));
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
