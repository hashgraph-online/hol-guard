//! Reading new lines from a usage record and counting the ones that hold a
//! request, a summary or the model in use.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use chrono::{DateTime, Local, NaiveDateTime};
use regex::bytes::Regex;
use serde_json::{Map, Value};

use super::{Counts, Entry, CHUNK, RECENT_IDS};

/// Calls `line` with each complete line at or after `start` that holds a
/// needle, and returns the offset after the last complete line. A final line
/// without a newline is still being written, so reading stops before it.
pub(super) fn read_lines(
    path: &Path,
    start: u64,
    needles: &Regex,
    mut line: impl FnMut(&[u8]),
) -> std::io::Result<u64> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut offset = start;
    let mut pending: Vec<u8> = Vec::new();
    let mut block = vec![0_u8; CHUNK];
    loop {
        let read = file.read(&mut block)?;
        if read == 0 {
            return Ok(offset);
        }
        pending.extend_from_slice(&block[..read]);
        let Some(cut) = pending.iter().rposition(|byte| *byte == b'\n') else {
            continue;
        };
        for text in pending[..cut].split(|byte| *byte == b'\n') {
            if needles.is_match(text) {
                line(text);
            }
        }
        offset += cut as u64 + 1;
        pending.drain(..=cut);
    }
}

fn local_day(stamp: Option<&Value>) -> Option<String> {
    let text = stamp?.as_str().filter(|text| !text.is_empty())?;
    if let Ok(moment) = DateTime::parse_from_rfc3339(text) {
        return Some(moment.with_timezone(&Local).date_naive().to_string());
    }
    NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|moment| moment.date().to_string())
}

fn number(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

fn count(entry: &mut Entry, day: Option<String>, counts: Counts) {
    if let Some(day) = day {
        entry.days.entry(day).or_default().add(&counts);
    }
}

fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn describe(entry: &mut Entry, model: Option<&Value>, cwd: Option<&Value>) {
    if let Some(model) = model
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        entry.model = Some(model.chars().take(80).collect());
    }
    if let Some(cwd) = cwd.and_then(Value::as_str).filter(|text| !text.is_empty()) {
        let name = Path::new(cwd)
            .file_name()
            .map(|name| name.to_string_lossy().chars().take(120).collect::<String>())
            .unwrap_or_default();
        entry.folder = Some(name);
    }
}

pub(super) fn codex_line(entry: &mut Entry, record: &Map<String, Value>) {
    let payload = object(record.get("payload"));
    let field = |name: &str| payload.and_then(|payload| payload.get(name));
    let day = local_day(record.get("timestamp"));
    match record.get("type").and_then(Value::as_str) {
        Some("token_usage_record") => {
            let usage = object(field("usage"));
            let read = |name: &str| number(usage.and_then(|usage| usage.get(name)));
            let (cached, written) = (
                read("cached_input_tokens"),
                read("cache_write_input_tokens"),
            );
            // OpenAI counts cached input inside `input_tokens`.
            let counts = Counts {
                uncached_input_tokens: read("input_tokens")
                    .saturating_sub(cached)
                    .saturating_sub(written),
                cached_input_tokens: cached,
                cache_write_tokens: written,
                output_tokens: read("output_tokens"),
                requests: 1,
                compactions: 0,
            };
            count(entry, day, counts);
        }
        Some("compacted") => count(
            entry,
            day,
            Counts {
                compactions: 1,
                ..Counts::default()
            },
        ),
        Some("turn_context") => {
            let (model, cwd) = (field("model").cloned(), field("cwd").cloned());
            describe(entry, model.as_ref(), cwd.as_ref());
        }
        _ => {}
    }
}

/// Recently counted message ids, so a message logged twice counts once.
pub(super) struct Seen {
    keys: HashSet<String>,
    pub(super) order: VecDeque<String>,
}

impl Seen {
    pub(super) fn new(ids: &[String]) -> Self {
        let order: VecDeque<String> = ids
            .iter()
            .skip(ids.len().saturating_sub(RECENT_IDS))
            .cloned()
            .collect();
        Self {
            keys: order.iter().cloned().collect(),
            order,
        }
    }

    /// Whether `id` is new; a new id is remembered.
    fn first(&mut self, id: &str) -> bool {
        let chars: Vec<char> = id.chars().collect();
        let key: String = chars[chars.len().saturating_sub(16)..].iter().collect();
        if self.keys.contains(&key) {
            return false;
        }
        if self.order.len() == RECENT_IDS {
            if let Some(oldest) = self.order.pop_front() {
                self.keys.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.keys.insert(key);
        true
    }
}

pub(super) fn claude_line(entry: &mut Entry, seen: &mut Seen, record: &Map<String, Value>) {
    let day = local_day(record.get("timestamp"));
    let kind = record.get("type").and_then(Value::as_str);
    if kind == Some("system")
        && record.get("subtype").and_then(Value::as_str) == Some("compact_boundary")
    {
        count(
            entry,
            day,
            Counts {
                compactions: 1,
                ..Counts::default()
            },
        );
        return;
    }
    let Some(message) = object(record.get("message")) else {
        return;
    };
    let Some(usage) = object(message.get("usage")) else {
        return;
    };
    if kind != Some("assistant") {
        return;
    }
    // One response is written as one line per content block, each repeating the same usage.
    if let Some(id) = message.get("id").and_then(Value::as_str) {
        if !seen.first(id) {
            return;
        }
    }
    let model = message
        .get("model")
        .filter(|model| model.as_str() != Some("<synthetic>"));
    describe(entry, model, record.get("cwd"));
    let read = |name: &str| number(usage.get(name));
    // Anthropic reports `input_tokens` without the cached part; cache reads and writes are separate.
    let counts = Counts {
        uncached_input_tokens: read("input_tokens"),
        cached_input_tokens: read("cache_read_input_tokens"),
        cache_write_tokens: read("cache_creation_input_tokens"),
        output_tokens: read("output_tokens"),
        requests: 1,
        compactions: 0,
    };
    count(entry, day, counts);
}
