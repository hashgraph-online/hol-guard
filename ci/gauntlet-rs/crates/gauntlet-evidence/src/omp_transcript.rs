//! Bounded, read-only OMP event transcript ingestion. The caller supplies the
//! byte digest from outside the transcript; event authenticity is separate.

use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::{EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const TRANSCRIPT_LIMIT: usize = 16 * 1024 * 1024;
const MAX_EVENTS: usize = 50_000;

fn separator(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\r'
            | '\u{000b}'
            | '\u{000c}'
            | '\u{001c}'
            | '\u{001d}'
            | '\u{001e}'
            | '\u{0085}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Match Python `evidence.read_events` for ordinary UTF-8 NDJSON. Duplicate
/// JSON keys, nonfinite numbers, deep values and more than 50,000 events are
/// additionally refused by Rust. This parser never treats model prose or a
/// producer-supplied success flag as an oracle.
pub fn parse_omp_transcript(raw: &[u8]) -> Result<Vec<Value>> {
    if raw.len() > TRANSCRIPT_LIMIT {
        return Err(EvidenceError::Invalid(
            "OMP transcript exceeds its evidence budget",
        ));
    }
    let decoded = std::str::from_utf8(raw)
        .map_err(|_| EvidenceError::Invalid("OMP transcript is not UTF-8"))?;
    let mut events = Vec::new();
    for line in decoded.split(separator) {
        if line.trim().is_empty() {
            continue;
        }
        if line.trim_start().starts_with('\u{feff}') {
            return Err(EvidenceError::Invalid("malformed OMP event"));
        }
        let canonical = canonicalize(line.as_bytes())
            .map_err(|_| EvidenceError::Invalid("malformed OMP event"))?;
        let event: Value = serde_json::from_slice(&canonical)
            .map_err(|_| EvidenceError::Invalid("malformed OMP event"))?;
        if !event.is_object() || !event.get("type").is_some_and(Value::is_string) {
            return Err(EvidenceError::Invalid("malformed OMP event"));
        }
        events.push(event);
        if events.len() > MAX_EVENTS {
            return Err(EvidenceError::Invalid("too many OMP events"));
        }
    }
    Ok(events)
}

/// Open one outside-pinned `.jsonl` or `.ndjson` transcript through canonical
/// no-symlink ancestry, then verify its exact bytes before parsing.
pub fn read_omp_transcript(path: &Path, expected_sha256: &str) -> Result<Vec<Value>> {
    if !is_sha256(expected_sha256) {
        return Err(EvidenceError::Invalid("OMP transcript SHA-256 pin missing"));
    }
    let parent = path.parent().ok_or(EvidenceError::Invalid(
        "absolute OMP transcript path required",
    ))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(EvidenceError::Invalid("invalid OMP transcript filename"))?;
    if name.len() > 128
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.'))
        || !(name.ends_with(".jsonl") || name.ends_with(".ndjson"))
    {
        return Err(EvidenceError::Invalid("invalid OMP transcript filename"));
    }
    let directory = open_absolute_directory(parent)?;
    let fd = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let before = fstat(&fd).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_size < 0
        || before.st_size as usize > TRANSCRIPT_LIMIT
        || before.st_nlink != 1
    {
        return Err(EvidenceError::Invalid(
            "nonregular or oversized OMP transcript",
        ));
    }
    let mut file = File::from(fd);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take((TRANSCRIPT_LIMIT + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let after = fstat(&file).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if raw.len() != before.st_size as usize
        || raw.len() > TRANSCRIPT_LIMIT
        || after.st_size != before.st_size
        || after.st_ino != before.st_ino
        || after.st_dev != before.st_dev
        || after.st_nlink != 1
    {
        return Err(EvidenceError::Invalid("OMP transcript changed while read"));
    }
    if sha256(&raw) != expected_sha256 {
        return Err(EvidenceError::Invalid("OMP transcript SHA-256 differs"));
    }
    parse_omp_transcript(&raw)
}
