//! Model usage per AI tool, read from each tool's own usage record on this
//! computer.
//!
//! Codex writes a `token_usage_record` for every model request into the
//! session rollout, and Claude Code writes `message.usage` on every assistant
//! message in the session transcript. The meter adds those numbers up per
//! local day. It never estimates: a tool whose usage record Guard does not
//! read is listed as unread.
//!
//! Both records are append-only and can reach hundreds of megabytes per
//! session, so the meter remembers how far it read each file (in
//! `context-usage-meter.json` under the Guard home) and later reads only the
//! bytes added since. Only lines carrying a usage, summary or model record are
//! parsed; chat text is never kept.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[path = "context_usage_meter_lines.rs"]
mod lines;
#[path = "context_usage_meter_op.rs"]
mod op;
#[path = "context_usage_meter_summary.rs"]
mod summary;
#[cfg(test)]
#[path = "context_usage_meter_tests.rs"]
mod tests;
#[path = "context_usage_meter_text.rs"]
mod text;

use lines::{claude_line, codex_line, read_lines, Seen};
pub(crate) use op::dispatch;
#[cfg(test)]
use summary::summarize;
pub(crate) use summary::{empty, read};
pub(crate) use text::grouped;

pub(crate) const SCHEMA: &str = "guard-context-usage-meter.v1";
pub(crate) const CACHE_NAME: &str = "context-usage-meter.json";
const CACHE_VERSION: u64 = 1;
pub(crate) const WINDOW_DAYS: i64 = 7;
const RECENT_SESSIONS: usize = 10;
/// Tools Guard protects whose usage it does not read; the meter names them
/// instead of guessing.
pub(crate) const UNREAD: [&str; 5] = ["copilot", "cursor", "gemini", "opencode", "pi"];
const CHUNK: usize = 1 << 24;
/// Claude Code re-logs a message (same id and usage) up to a few hundred
/// lines later after a resume.
const RECENT_IDS: usize = 1_024;
const MAX_DEPTH: usize = 32;
const CODEX: &str = "codex";
const CLAUDE: &str = "claude-code";

/// One day's counts, in the order the dashboard lists them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Counts {
    pub(crate) uncached_input_tokens: u64,
    pub(crate) cached_input_tokens: u64,
    pub(crate) cache_write_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) requests: u64,
    pub(crate) compactions: u64,
}

impl Counts {
    fn add(&mut self, other: &Self) {
        self.uncached_input_tokens += other.uncached_input_tokens;
        self.cached_input_tokens += other.cached_input_tokens;
        self.cache_write_tokens += other.cache_write_tokens;
        self.output_tokens += other.output_tokens;
        self.requests += other.requests;
        self.compactions += other.compactions;
    }
}

/// How far one record was read, and what it said up to there.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Entry {
    #[serde(default)]
    pub(crate) ino: u64,
    #[serde(default)]
    pub(crate) size: u64,
    pub(crate) offset: u64,
    #[serde(default)]
    pub(crate) mtime: f64,
    #[serde(default)]
    pub(crate) session: String,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) folder: Option<String>,
    #[serde(default)]
    pub(crate) ids: Vec<String>,
    pub(crate) days: BTreeMap<String, Counts>,
}

/// Every record read, keyed `harness:path`.
pub(crate) type Files = BTreeMap<String, Entry>;

struct Source {
    harness: &'static str,
    root: PathBuf,
    needles: Regex,
}

impl Source {
    fn wants(&self, name: &str) -> bool {
        name.ends_with(".jsonl") && (self.harness != CODEX || name.starts_with("rollout-"))
    }
}

fn expand(raw: &str, home: &Path) -> PathBuf {
    match raw.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with(['/', '\\']) => home.join(&rest[1..]),
        _ => PathBuf::from(raw),
    }
}

fn sources(home: &Path, env: &impl Fn(&str) -> Option<String>) -> [Source; 2] {
    let root = |name: &str, fallback: &str| {
        env(name)
            .filter(|value| !value.is_empty())
            .map_or_else(|| home.join(fallback), |value| expand(&value, home))
    };
    let needles = |words: &[&str]| {
        let pattern = words
            .iter()
            .map(|word| regex::escape(word))
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&pattern).expect("literal needles")
    };
    [
        Source {
            harness: CODEX,
            root: root("CODEX_HOME", ".codex").join("sessions"),
            needles: needles(&[
                r#""type":"token_usage_record""#,
                r#""type":"compacted""#,
                r#""type":"turn_context""#,
            ]),
        },
        Source {
            harness: CLAUDE,
            root: root("CLAUDE_CONFIG_DIR", ".claude").join("projects"),
            needles: needles(&[r#""type":"assistant""#, r#""subtype":"compact_boundary""#]),
        },
    ]
}

fn session_key(source: &Source, path: &Path) -> String {
    let parts: Vec<String> = path
        .strip_prefix(&source.root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    if source.harness == CLAUDE && parts.len() > 2 {
        // Subagent transcripts live in a folder named after their parent session.
        return format!("{}/{}", parts[0], parts[1]);
    }
    let joined = parts.join("/");
    if let Some(stem) = joined.strip_suffix(".jsonl") {
        return stem.to_owned();
    }
    joined
}

/// Tells a replaced file from one that only grew.
fn identity(meta: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }
    #[cfg(not(unix))]
    {
        meta.created()
            .ok()
            .and_then(|born| born.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
            .unwrap_or(0)
    }
}

fn seconds(time: std::io::Result<std::time::SystemTime>) -> f64 {
    time.ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

fn read_file(source: &Source, path: &Path, known: Option<&Entry>) -> std::io::Result<Entry> {
    let meta = std::fs::metadata(path)?;
    let ino = identity(&meta);
    let mut entry = match known {
        Some(entry) if entry.ino == ino && meta.len() >= entry.offset => entry.clone(),
        _ => Entry {
            ino,
            session: session_key(source, path),
            ..Entry::default()
        },
    };
    entry.size = meta.len();
    entry.mtime = seconds(meta.modified());
    if entry.size == entry.offset {
        return Ok(entry);
    }
    let mut seen = Seen::new(&entry.ids);
    let start = entry.offset;
    let offset = read_lines(path, start, &source.needles, |text| {
        let Ok(Value::Object(record)) = serde_json::from_slice::<Value>(text) else {
            return;
        };
        if source.harness == CODEX {
            codex_line(&mut entry, &record);
        } else {
            claude_line(&mut entry, &mut seen, &record);
        }
    })?;
    entry.offset = offset;
    entry.ids = seen.order.into_iter().collect();
    Ok(entry)
}

fn walk(source: &Source, dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return;
    };
    for item in listing.flatten() {
        let Ok(kind) = item.file_type() else {
            continue;
        };
        let path = item.path();
        if kind.is_dir() {
            if depth < MAX_DEPTH {
                walk(source, &path, depth + 1, found);
            }
        } else if source.wants(&item.file_name().to_string_lossy()) {
            found.push(path);
        }
    }
}

fn load_cache(path: &Path) -> Files {
    let Ok(bytes) = std::fs::read(path) else {
        return Files::new();
    };
    let Ok(Value::Object(data)) = serde_json::from_slice::<Value>(&bytes) else {
        return Files::new();
    };
    if data.get("version").and_then(Value::as_u64) != Some(CACHE_VERSION) {
        return Files::new();
    }
    let Some(Value::Object(files)) = data.get("files") else {
        return Files::new();
    };
    files
        .iter()
        .filter_map(|(key, value)| {
            serde_json::from_value::<Entry>(value.clone())
                .ok()
                .map(|entry| (key.clone(), entry))
        })
        .collect()
}

fn save_cache(path: &Path, files: &Files) {
    let Some(dir) = path.parent() else {
        return;
    };
    let body = serde_json::json!({"version": CACHE_VERSION, "files": files});
    let Ok(bytes) = serde_json::to_vec(&body) else {
        return;
    };
    let _ = std::fs::create_dir_all(dir);
    let Ok(mut temporary) = tempfile::Builder::new()
        .prefix(".context-usage-meter.")
        .tempfile_in(dir)
    else {
        return;
    };
    if temporary.write_all(&bytes).is_ok() {
        let _ = temporary.persist(path);
    }
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> f64 {
    seconds(Ok(std::time::SystemTime::now()))
}

/// Brings the per-file counts up to date for sessions active in the last
/// [`WINDOW_DAYS`] days, and saves them for the next read.
pub(crate) fn scan(
    home: &Path,
    guard_home: &Path,
    env: impl Fn(&str) -> Option<String>,
    now: f64,
) -> Files {
    let cutoff = now - (WINDOW_DAYS * 86_400) as f64;
    let cache_path = guard_home.join(CACHE_NAME);
    let previous = load_cache(&cache_path);
    let mut files = Files::new();
    for source in sources(home, &env) {
        if !source.root.is_dir() {
            continue;
        }
        let mut found = Vec::new();
        walk(&source, &source.root, 0, &mut found);
        for path in found {
            let key = format!("{}:{}", source.harness, path.to_string_lossy());
            let fresh = std::fs::metadata(&path).map(|meta| seconds(meta.modified()));
            let read = match fresh {
                Ok(mtime) if mtime < cutoff => continue,
                Ok(_) => read_file(&source, &path, previous.get(&key)),
                Err(error) => Err(error),
            };
            match read {
                Ok(entry) => {
                    files.insert(key, entry);
                }
                Err(_) => {
                    if let Some(entry) = previous.get(&key) {
                        files.insert(key, entry.clone());
                    }
                }
            }
        }
    }
    save_cache(&cache_path, &files);
    files
}
