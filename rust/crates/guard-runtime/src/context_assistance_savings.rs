//! Which sessions CIGAR helped, kept so Guard can estimate what it saved
//! without running anything twice.
//!
//! Each time a prompt's answer gets project context, Guard notes the app, the
//! session, the app's own record of that session, how much context it added
//! and which files that context showed. The record lives in the Guard home as
//! `context-savings.json` and leaves this computer never. It keeps at most
//! `MAX_SESSIONS` sessions from the last `KEEP_DAYS` days and `MAX_FILES`
//! files per session; a write that fails changes nothing the prompt sees.
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "context_assistance_savings_read.rs"]
mod read;
#[path = "context_assistance_savings_report.rs"]
pub(crate) mod report;

pub(crate) const FILE_NAME: &str = "context-savings.json";
const SCHEMA: &str = "guard-cigar-savings-journal.v1";
const MAX_SESSIONS: usize = 256;
const MAX_FILES: usize = 64;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_ID_BYTES: usize = 200;
pub(crate) const KEEP_DAYS: u64 = 7;
const DAY_SECS: u64 = 86_400;

/// One session CIGAR added context to.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Helped {
    pub(crate) app: String,
    pub(crate) id: String,
    /// The app's own record of the session, as its hook named it.
    #[serde(default)]
    pub(crate) transcript: Option<String>,
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) prompts: u64,
    /// Characters of context CIGAR added over the session.
    pub(crate) chars: u64,
    /// Project files the context showed, relative to the project.
    #[serde(default)]
    pub(crate) files: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct Journal {
    schema: String,
    #[serde(default)]
    pub(crate) sessions: Vec<Helped>,
}

/// What one prompt's answer added.
pub(crate) struct Added<'a> {
    pub(crate) app: &'a str,
    pub(crate) id: &'a str,
    pub(crate) transcript: Option<&'a str>,
    pub(crate) chars: usize,
    pub(crate) files: Vec<String>,
}

fn lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Reads the record, or an empty one when it is missing or unreadable.
pub(crate) fn load(guard_home: &Path) -> Journal {
    std::fs::read(guard_home.join(FILE_NAME))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Journal>(&bytes).ok())
        .filter(|journal| journal.schema == SCHEMA)
        .unwrap_or_default()
}

/// Notes what one prompt's answer added. Best effort: an empty answer, an
/// unnamed session or a failed write records nothing.
pub(crate) fn record(guard_home: &Path, added: Added<'_>) {
    record_at(guard_home, added, now());
}

/// Notes a prompt from its hook payload. Pi and Oh My Pi can drop added
/// context before the agent sees it, so Guard cannot say it helped them.
pub(crate) fn noted(
    guard_home: &Path,
    payload: &serde_json::Value,
    app: &str,
    chars: usize,
    files: Vec<String>,
) {
    if chars == 0 || matches!(app, "pi" | "omp") {
        return;
    }
    let text = |key: &str| payload.get(key).and_then(serde_json::Value::as_str);
    let Some(id) = text("session_id") else { return };
    let added = Added {
        app,
        id,
        transcript: text("transcript_path"),
        chars,
        files,
    };
    record(guard_home, added);
}

pub(crate) fn record_at(guard_home: &Path, added: Added<'_>, at: u64) {
    let id = added.id.trim();
    if added.chars == 0 || id.is_empty() || id.len() > MAX_ID_BYTES {
        return;
    }
    let Ok(_held) = lock().lock() else { return };
    let mut journal = load(guard_home);
    let cutoff = at.saturating_sub(KEEP_DAYS * DAY_SECS);
    journal.sessions.retain(|session| session.last >= cutoff);
    let index = journal
        .sessions
        .iter()
        .position(|session| session.app == added.app && session.id == id);
    let mut session = index
        .map(|index| journal.sessions.remove(index))
        .unwrap_or_else(|| Helped {
            app: added.app.to_owned(),
            id: id.to_owned(),
            first: at,
            ..Helped::default()
        });
    if let Some(path) = added.transcript.filter(|path| path.len() <= MAX_PATH_BYTES) {
        session.transcript = Some(path.to_owned());
    }
    session.last = at;
    session.prompts += 1;
    session.chars += added.chars as u64;
    for file in added.files {
        let fits = !file.is_empty() && file.len() <= MAX_PATH_BYTES;
        if fits && session.files.len() < MAX_FILES && !session.files.contains(&file) {
            session.files.push(file);
        }
    }
    journal.sessions.push(session);
    let extra = journal.sessions.len().saturating_sub(MAX_SESSIONS);
    journal.sessions.drain(..extra);
    journal.schema = SCHEMA.to_owned();
    let _ = save(guard_home, &journal);
}

fn save(guard_home: &Path, journal: &Journal) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(journal).map_err(std::io::Error::other)?;
    let mut file = tempfile::NamedTempFile::new_in(guard_home)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(guard_home.join(FILE_NAME))
        .map(drop)
        .map_err(|error| error.error)
}

/// Where the app keeps its session records, for checking a hook's
/// `transcript_path` before reading it.
pub(crate) fn record_roots(home: &Path, env: impl Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let mut roots = vec![
        home.join(".codex").join("sessions"),
        home.join(".claude").join("projects"),
    ];
    if let Some(codex) = env("CODEX_HOME").filter(|value| !value.is_empty()) {
        roots.push(PathBuf::from(codex).join("sessions"));
    }
    if let Some(claude) = env("CLAUDE_CONFIG_DIR").filter(|value| !value.is_empty()) {
        roots.push(PathBuf::from(claude).join("projects"));
    }
    roots
}

#[cfg(test)]
#[path = "context_assistance_savings_tests.rs"]
mod tests;
