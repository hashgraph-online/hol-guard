//! Totals per tool for today and the last week, and the background count
//! that keeps a first read of a large history from holding a request open.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Local, NaiveDate, TimeZone};
use serde_json::{json, Value};

use super::{scan, Counts, Files, RECENT_SESSIONS, SCHEMA, UNREAD, WINDOW_DAYS};

/// How long one count stays fresh before a read starts another.
const MAX_AGE: Duration = Duration::from_secs(30);

struct Session {
    model: Option<String>,
    folder: Option<String>,
    last_active: f64,
    totals: Counts,
}

fn stamp(seconds: f64) -> Value {
    let moment = Local.timestamp_opt(seconds.floor() as i64, 0).single();
    moment.map_or(Value::Null, |moment| {
        Value::from(moment.format("%Y-%m-%dT%H:%M:%S%:z").to_string())
    })
}

fn tools(files: &Files, days: i64, today: NaiveDate, recent: usize) -> Value {
    let first = (today - chrono::Duration::days(days - 1)).to_string();
    let mut sessions: BTreeMap<(String, String), Session> = BTreeMap::new();
    for (key, entry) in files {
        let harness = key
            .split_once(':')
            .map_or(key.as_str(), |(harness, _)| harness);
        let mut counts = Counts::default();
        for (day, bucket) in &entry.days {
            if day.as_str() >= first.as_str() {
                counts.add(bucket);
            }
        }
        if counts.requests == 0 && counts.compactions == 0 {
            continue;
        }
        let session = sessions
            .entry((harness.to_owned(), entry.session.clone()))
            .or_insert(Session {
                model: None,
                folder: None,
                last_active: 0.0,
                totals: Counts::default(),
            });
        session.totals.add(&counts);
        if entry.mtime >= session.last_active {
            session.last_active = entry.mtime;
            let pick = |mine: &Option<String>, known: &Option<String>| {
                mine.clone()
                    .filter(|text| !text.is_empty())
                    .or_else(|| known.clone())
            };
            session.model = pick(&entry.model, &session.model);
            session.folder = pick(&entry.folder, &session.folder);
        }
    }
    let mut tools = Vec::new();
    for source in [super::CODEX, super::CLAUDE] {
        let mut mine: Vec<&Session> = sessions
            .iter()
            .filter(|((harness, _), _)| harness == source)
            .map(|(_, session)| session)
            .collect();
        mine.sort_by(|left, right| right.last_active.total_cmp(&left.last_active));
        let mut totals = Counts::default();
        for session in &mine {
            totals.add(&session.totals);
        }
        let recent: Vec<Value> = mine
            .iter()
            .take(recent)
            .map(|session| {
                json!({
                    "last_active": stamp(session.last_active),
                    "model": session.model,
                    "folder": session.folder,
                    "totals": session.totals,
                })
            })
            .collect();
        tools.push(json!({
            "harness": source,
            "sessions": mine.len(),
            "totals": totals,
            "recent": recent,
        }));
    }
    Value::Array(tools)
}

/// Totals per tool for today and the last [`WINDOW_DAYS`] local days, with
/// the week's latest sessions.
pub(crate) fn summarize(files: &Files, today: NaiveDate) -> Value {
    json!({
        "schema": SCHEMA,
        "state": "ready",
        "window_days": WINDOW_DAYS,
        "today": tools(files, 1, today, 0),
        "week": tools(files, WINDOW_DAYS, today, RECENT_SESSIONS),
        "unread": UNREAD,
    })
}

/// The meter with nothing to show yet: `counting` or `unavailable`.
pub(crate) fn empty(state: &str) -> Value {
    json!({
        "schema": SCHEMA,
        "state": state,
        "window_days": WINDOW_DAYS,
        "today": [],
        "week": [],
        "unread": UNREAD,
    })
}

#[derive(Default)]
struct Meter {
    files: Option<Arc<Files>>,
    read_at: Option<Instant>,
    running: bool,
    /// A failed first count is reported once; the read after that (Try
    /// again) counts afresh.
    failure_unseen: bool,
}

fn meter() -> &'static Mutex<Meter> {
    static METER: std::sync::OnceLock<Mutex<Meter>> = std::sync::OnceLock::new();
    METER.get_or_init(Default::default)
}

fn count(home: PathBuf, guard_home: PathBuf, env: HashMap<String, String>) {
    let counted = std::panic::catch_unwind(|| {
        let now = super::now();
        scan(&home, &guard_home, |name| env.get(name).cloned(), now)
    });
    let Ok(mut held) = meter().lock() else {
        return;
    };
    held.running = false;
    held.read_at = Some(Instant::now());
    match counted {
        Ok(files) => {
            held.files = Some(Arc::new(files));
            held.failure_unseen = false;
        }
        // Any failure counts: a refresh waits MAX_AGE before trying again,
        // a first count waits for Try again.
        Err(_) => held.failure_unseen = true,
    }
}

/// The meter's latest totals, starting a count in the background when they
/// are missing or older than [`MAX_AGE`]. Totals from the last count stay on
/// screen while a newer count runs.
pub(crate) fn read(home: &Path, guard_home: &Path, env: HashMap<String, String>) -> Value {
    let files = {
        let Ok(mut held) = meter().lock() else {
            return empty("unavailable");
        };
        if held.failure_unseen && !held.running {
            held.failure_unseen = false;
            if held.files.is_none() {
                return empty("unavailable");
            }
        }
        let stale = held.files.is_none() || held.read_at.is_none_or(|at| at.elapsed() > MAX_AGE);
        if stale && !held.running {
            let (home, guard_home) = (home.to_path_buf(), guard_home.to_path_buf());
            let started = std::thread::Builder::new()
                .name("guard-usage-meter".to_owned())
                .spawn(move || count(home, guard_home, env));
            held.running = started.is_ok();
        }
        (held.files.clone(), held.running)
    };
    let (Some(files), refreshing) = files else {
        return empty("counting");
    };
    let mut state = summarize(&files, Local::now().date_naive());
    state["refreshing"] = Value::Bool(refreshing);
    state
}
