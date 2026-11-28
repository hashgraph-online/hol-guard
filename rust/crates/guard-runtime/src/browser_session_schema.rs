//! Schema of the native browser store: the session tables (BP-T040) and the
//! per-driver schema ledger (BP-T060).
//!
//! `ensure_browser_session_schema` creates every table idempotently and checks
//! that the stored `guard_browser_*` objects are exactly the ones declared
//! here. It records no `schema_migrations` row, so it can never collide with a
//! version number of the Python migration chain.

use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::browser_driver_ledger as ledger;

const SAVEPOINT: &str = "browser_session_schema";

const SESSION_STATEMENTS: [&str; 4] = [
    "create table if not exists guard_browser_sessions (
        session_digest text primary key,
        harness text not null,
        harness_session_digest text not null,
        driver_identity_hash text not null,
        profile_mode text not null,
        first_seen_unix integer not null,
        last_seen_unix integer not null,
        current_origin text
    )",
    "create index if not exists idx_guard_browser_sessions_harness_session
        on guard_browser_sessions (harness, harness_session_digest, last_seen_unix)",
    "create table if not exists guard_browser_session_ports (
        session_digest text not null
            references guard_browser_sessions (session_digest) on delete cascade,
        port integer not null check (port between 1 and 65535),
        primary key (session_digest, port)
    )",
    "create index if not exists idx_guard_browser_sessions_last_seen
        on guard_browser_sessions (last_seen_unix)",
];

const SESSION_OBJECTS: [(&str, &str); 4] = [
    ("table", "guard_browser_sessions"),
    ("index", "idx_guard_browser_sessions_harness_session"),
    ("table", "guard_browser_session_ports"),
    ("index", "idx_guard_browser_sessions_last_seen"),
];

#[derive(Debug)]
pub enum BrowserSessionStoreError {
    Invalid(&'static str),
    Schema(String),
    Store(rusqlite::Error),
}

impl From<rusqlite::Error> for BrowserSessionStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error)
    }
}

impl std::fmt::Display for BrowserSessionStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "invalid_browser_session:{reason}"),
            Self::Schema(reason) => write!(formatter, "invalid_browser_session_schema:{reason}"),
            Self::Store(error) => write!(formatter, "browser_session_store:{error}"),
        }
    }
}

impl std::error::Error for BrowserSessionStoreError {}

pub type BrowserSessionResult<T> = Result<T, BrowserSessionStoreError>;

fn normalized_sql(statement: &str) -> String {
    statement
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" if not exists", "")
}

fn validate_objects(connection: &Connection) -> BrowserSessionResult<()> {
    let mut statement = connection.prepare(
        "select type, name, sql from sqlite_master \
         where name like 'guard_browser_%' or name like 'idx_guard_browser_%'",
    )?;
    let mut actual: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let name: String = row.get(1)?;
        let sql: Option<String> = row.get(2)?;
        if let Some(sql) = sql {
            actual.insert((kind, name), normalized_sql(&sql));
        }
    }
    let objects = SESSION_OBJECTS.iter().chain(ledger::OBJECTS.iter());
    let statements = SESSION_STATEMENTS.iter().chain(ledger::STATEMENTS.iter());
    if actual.len() != SESSION_OBJECTS.len() + ledger::OBJECTS.len() {
        return Err(BrowserSessionStoreError::Schema("owned_objects".to_owned()));
    }
    for ((kind, name), statement) in objects.zip(statements) {
        let key = (kind.to_string(), name.to_string());
        if actual.get(&key) != Some(&normalized_sql(statement)) {
            return Err(BrowserSessionStoreError::Schema(format!("{kind}:{name}")));
        }
    }
    Ok(())
}

/// Creates the browser session tables when absent and checks that the stored
/// objects match this module exactly. A failed check rolls back and leaves the
/// store as it was.
pub fn ensure_browser_session_schema(connection: &Connection) -> BrowserSessionResult<()> {
    in_savepoint(connection, SAVEPOINT, || {
        SESSION_STATEMENTS
            .iter()
            .chain(ledger::STATEMENTS.iter())
            .try_for_each(|statement| connection.execute_batch(statement))
            .map_err(BrowserSessionStoreError::from)
            .and_then(|()| validate_objects(connection))
    })
}

/// Runs `body` inside a named savepoint. A failed body rolls back. A failed
/// `release` (an outermost release is the commit, which a reader can hold off)
/// also rolls back and removes the savepoint, so the connection never keeps an
/// open write transaction that would swallow later writes; only this
/// operation's savepoint is unwound, so a caller's outer transaction survives.
pub(crate) fn in_savepoint<T>(
    connection: &Connection,
    name: &str,
    body: impl FnOnce() -> BrowserSessionResult<T>,
) -> BrowserSessionResult<T> {
    connection.execute_batch(&format!("savepoint {name}"))?;
    let outcome = body();
    if outcome.is_err() {
        if let Err(error) = connection.execute_batch(&format!("rollback to {name}")) {
            let _ = connection.execute_batch(&format!("release {name}"));
            return Err(error.into());
        }
    }
    if let Err(error) = connection.execute_batch(&format!("release {name}")) {
        let _ = connection.execute_batch(&format!("rollback to {name}"));
        let _ = connection.execute_batch(&format!("release {name}"));
        return Err(error.into());
    }
    outcome
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
