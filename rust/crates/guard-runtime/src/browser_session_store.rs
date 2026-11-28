//! Browser session model (BP-T040): one row per browser session a harness
//! drives, with the driver identity, the profile mode, the debugging ports a
//! reviewed launch named and the current origin.
//!
//! The tables are owned by the native store; `browser_session_schema.rs`
//! creates them idempotently and checks that the stored objects are exactly
//! the ones it declares, and records no `schema_migrations` row, so it never
//! collides with a version number of the Python migration chain.
//!
//! Every recorded value only tightens what Guard already knows: the profile
//! mode keeps the riskier of the old and new mode, and debugging ports are only
//! added. Nothing here can produce an allow.

use guard_contracts::BrowserProfileModeV1;
use rusqlite::{params, Connection, OptionalExtension};

pub use crate::browser_session_schema::{
    ensure_browser_session_schema, BrowserSessionResult, BrowserSessionStoreError,
};
use crate::browser_session_schema::{in_savepoint, is_digest};

/// A session that has not been seen for this long is dropped.
pub const BROWSER_SESSION_IDLE_SECONDS: i64 = 2 * 60 * 60;
/// Debugging ports kept per session; further ports are ignored.
pub const MAX_DEBUGGING_PORTS_PER_SESSION: usize = 16;
/// Sessions kept per harness session; the least recently seen is dropped.
pub const MAX_SESSIONS_PER_HARNESS_SESSION: i64 = 64;
const MAX_ORIGIN_CHARS: usize = 512;
const RECORD_SAVEPOINT: &str = "browser_session_record";
const PRUNE_SAVEPOINT: &str = "browser_session_prune";

/// One sighting of a browser session by a hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionObservation<'a> {
    pub session_digest: &'a str,
    pub harness: &'a str,
    pub harness_session_digest: &'a str,
    pub driver_identity_hash: &'a str,
    pub profile_mode: BrowserProfileModeV1,
    pub origin: Option<&'a str>,
    pub debugging_port: Option<u16>,
    pub now_unix: i64,
}

/// A stored browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSession {
    pub session_digest: String,
    pub harness: String,
    pub harness_session_digest: String,
    pub driver_identity_hash: String,
    pub profile_mode: BrowserProfileModeV1,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    pub current_origin: Option<String>,
    pub debugging_ports: Vec<u16>,
}

fn is_harness(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_origin(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+-.".contains(&byte)
        })
        && !rest.is_empty()
        && !rest.contains('/')
        && value.chars().count() <= MAX_ORIGIN_CHARS
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn mode_text(mode: BrowserProfileModeV1) -> &'static str {
    match mode {
        BrowserProfileModeV1::Isolated => "isolated",
        BrowserProfileModeV1::Dedicated => "dedicated",
        BrowserProfileModeV1::RemoteDebugging => "remote-debugging",
        BrowserProfileModeV1::Shared => "shared",
        BrowserProfileModeV1::Unknown => "unknown",
    }
}

fn mode_from_text(text: &str) -> BrowserProfileModeV1 {
    match text {
        "isolated" => BrowserProfileModeV1::Isolated,
        "dedicated" => BrowserProfileModeV1::Dedicated,
        "remote-debugging" => BrowserProfileModeV1::RemoteDebugging,
        "shared" => BrowserProfileModeV1::Shared,
        _ => BrowserProfileModeV1::Unknown,
    }
}

/// Riskier modes rank higher; a session never moves to a lower rank.
fn mode_rank(mode: BrowserProfileModeV1) -> u8 {
    match mode {
        BrowserProfileModeV1::Isolated => 0,
        BrowserProfileModeV1::Dedicated => 1,
        BrowserProfileModeV1::Unknown => 2,
        BrowserProfileModeV1::Shared => 3,
        BrowserProfileModeV1::RemoteDebugging => 4,
    }
}

fn validate(observation: &BrowserSessionObservation<'_>) -> BrowserSessionResult<()> {
    let invalid = |reason| Err(BrowserSessionStoreError::Invalid(reason));
    if !is_digest(observation.session_digest) {
        return invalid("session_digest");
    }
    if !is_harness(observation.harness) {
        return invalid("harness");
    }
    if !is_digest(observation.harness_session_digest) {
        return invalid("harness_session_digest");
    }
    if !is_digest(observation.driver_identity_hash) {
        return invalid("driver_identity_hash");
    }
    if observation.origin.is_some_and(|origin| !is_origin(origin)) {
        return invalid("origin");
    }
    if observation.debugging_port == Some(0) {
        return invalid("debugging_port");
    }
    if observation.now_unix <= 0 {
        return invalid("now_unix");
    }
    Ok(())
}

/// Records one sighting. A new session is created; a known session keeps its
/// harness, harness session and driver identity, moves `last_seen` forward,
/// keeps the riskier profile mode, takes the new origin when one is given and
/// adds the debugging port. A sighting that names a different harness session
/// or driver for a known session digest is rejected.
pub fn record_browser_session(
    connection: &Connection,
    observation: &BrowserSessionObservation<'_>,
) -> BrowserSessionResult<()> {
    validate(observation)?;
    in_savepoint(connection, RECORD_SAVEPOINT, || {
        record_in_savepoint(connection, observation)
    })
}

/// The insert claims a new digest atomically, so two concurrent first sightings
/// cannot both take the insert path. The port is added before the trim, so a
/// session trimmed straight away takes its port with it.
fn record_in_savepoint(
    connection: &Connection,
    observation: &BrowserSessionObservation<'_>,
) -> BrowserSessionResult<()> {
    let inserted = connection.execute(
        "insert into guard_browser_sessions (session_digest, harness, \
         harness_session_digest, driver_identity_hash, profile_mode, first_seen_unix, \
         last_seen_unix, current_origin) values (?, ?, ?, ?, ?, ?, ?, ?) \
         on conflict(session_digest) do nothing",
        params![
            observation.session_digest,
            observation.harness,
            observation.harness_session_digest,
            observation.driver_identity_hash,
            mode_text(observation.profile_mode),
            observation.now_unix,
            observation.now_unix,
            observation.origin,
        ],
    )? == 1;
    if !inserted {
        update_known_session(connection, observation)?;
    }
    if let Some(port) = observation.debugging_port {
        add_debugging_port(connection, observation.session_digest, port)?;
    }
    if inserted {
        trim_harness_session(connection, observation)?;
    }
    Ok(())
}

fn update_known_session(
    connection: &Connection,
    observation: &BrowserSessionObservation<'_>,
) -> BrowserSessionResult<()> {
    let (harness, harness_session, driver, mode): (String, String, String, String) = connection
        .query_row(
            "select harness, harness_session_digest, driver_identity_hash, profile_mode \
             from guard_browser_sessions where session_digest = ?",
            [observation.session_digest],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    if harness != observation.harness
        || harness_session != observation.harness_session_digest
        || driver != observation.driver_identity_hash
    {
        return Err(BrowserSessionStoreError::Invalid("session_identity"));
    }
    let stored = mode_from_text(&mode);
    let kept = if mode_rank(observation.profile_mode) > mode_rank(stored) {
        observation.profile_mode
    } else {
        stored
    };
    connection.execute(
        "update guard_browser_sessions set profile_mode = ?, \
         last_seen_unix = max(last_seen_unix, ?), \
         current_origin = coalesce(?, current_origin) where session_digest = ?",
        params![
            mode_text(kept),
            observation.now_unix,
            observation.origin,
            observation.session_digest,
        ],
    )?;
    Ok(())
}

fn add_debugging_port(
    connection: &Connection,
    session_digest: &str,
    port: u16,
) -> BrowserSessionResult<()> {
    let count: i64 = connection.query_row(
        "select count(*) from guard_browser_session_ports where session_digest = ?",
        [session_digest],
        |row| row.get(0),
    )?;
    if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_DEBUGGING_PORTS_PER_SESSION {
        return Ok(());
    }
    connection.execute(
        "insert or ignore into guard_browser_session_ports (session_digest, port) values (?, ?)",
        params![session_digest, i64::from(port)],
    )?;
    Ok(())
}

fn trim_harness_session(
    connection: &Connection,
    observation: &BrowserSessionObservation<'_>,
) -> BrowserSessionResult<()> {
    let doomed: Vec<String> = {
        let mut statement = connection.prepare(
            "select session_digest from guard_browser_sessions \
             where harness = ? and harness_session_digest = ? \
             order by last_seen_unix desc, session_digest limit -1 offset ?",
        )?;
        let rows = statement.query_map(
            params![
                observation.harness,
                observation.harness_session_digest,
                MAX_SESSIONS_PER_HARNESS_SESSION
            ],
            |row| row.get(0),
        )?;
        rows.collect::<Result<_, _>>()?
    };
    for digest in doomed {
        delete_session(connection, &digest)?;
    }
    Ok(())
}

fn delete_session(connection: &Connection, session_digest: &str) -> BrowserSessionResult<()> {
    connection.execute(
        "delete from guard_browser_session_ports where session_digest = ?",
        [session_digest],
    )?;
    connection.execute(
        "delete from guard_browser_sessions where session_digest = ?",
        [session_digest],
    )?;
    Ok(())
}

fn ports_for(connection: &Connection, session_digest: &str) -> BrowserSessionResult<Vec<u16>> {
    let mut statement = connection.prepare(
        "select port from guard_browser_session_ports where session_digest = ? order by port",
    )?;
    let rows = statement.query_map([session_digest], |row| row.get::<_, i64>(0))?;
    let mut ports = Vec::new();
    for port in rows {
        if let Ok(port) = u16::try_from(port?) {
            ports.push(port);
        }
    }
    Ok(ports)
}

fn is_live(last_seen_unix: i64, now_unix: i64) -> bool {
    now_unix.saturating_sub(last_seen_unix) <= BROWSER_SESSION_IDLE_SECONDS
}

/// The session with this digest, unless it has been idle past the bound.
pub fn browser_session(
    connection: &Connection,
    session_digest: &str,
    now_unix: i64,
) -> BrowserSessionResult<Option<BrowserSession>> {
    let row = connection
        .query_row(
            "select session_digest, harness, harness_session_digest, driver_identity_hash, \
             profile_mode, first_seen_unix, last_seen_unix, current_origin \
             from guard_browser_sessions where session_digest = ?",
            [session_digest],
            |row| {
                Ok(BrowserSession {
                    session_digest: row.get(0)?,
                    harness: row.get(1)?,
                    harness_session_digest: row.get(2)?,
                    driver_identity_hash: row.get(3)?,
                    profile_mode: mode_from_text(&row.get::<_, String>(4)?),
                    first_seen_unix: row.get(5)?,
                    last_seen_unix: row.get(6)?,
                    current_origin: row.get(7)?,
                    debugging_ports: Vec::new(),
                })
            },
        )
        .optional()?;
    let Some(mut session) = row.filter(|session| is_live(session.last_seen_unix, now_unix)) else {
        return Ok(None);
    };
    session.debugging_ports = ports_for(connection, &session.session_digest)?;
    Ok(Some(session))
}

/// Debugging ports named by reviewed launches in the live browser sessions of
/// one harness session, ascending and without duplicates.
pub fn known_debugging_ports(
    connection: &Connection,
    harness: &str,
    harness_session_digest: &str,
    now_unix: i64,
) -> BrowserSessionResult<Vec<u16>> {
    let mut statement = connection.prepare(
        "select distinct p.port from guard_browser_session_ports p \
         join guard_browser_sessions s on s.session_digest = p.session_digest \
         where s.harness = ? and s.harness_session_digest = ? and s.last_seen_unix >= ? \
         order by p.port",
    )?;
    let cutoff = now_unix.saturating_sub(BROWSER_SESSION_IDLE_SECONDS);
    let rows = statement.query_map(params![harness, harness_session_digest, cutoff], |row| {
        row.get::<_, i64>(0)
    })?;
    let mut ports = Vec::new();
    for port in rows {
        if let Ok(port) = u16::try_from(port?) {
            ports.push(port);
        }
    }
    Ok(ports)
}

/// Drops every browser session of a harness session that has ended.
pub fn expire_harness_session(
    connection: &Connection,
    harness: &str,
    harness_session_digest: &str,
) -> BrowserSessionResult<usize> {
    connection.execute(
        "delete from guard_browser_session_ports where session_digest in \
         (select session_digest from guard_browser_sessions \
          where harness = ? and harness_session_digest = ?)",
        params![harness, harness_session_digest],
    )?;
    Ok(connection.execute(
        "delete from guard_browser_sessions where harness = ? and harness_session_digest = ?",
        params![harness, harness_session_digest],
    )?)
}

/// Drops every browser session idle past the bound. Both deletes run in one
/// savepoint, so a concurrent refresh cannot keep a session whose ports went.
pub fn prune_idle_browser_sessions(
    connection: &Connection,
    now_unix: i64,
) -> BrowserSessionResult<usize> {
    let cutoff = now_unix.saturating_sub(BROWSER_SESSION_IDLE_SECONDS);
    in_savepoint(connection, PRUNE_SAVEPOINT, || {
        connection.execute(
            "delete from guard_browser_session_ports where session_digest in \
             (select session_digest from guard_browser_sessions where last_seen_unix < ?)",
            [cutoff],
        )?;
        Ok(connection.execute(
            "delete from guard_browser_sessions where last_seen_unix < ?",
            [cutoff],
        )?)
    })
}

#[cfg(test)]
#[path = "browser_session_store_tests.rs"]
mod tests;
