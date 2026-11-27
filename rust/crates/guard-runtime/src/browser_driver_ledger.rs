//! Driver identity hash and the per-driver schema ledger (BP-T060).
//!
//! A site grant covers the routine actions of one browser driver, whichever of
//! its profiled tools performs them. The driver is named by its identity:
//! the driver profile id and digest, the MCP server name and the server's
//! `server_identity_hash`. The ledger keyed by that identity records the
//! `schema_hash` of every profiled tool the driver has been seen with, and a
//! schema epoch. `driver_identity_hash` digests the identity and the epoch,
//! and every browser grant is filed under it.
//!
//! What ends a grant, never re-hashes it:
//!
//! * a changed profile id or digest, server name or server identity is another
//!   identity, so it has its own ledger and its own hash;
//! * a changed schema hash for a tool the ledger already holds bumps the epoch;
//! * a new tool when the ledger is full bumps the epoch and starts the ledger
//!   again rather than silently evicting an older tool.
//!
//! A grant filed under the old hash then matches no call. Grant rows are
//! signed policy decisions, so they are not deleted here; they run out at their
//! expiry. A new profiled tool joins the ledger without ending anything.
//!
//! Two limits are deliberate. A tool the driver profile does not map is never
//! covered by a grant. A call with no schema hash never writes to the ledger
//! and never counts as seen: it may use a grant only through the identity
//! match itself, so a schema change on such a call goes unnoticed until a call
//! of that tool carries a schema hash.

use rusqlite::{params, Connection, OptionalExtension};

use crate::browser_session_schema::{
    in_savepoint, is_digest, BrowserSessionResult, BrowserSessionStoreError,
};

/// Tools kept per driver identity. A further tool ends the driver's grants.
pub const MAX_TOOLS_PER_DRIVER: i64 = 256;
const MAX_NAME_CHARS: usize = 256;
const SAVEPOINT: &str = "browser_driver_ledger";
const KEY_DOMAIN: &str = "hol-guard.browser-driver-key.v1";
const HASH_DOMAIN: &str = "hol-guard.browser-driver-identity.v1";

pub(crate) const STATEMENTS: [&str; 2] = [
    "create table if not exists guard_browser_driver_ledgers (
        driver_key text primary key,
        schema_epoch integer not null check (schema_epoch >= 0)
    )",
    "create table if not exists guard_browser_driver_tools (
        driver_key text not null
            references guard_browser_driver_ledgers (driver_key) on delete cascade,
        tool_name text not null,
        schema_hash text not null,
        primary key (driver_key, tool_name)
    )",
];

pub(crate) const OBJECTS: [(&str, &str); 2] = [
    ("table", "guard_browser_driver_ledgers"),
    ("table", "guard_browser_driver_tools"),
];

/// Everything a driver identity is made of except the schema epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverIdentity<'a> {
    pub profile_id: &'a str,
    pub profile_digest: &'a str,
    pub mcp_server_name: &'a str,
    pub server_identity_hash: &'a str,
}

/// One tool call of a driver as the hook saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverToolCall<'a> {
    pub tool_name: &'a str,
    /// Whether the driver profile maps this tool.
    pub profiled: bool,
    pub schema_hash: Option<&'a str>,
}

/// Which grants may cover a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverGrantScope {
    /// Grants filed under this hash may cover the call.
    Covered {
        driver_identity_hash: String,
        /// The hash this call retired, when it ended the driver's grants.
        ended: Option<String>,
    },
    /// The call carried no schema hash. Grants under this hash may cover it
    /// through the identity match alone; the ledger is unchanged.
    IdentityOnly { driver_identity_hash: String },
    /// The profile does not map the tool: no grant covers it.
    Unprofiled,
}

fn bounded_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_CHARS
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate(identity: &DriverIdentity<'_>) -> BrowserSessionResult<()> {
    let checks = [
        (bounded_name(identity.profile_id), "profile_id"),
        (is_digest(identity.profile_digest), "profile_digest"),
        (bounded_name(identity.mcp_server_name), "mcp_server_name"),
        (
            bounded_name(identity.server_identity_hash),
            "server_identity_hash",
        ),
    ];
    match checks.into_iter().find(|(ok, _)| !ok) {
        Some((_, field)) => Err(BrowserSessionStoreError::Invalid(field)),
        None => Ok(()),
    }
}

/// Length-prefixed parts, so no two different part lists digest alike.
fn digest_parts(domain: &str, parts: &[&str]) -> String {
    let mut bytes = Vec::new();
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    guard_policy_snapshot::digest_bytes(&bytes)
}

/// The ledger key: the identity without its epoch.
pub fn driver_key(identity: &DriverIdentity<'_>) -> BrowserSessionResult<String> {
    validate(identity)?;
    Ok(digest_parts(
        KEY_DOMAIN,
        &[
            identity.profile_id,
            identity.profile_digest,
            identity.mcp_server_name,
            identity.server_identity_hash,
        ],
    ))
}

/// The hash every browser grant of this driver is filed under.
pub fn driver_identity_hash(driver_key: &str, schema_epoch: i64) -> String {
    digest_parts(HASH_DOMAIN, &[driver_key, &schema_epoch.to_string()])
}

/// The epoch of `driver_key`, `0` for a driver with no ledger yet.
fn epoch(connection: &Connection, driver_key: &str) -> BrowserSessionResult<i64> {
    Ok(connection
        .query_row(
            "select schema_epoch from guard_browser_driver_ledgers where driver_key = ?1",
            params![driver_key],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// Bumps the epoch of `driver_key` and returns the hash it retired.
fn end_grants(
    connection: &Connection,
    driver_key: &str,
    from: i64,
) -> BrowserSessionResult<String> {
    let next = from
        .checked_add(1)
        .ok_or(BrowserSessionStoreError::Invalid("schema_epoch"))?;
    connection.execute(
        "update guard_browser_driver_ledgers set schema_epoch = ?2 where driver_key = ?1",
        params![driver_key, next],
    )?;
    Ok(driver_identity_hash(driver_key, from))
}

/// Records `call` in the ledger of `identity` and answers which grants may
/// cover it. Only a profiled call with a schema hash writes.
pub fn observe_driver_tool(
    connection: &Connection,
    identity: &DriverIdentity<'_>,
    call: &DriverToolCall<'_>,
) -> BrowserSessionResult<DriverGrantScope> {
    let key = driver_key(identity)?;
    if !bounded_name(call.tool_name) {
        return Err(BrowserSessionStoreError::Invalid("tool_name"));
    }
    if !call.profiled {
        return Ok(DriverGrantScope::Unprofiled);
    }
    let Some(schema_hash) = call.schema_hash else {
        let driver_identity_hash = driver_identity_hash(&key, epoch(connection, &key)?);
        return Ok(DriverGrantScope::IdentityOnly {
            driver_identity_hash,
        });
    };
    if !is_digest(schema_hash) {
        return Err(BrowserSessionStoreError::Invalid("schema_hash"));
    }
    in_savepoint(connection, SAVEPOINT, || {
        record(connection, &key, call.tool_name, schema_hash)
    })
}

fn record(
    connection: &Connection,
    key: &str,
    tool_name: &str,
    schema_hash: &str,
) -> BrowserSessionResult<DriverGrantScope> {
    connection.execute(
        "insert into guard_browser_driver_ledgers (driver_key, schema_epoch) values (?1, 0) \
         on conflict (driver_key) do nothing",
        params![key],
    )?;
    let current = epoch(connection, key)?;
    let seen: Option<String> = connection
        .query_row(
            "select schema_hash from guard_browser_driver_tools \
             where driver_key = ?1 and tool_name = ?2",
            params![key, tool_name],
            |row| row.get(0),
        )
        .optional()?;
    let ended = match seen {
        Some(seen) if seen == schema_hash => None,
        Some(_) => {
            connection.execute(
                "update guard_browser_driver_tools set schema_hash = ?3 \
                 where driver_key = ?1 and tool_name = ?2",
                params![key, tool_name, schema_hash],
            )?;
            Some(end_grants(connection, key, current)?)
        }
        None => {
            let tools: i64 = connection.query_row(
                "select count(*) from guard_browser_driver_tools where driver_key = ?1",
                params![key],
                |row| row.get(0),
            )?;
            // A full ledger starts again and ends the grants, so no tool's
            // schema ever stops being watched while a grant still stands.
            let ended = if tools >= MAX_TOOLS_PER_DRIVER {
                connection.execute(
                    "delete from guard_browser_driver_tools where driver_key = ?1",
                    params![key],
                )?;
                Some(end_grants(connection, key, current)?)
            } else {
                None
            };
            connection.execute(
                "insert into guard_browser_driver_tools (driver_key, tool_name, schema_hash) \
                 values (?1, ?2, ?3)",
                params![key, tool_name, schema_hash],
            )?;
            ended
        }
    };
    Ok(DriverGrantScope::Covered {
        driver_identity_hash: driver_identity_hash(key, epoch(connection, key)?),
        ended,
    })
}

#[cfg(test)]
#[path = "browser_driver_ledger_tests.rs"]
mod tests;
