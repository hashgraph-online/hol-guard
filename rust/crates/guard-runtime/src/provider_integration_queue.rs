//! The provider lookup queue (PRD 6.7, BP-T122): how the decision path asks the worker for an
//! answer without waiting on it.
//!
//! The hook runs in its own process and may not call a provider or wait on the worker (BP-T124), so
//! it leaves a request here and decides on the cache it already has. The daemon's scheduler takes
//! the requests and runs the lookups off the decision path; the answer applies from the next action
//! on that subject.
//!
//! The provider tables hold digests only. A lookup has to send the origin itself, so a queued
//! request is kept apart from them, in `pending_provider_lookups`, and is short-lived:
//!
//! - Only a public origin is queued. One `origin_subject` refuses (loopback, private, `.local`,
//!   `.internal`, `.test`, single-label) is never written, so it can never be sent.
//! - The origin is stored in its canonical spelling and checked against the subject digest again
//!   when it is taken.
//! - A request is removed when the scheduler takes it, after [`QUEUED_LOOKUP_TTL_MS`], when its
//!   provider is disconnected and by the provider purge. At most [`MAX_QUEUED_LOOKUPS`] are kept;
//!   the oldest go first.
//! - One request per provider, capability and subject: asking again while one waits adds nothing.

use guard_contracts::{
    provider_id_is_valid, sha256_hex_is_valid, ProviderCapabilityV1, ProviderSubjectV1,
};
use rusqlite::{params, Connection, OptionalExtension};

use crate::provider_integration_routes::origin_subject;
use crate::provider_integration_store::{
    in_write_savepoint, ProviderStoreError, ProviderStoreResult,
};

/// Requests kept at once; the oldest are dropped past this.
pub const MAX_QUEUED_LOOKUPS: i64 = 256;
/// A request older than this is dropped unsent: the action that asked for it is long decided.
pub const QUEUED_LOOKUP_TTL_MS: u64 = 5 * 60 * 1000;

const SCHEMA: &str = "create table if not exists pending_provider_lookups (
    provider_id text not null,
    capability text not null,
    subject_digest text not null,
    origin text not null,
    requested_at_ms integer not null,
    primary key (provider_id, capability, subject_digest)
)";

/// One request taken from the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedLookup {
    pub provider_id: String,
    pub capability: ProviderCapabilityV1,
    pub subject: ProviderSubjectV1,
    /// The canonical public origin `subject` is the digest of.
    pub origin: String,
    pub requested_at_ms: u64,
}

/// Creates the queue table when absent.
pub fn ensure_lookup_queue_schema(connection: &Connection) -> ProviderStoreResult<()> {
    Ok(connection.execute_batch(SCHEMA)?)
}

fn ms(value: u64) -> ProviderStoreResult<i64> {
    i64::try_from(value).map_err(|_| ProviderStoreError::Invalid("time"))
}

/// Asks for a lookup of `origin`. Returns whether a new request was written: `false` for an origin
/// that may not be shared and for a request already waiting.
pub fn request_lookup(
    connection: &Connection,
    provider_id: &str,
    capability: ProviderCapabilityV1,
    origin: &str,
    now_ms: u64,
) -> ProviderStoreResult<bool> {
    if !provider_id_is_valid(provider_id) {
        return Err(ProviderStoreError::Invalid("provider_id"));
    }
    let Some((canonical, subject)) = origin_subject(origin) else {
        return Ok(false);
    };
    let now = ms(now_ms)?;
    in_write_savepoint(connection, || {
        let added = connection.execute(
            "insert or ignore into pending_provider_lookups \
             (provider_id, capability, subject_digest, origin, requested_at_ms) \
             values (?1, ?2, ?3, ?4, ?5)",
            params![
                provider_id,
                capability.as_str(),
                subject.digest,
                canonical,
                now
            ],
        )?;
        connection.execute(
            "delete from pending_provider_lookups where rowid not in \
             (select rowid from pending_provider_lookups \
              order by requested_at_ms desc, rowid desc limit ?1)",
            [MAX_QUEUED_LOOKUPS],
        )?;
        Ok(added == 1)
    })
}

/// Removes and returns up to `limit` requests, oldest first, after dropping expired ones. A row that
/// no longer reads as a public origin with a matching digest is dropped, never returned.
pub fn take_lookups(
    connection: &Connection,
    now_ms: u64,
    limit: usize,
) -> ProviderStoreResult<Vec<QueuedLookup>> {
    let cutoff = ms(now_ms.saturating_sub(QUEUED_LOOKUP_TTL_MS))?;
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    in_write_savepoint(connection, || {
        connection.execute(
            "delete from pending_provider_lookups where requested_at_ms < ?1",
            [cutoff],
        )?;
        let mut statement = connection.prepare(
            "select rowid, provider_id, capability, subject_digest, origin, requested_at_ms \
             from pending_provider_lookups order by requested_at_ms, rowid limit ?1",
        )?;
        let rows: Vec<(i64, String, String, String, String, i64)> = statement
            .query_map([limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        let mut taken = Vec::with_capacity(rows.len());
        for (rowid, provider_id, capability, digest, origin, requested_at_ms) in rows {
            connection.execute(
                "delete from pending_provider_lookups where rowid = ?1",
                [rowid],
            )?;
            if let Some(lookup) =
                checked(provider_id, &capability, &digest, &origin, requested_at_ms)
            {
                taken.push(lookup);
            }
        }
        Ok(taken)
    })
}

fn checked(
    provider_id: String,
    capability: &str,
    digest: &str,
    origin: &str,
    requested_at_ms: i64,
) -> Option<QueuedLookup> {
    let capability: ProviderCapabilityV1 =
        serde_json::from_value(serde_json::Value::String(capability.to_owned())).ok()?;
    let (canonical, subject) = origin_subject(origin)?;
    let matches = provider_id_is_valid(&provider_id)
        && sha256_hex_is_valid(digest)
        && subject.digest == digest
        && canonical == origin;
    matches.then(|| QueuedLookup {
        provider_id,
        capability,
        subject,
        origin: canonical,
        requested_at_ms: u64::try_from(requested_at_ms).unwrap_or(0),
    })
}

/// Drops every request for `provider_id` (disconnect), or every request when `None` (purge). A
/// store with no queue table has nothing to drop.
pub fn forget_queued_lookups(
    connection: &Connection,
    provider_id: Option<&str>,
) -> ProviderStoreResult<usize> {
    let exists = connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = 'pending_provider_lookups'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(0);
    }
    Ok(match provider_id {
        Some(provider_id) => connection.execute(
            "delete from pending_provider_lookups where provider_id = ?1",
            [provider_id],
        )?,
        None => connection.execute("delete from pending_provider_lookups", [])?,
    })
}

#[cfg(test)]
#[path = "provider_integration_queue_tests.rs"]
mod tests;
