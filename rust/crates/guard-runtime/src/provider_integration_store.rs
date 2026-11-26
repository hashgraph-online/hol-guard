//! Provider integration store (BP-T121, PRD 6.7): one row per connected provider, its per-capability
//! settings, and the `provider_signals` cache keyed by `(provider_id, capability, subject_digest)`.
//!
//! The tables are owned by the native store. `ensure_provider_integration_schema` creates them
//! idempotently and checks that the stored objects are exactly the ones below. It records no
//! `schema_migrations` row, so it can never collide with a version number of the Python migration
//! chain.
//!
//! What a row may hold:
//!
//! - Provider ids, capability names, reason codes and enum states, each checked against the contract
//!   before it is written and again when it is read.
//! - Subjects as lowercase SHA-256 digests only. A URL, path, page text or argument value is never
//!   stored; the shape checks reject anything that is not a digest.
//! - No key. The API key lives in the encrypted secret store (BP-T120).
//!
//! A stored row that no longer passes the contract checks is a store error, never a missing signal,
//! so a damaged `danger` row cannot quietly turn into "no provider said anything".

use std::collections::BTreeMap;

use guard_contracts::{
    provider_id_is_valid, provider_reason_code_is_valid, sha256_hex_is_valid, ProviderCapabilityV1,
    ProviderConnectionStateV1, ProviderEffectLevelV1, ProviderShareableFactV1, ProviderSignalV1,
    ProviderSubjectV1, PROVIDER_SIGNAL_V1_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{de::DeserializeOwned, Serialize};

/// Signals kept per provider; the oldest observed are dropped past this.
pub const MAX_SIGNALS_PER_PROVIDER: i64 = 4_096;
/// Expired signals are kept this long so the card can still say "checked 3 min ago, stale".
pub const EXPIRED_SIGNAL_GRACE_MS: u64 = 60 * 60 * 1000;
const SAVEPOINT: &str = "provider_integration_schema";
const WRITE_SAVEPOINT: &str = "provider_integration_write";

const STATEMENTS: [&str; 5] = [
    "create table if not exists provider_connections (
        provider_id text primary key,
        manifest_digest text not null,
        state text not null,
        opt_in_facts text not null,
        connected_at_ms integer not null,
        updated_at_ms integer not null,
        last_verified_at_ms integer
    )",
    "create table if not exists provider_capability_settings (
        provider_id text not null
            references provider_connections (provider_id) on delete cascade,
        capability text not null,
        effect_level text not null,
        require_fresh integer not null check (require_fresh in (0, 1)),
        primary key (provider_id, capability)
    )",
    "create table if not exists provider_signals (
        provider_id text not null,
        capability text not null,
        subject_digest text not null,
        subject_kind text not null,
        revision integer not null check (revision >= 1),
        verdict text not null,
        reason_codes text not null,
        inventory text not null,
        state text not null,
        observed_at_ms integer not null,
        expires_at_ms integer not null,
        primary key (provider_id, capability, subject_digest)
    )",
    "create index if not exists idx_provider_signals_subject
        on provider_signals (capability, subject_digest)",
    "create index if not exists idx_provider_signals_expires
        on provider_signals (expires_at_ms)",
];

const OBJECTS: [(&str, &str); 5] = [
    ("table", "provider_connections"),
    ("table", "provider_capability_settings"),
    ("table", "provider_signals"),
    ("index", "idx_provider_signals_subject"),
    ("index", "idx_provider_signals_expires"),
];

#[derive(Debug)]
pub enum ProviderStoreError {
    /// A value failed the contract checks before it was written.
    Invalid(&'static str),
    /// The stored objects or a stored row do not match this module.
    Schema(String),
    Store(rusqlite::Error),
}

impl From<rusqlite::Error> for ProviderStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error)
    }
}

impl std::fmt::Display for ProviderStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "invalid_provider_integration:{reason}"),
            Self::Schema(reason) => {
                write!(formatter, "invalid_provider_integration_schema:{reason}")
            }
            Self::Store(error) => write!(formatter, "provider_integration_store:{error}"),
        }
    }
}

impl std::error::Error for ProviderStoreError {}

pub type ProviderStoreResult<T> = Result<T, ProviderStoreError>;

/// A connected provider. Absence of a row is `not_connected`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConnection {
    pub provider_id: String,
    /// SHA-256 of the compiled manifest the user connected, so a changed manifest is noticed.
    pub manifest_digest: String,
    pub state: ProviderConnectionStateV1,
    /// Facts the user turned on at connect that are off by default (`target.path_prefix`).
    pub opt_in_facts: Vec<ProviderShareableFactV1>,
    pub connected_at_ms: u64,
    pub updated_at_ms: u64,
    pub last_verified_at_ms: Option<u64>,
}

/// Per-capability settings. A capability with no row uses [`CapabilitySetting::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySetting {
    pub effect_level: ProviderEffectLevelV1,
    pub require_fresh: bool,
}

/// A cached signal and the revision the store gave it. The revision goes up each time the provider's
/// verdict or reason codes for the subject change, so "one review per subject per signal version"
/// (BP-T176) counts real changes, not refreshes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSignal {
    pub signal: ProviderSignalV1,
    pub revision: u32,
}

fn normalized_sql(statement: &str) -> String {
    statement
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" if not exists", "")
}

fn validate_objects(connection: &Connection) -> ProviderStoreResult<()> {
    let mut statement = connection.prepare(
        "select type, name, sql from sqlite_master \
         where name like 'provider\\_%' escape '\\' \
            or name like 'idx\\_provider\\_%' escape '\\'",
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
    if actual.len() != OBJECTS.len() {
        return Err(ProviderStoreError::Schema("owned_objects".to_owned()));
    }
    for ((kind, name), statement) in OBJECTS.iter().zip(STATEMENTS.iter()) {
        let key = (kind.to_string(), name.to_string());
        if actual.get(&key) != Some(&normalized_sql(statement)) {
            return Err(ProviderStoreError::Schema(format!("{kind}:{name}")));
        }
    }
    Ok(())
}

/// Creates the provider tables when absent and checks that the stored objects match this module
/// exactly. A failed check rolls back and leaves the store as it was.
pub fn ensure_provider_integration_schema(connection: &Connection) -> ProviderStoreResult<()> {
    in_savepoint(connection, SAVEPOINT, || {
        STATEMENTS
            .iter()
            .try_for_each(|statement| connection.execute_batch(statement))
            .map_err(ProviderStoreError::from)
            .and_then(|()| validate_objects(connection))
    })
}

/// Runs `body` inside a named savepoint. A failed body rolls back; a failed release also rolls back
/// and removes the savepoint, so the connection never keeps an open write transaction.
fn in_savepoint<T>(
    connection: &Connection,
    name: &str,
    body: impl FnOnce() -> ProviderStoreResult<T>,
) -> ProviderStoreResult<T> {
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

/// The serde name of a contract enum, which is the text stored for it.
fn enum_text<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        _ => String::new(),
    }
}

fn enum_from<T: DeserializeOwned>(text: &str, column: &str) -> ProviderStoreResult<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| ProviderStoreError::Schema(format!("row:{column}")))
}

fn ms_to_sql(value: u64) -> ProviderStoreResult<i64> {
    i64::try_from(value).map_err(|_| ProviderStoreError::Invalid("time"))
}

fn ms_from_sql(value: i64, column: &str) -> ProviderStoreResult<u64> {
    u64::try_from(value).map_err(|_| ProviderStoreError::Schema(format!("row:{column}")))
}

fn join_codes(codes: &[String]) -> String {
    codes.join(",")
}

fn split_list(text: &str) -> impl Iterator<Item = &str> {
    text.split(',').filter(|part| !part.is_empty())
}

fn check_connection(connection: &ProviderConnection) -> ProviderStoreResult<()> {
    if !provider_id_is_valid(&connection.provider_id) {
        return Err(ProviderStoreError::Invalid("provider_id"));
    }
    if !sha256_hex_is_valid(&connection.manifest_digest) {
        return Err(ProviderStoreError::Invalid("manifest_digest"));
    }
    if connection.state == ProviderConnectionStateV1::NotConnected {
        return Err(ProviderStoreError::Invalid("state"));
    }
    if connection
        .opt_in_facts
        .iter()
        .any(|fact| !fact.opt_in_only())
    {
        return Err(ProviderStoreError::Invalid("opt_in_facts"));
    }
    Ok(())
}

/// Writes or replaces a connection row. Settings and cached signals are kept.
pub fn put_connection(
    connection: &Connection,
    record: &ProviderConnection,
) -> ProviderStoreResult<()> {
    check_connection(record)?;
    let facts = record
        .opt_in_facts
        .iter()
        .map(enum_text)
        .collect::<Vec<_>>()
        .join(",");
    connection.execute(
        "insert into provider_connections (provider_id, manifest_digest, state, opt_in_facts, \
             connected_at_ms, updated_at_ms, last_verified_at_ms) \
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         on conflict (provider_id) do update set manifest_digest = excluded.manifest_digest, \
             state = excluded.state, opt_in_facts = excluded.opt_in_facts, \
             updated_at_ms = excluded.updated_at_ms, \
             last_verified_at_ms = excluded.last_verified_at_ms",
        params![
            record.provider_id,
            record.manifest_digest,
            enum_text(&record.state),
            facts,
            ms_to_sql(record.connected_at_ms)?,
            ms_to_sql(record.updated_at_ms)?,
            record.last_verified_at_ms.map(ms_to_sql).transpose()?,
        ],
    )?;
    Ok(())
}

/// Moves a connected provider to a new state, for example `key_invalid` after a `401`. Returns
/// whether a row changed.
pub fn set_connection_state(
    connection: &Connection,
    provider_id: &str,
    state: ProviderConnectionStateV1,
    now_ms: u64,
) -> ProviderStoreResult<bool> {
    if state == ProviderConnectionStateV1::NotConnected {
        return Err(ProviderStoreError::Invalid("state"));
    }
    Ok(connection.execute(
        "update provider_connections set state = ?2, updated_at_ms = ?3 where provider_id = ?1",
        params![provider_id, enum_text(&state), ms_to_sql(now_ms)?],
    )? == 1)
}

fn connection_from_row(row: &Row<'_>) -> ProviderStoreResult<ProviderConnection> {
    let provider_id: String = row.get(0)?;
    let manifest_digest: String = row.get(1)?;
    let state: ProviderConnectionStateV1 = enum_from(&row.get::<_, String>(2)?, "state")?;
    let facts: String = row.get(3)?;
    let record = ProviderConnection {
        provider_id,
        manifest_digest,
        state,
        opt_in_facts: split_list(&facts)
            .map(|fact| enum_from(fact, "opt_in_facts"))
            .collect::<ProviderStoreResult<_>>()?,
        connected_at_ms: ms_from_sql(row.get(4)?, "connected_at_ms")?,
        updated_at_ms: ms_from_sql(row.get(5)?, "updated_at_ms")?,
        last_verified_at_ms: row
            .get::<_, Option<i64>>(6)?
            .map(|value| ms_from_sql(value, "last_verified_at_ms"))
            .transpose()?,
    };
    check_connection(&record)
        .map_err(|_| ProviderStoreError::Schema("row:connection".to_owned()))?;
    Ok(record)
}

const CONNECTION_COLUMNS: &str = "provider_id, manifest_digest, state, opt_in_facts, \
     connected_at_ms, updated_at_ms, last_verified_at_ms";

pub fn provider_connection(
    connection: &Connection,
    provider_id: &str,
) -> ProviderStoreResult<Option<ProviderConnection>> {
    connection
        .query_row(
            &format!(
                "select {CONNECTION_COLUMNS} from provider_connections where provider_id = ?1"
            ),
            [provider_id],
            |row| Ok(connection_from_row(row)),
        )
        .optional()?
        .transpose()
}

/// Every connection, ordered by provider id.
pub fn provider_connections(
    connection: &Connection,
) -> ProviderStoreResult<Vec<ProviderConnection>> {
    let mut statement = connection.prepare(&format!(
        "select {CONNECTION_COLUMNS} from provider_connections order by provider_id"
    ))?;
    let mut rows = statement.query([])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(connection_from_row(row)?);
    }
    Ok(records)
}

/// Sets one capability's effect level and fresh-check switch for a connected provider. This is the
/// store half only: the route that calls it owns the preview and one-use proof (BP-T175).
pub fn put_capability_setting(
    connection: &Connection,
    provider_id: &str,
    capability: ProviderCapabilityV1,
    setting: CapabilitySetting,
) -> ProviderStoreResult<()> {
    if provider_connection(connection, provider_id)?.is_none() {
        return Err(ProviderStoreError::Invalid("not_connected"));
    }
    connection.execute(
        "insert into provider_capability_settings (provider_id, capability, effect_level, \
             require_fresh) values (?1, ?2, ?3, ?4) \
         on conflict (provider_id, capability) do update set \
             effect_level = excluded.effect_level, require_fresh = excluded.require_fresh",
        params![
            provider_id,
            capability.as_str(),
            enum_text(&setting.effect_level),
            i64::from(setting.require_fresh),
        ],
    )?;
    Ok(())
}

/// The settings of every capability, with defaults filled in for capabilities that have no row.
pub fn capability_settings(
    connection: &Connection,
    provider_id: &str,
) -> ProviderStoreResult<BTreeMap<ProviderCapabilityV1, CapabilitySetting>> {
    let mut settings: BTreeMap<_, _> = ProviderCapabilityV1::ALL
        .iter()
        .map(|capability| (*capability, CapabilitySetting::default()))
        .collect();
    let mut statement = connection.prepare(
        "select capability, effect_level, require_fresh from provider_capability_settings \
         where provider_id = ?1",
    )?;
    let mut rows = statement.query([provider_id])?;
    while let Some(row) = rows.next()? {
        let capability: ProviderCapabilityV1 = enum_from(&row.get::<_, String>(0)?, "capability")?;
        let effect_level = enum_from(&row.get::<_, String>(1)?, "effect_level")?;
        let require_fresh = match row.get::<_, i64>(2)? {
            0 => false,
            1 => true,
            _ => return Err(ProviderStoreError::Schema("row:require_fresh".to_owned())),
        };
        settings.insert(
            capability,
            CapabilitySetting {
                effect_level,
                require_fresh,
            },
        );
    }
    Ok(settings)
}

fn check_signal(signal: &ProviderSignalV1) -> ProviderStoreResult<()> {
    signal
        .validate_shape()
        .map_err(|error| ProviderStoreError::Invalid(error.code()))
}

/// Caches a signal, replacing the previous one for the same provider, capability and subject. The
/// revision goes up only when the verdict or reason codes changed. Returns the stored revision.
pub fn put_signal(connection: &Connection, signal: &ProviderSignalV1) -> ProviderStoreResult<u32> {
    check_signal(signal)?;
    in_savepoint(connection, WRITE_SAVEPOINT, || {
        let previous: Option<(i64, String, String)> = connection
            .query_row(
                "select revision, verdict, reason_codes from provider_signals \
                 where provider_id = ?1 and capability = ?2 and subject_digest = ?3",
                params![
                    signal.provider_id,
                    signal.capability.as_str(),
                    signal.subject.digest
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let verdict = enum_text(&signal.verdict);
        let codes = join_codes(&signal.reason_codes);
        let revision = match previous {
            None => 1,
            Some((revision, old_verdict, old_codes))
                if old_verdict == verdict && old_codes == codes =>
            {
                revision
            }
            Some((revision, ..)) => revision.saturating_add(1),
        };
        connection.execute(
            "insert or replace into provider_signals (provider_id, capability, subject_digest, \
                 subject_kind, revision, verdict, reason_codes, inventory, state, observed_at_ms, \
                 expires_at_ms) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                signal.provider_id,
                signal.capability.as_str(),
                signal.subject.digest,
                enum_text(&signal.subject.kind),
                revision,
                verdict,
                codes,
                enum_text(&signal.inventory),
                enum_text(&signal.state),
                ms_to_sql(signal.observed_at_ms)?,
                ms_to_sql(signal.expires_at_ms)?,
            ],
        )?;
        connection.execute(
            "delete from provider_signals where provider_id = ?1 and rowid not in \
             (select rowid from provider_signals where provider_id = ?1 \
              order by observed_at_ms desc, rowid desc limit ?2)",
            params![signal.provider_id, MAX_SIGNALS_PER_PROVIDER],
        )?;
        u32::try_from(revision).map_err(|_| ProviderStoreError::Schema("row:revision".to_owned()))
    })
}

fn signal_from_row(row: &Row<'_>) -> ProviderStoreResult<StoredSignal> {
    let reason_codes: String = row.get(6)?;
    let reason_codes: Vec<String> = split_list(&reason_codes).map(str::to_owned).collect();
    if !reason_codes
        .iter()
        .all(|code| provider_reason_code_is_valid(code))
    {
        return Err(ProviderStoreError::Schema("row:reason_codes".to_owned()));
    }
    let revision = u32::try_from(row.get::<_, i64>(4)?)
        .ok()
        .filter(|revision| *revision >= 1)
        .ok_or_else(|| ProviderStoreError::Schema("row:revision".to_owned()))?;
    let signal = ProviderSignalV1 {
        version: PROVIDER_SIGNAL_V1_VERSION,
        provider_id: row.get(0)?,
        capability: enum_from(&row.get::<_, String>(1)?, "capability")?,
        subject: ProviderSubjectV1 {
            kind: enum_from(&row.get::<_, String>(3)?, "subject_kind")?,
            digest: row.get(2)?,
        },
        verdict: enum_from(&row.get::<_, String>(5)?, "verdict")?,
        reason_codes,
        observed_at_ms: ms_from_sql(row.get(9)?, "observed_at_ms")?,
        expires_at_ms: ms_from_sql(row.get(10)?, "expires_at_ms")?,
        inventory: enum_from(&row.get::<_, String>(7)?, "inventory")?,
        state: enum_from(&row.get::<_, String>(8)?, "state")?,
    };
    signal
        .validate_shape()
        .map_err(|error| ProviderStoreError::Schema(format!("row:{}", error.code())))?;
    Ok(StoredSignal { signal, revision })
}

const SIGNAL_COLUMNS: &str = "provider_id, capability, subject_digest, subject_kind, revision, \
     verdict, reason_codes, inventory, state, observed_at_ms, expires_at_ms";

/// Every cached signal about one subject for one capability, from every provider, ordered by
/// provider id. Expired and stale rows are returned too: freshness is the decide step's call
/// (`ProviderSignalV1::is_live_at`), and the card shows a stale row's age.
pub fn signals_for_subject(
    connection: &Connection,
    capability: ProviderCapabilityV1,
    subject_digest: &str,
) -> ProviderStoreResult<Vec<StoredSignal>> {
    if !sha256_hex_is_valid(subject_digest) {
        return Err(ProviderStoreError::Invalid("subject_digest"));
    }
    let mut statement = connection.prepare(&format!(
        "select {SIGNAL_COLUMNS} from provider_signals \
         where capability = ?1 and subject_digest = ?2 order by provider_id"
    ))?;
    let mut rows = statement.query(params![capability.as_str(), subject_digest])?;
    let mut signals = Vec::new();
    while let Some(row) = rows.next()? {
        signals.push(signal_from_row(row)?);
    }
    Ok(signals)
}

/// Drops signals that expired more than [`EXPIRED_SIGNAL_GRACE_MS`] before `now_ms`.
pub fn prune_expired_signals(connection: &Connection, now_ms: u64) -> ProviderStoreResult<usize> {
    let cutoff = ms_to_sql(now_ms.saturating_sub(EXPIRED_SIGNAL_GRACE_MS))?;
    Ok(connection.execute(
        "delete from provider_signals where expires_at_ms < ?1",
        [cutoff],
    )?)
}

/// Disconnect (PRD 6.7): drops the connection row, its settings and every cached signal of the
/// provider in one savepoint. The secret is deleted by the secret store (BP-T120). Returns whether
/// the provider was connected.
pub fn forget_provider(connection: &Connection, provider_id: &str) -> ProviderStoreResult<bool> {
    in_savepoint(connection, WRITE_SAVEPOINT, || {
        connection.execute(
            "delete from provider_signals where provider_id = ?1",
            [provider_id],
        )?;
        connection.execute(
            "delete from provider_capability_settings where provider_id = ?1",
            [provider_id],
        )?;
        Ok(connection.execute(
            "delete from provider_connections where provider_id = ?1",
            [provider_id],
        )? == 1)
    })
}

#[cfg(test)]
#[path = "provider_integration_store_tests.rs"]
mod tests;
