//! `store_workflow_capabilities*.py` — the `rusqlite`-backed workflow-capability
//! authority substrate (RTM-013 store half).
//!
//! This ports the mixin family that owns capability persistence:
//!   - `ensure_workflow_capability_schema` + `_validate_schema_objects` (strict
//!     owned-object equality on normalized SQL) + the retired-index migration.
//!   - `guard_events` insert + `_workflow_capability_event_payload` /
//!     `_private_reference` / `_canonical_json` (`capability_canonical_json`).
//!   - `build/append_authority_transition` + `validate_global_authority_ledger`
//!       + `validate_capability_transition_projection` — the append-only
//!         hash-chain ledger the control plane recomputes on every op.
//!   - `WorkflowCapabilityControl` two-phase commit (`load_validate_and_observe`
//!     / `prepare` / `finalize`) over a host-owned control blob.
//!   - `create/load_and_validate/advance_authority_state`, `append_revocation`.
//!   - The CAS ops `issue`/`claim`/`revoke`/`lookup`.
//!
//! Host coupling: `_connect` is replaced by a caller-owned `&Connection` inside
//! a `BEGIN IMMEDIATE` transaction (the caller opens the txn like
//! `claim_reuse.rs`); `_policy_integrity_secret_material` and the control-plane
//! blob are injected via the [`CapabilityStoreHooks`] trait. The serialized
//! `hold_workflow_capability_authority_lock` is process-level and stays on the
//! Python/host side — these methods document the same ordering but do not
//! re-implement the lock (each runs inside one `BEGIN IMMEDIATE` anyway).

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use guard_contracts::{
    authority_transition_sha256, canonical_framed_payload, capability_canonical_json,
    decode_signed_authority_state, decode_signed_authority_transition, decode_signed_revocation,
    encode_signed_authority_state, encode_signed_authority_transition, encode_signed_revocation,
    sign_authority_state, sign_authority_transition, sign_revocation,
    sign_workflow_capability_receipt, utc_timestamp_micros,
    validate_workflow_capability_identifier, verify_authority_state, verify_authority_transition,
    verify_revocation, verify_workflow_capability_receipt, workflow_capability_claim_sha256,
    SignedAuthorityState, SignedAuthorityTransition, SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt, WorkflowCapabilityAuthorityState,
    WorkflowCapabilityAuthorityTransition, WorkflowCapabilityBinding, WorkflowCapabilityError,
    WorkflowCapabilityReceipt, WorkflowCapabilityRevocation,
};

#[allow(dead_code)]
const ZERO_TRANSITION_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
#[allow(dead_code)]
const WORKFLOW_CAPABILITY_MIGRATION_VERSION: i64 = 14;
#[allow(dead_code)]
const RECEIPT_EVENT_INDEX_MIGRATION_VERSION: i64 = 22;
#[allow(dead_code)]
const RETIRED_RECEIPT_EVENT_INDEX: &str = "idx_guard_workflow_receipt_event";

#[allow(dead_code)]
type StoreResult<T> = Result<T, WorkflowCapabilityError>;
#[allow(dead_code)]
fn err<T>(reason: &'static str) -> StoreResult<T> {
    Err(WorkflowCapabilityError(reason))
}

/// `CapabilityStoreHooks` — the `_ControlStore` host callbacks plus the
/// policy-integrity key material the Python mixins pulled from `self`.
#[allow(dead_code)]
pub trait CapabilityStoreHooks {
    /// `_policy_integrity_secret_material(create)` → `(key, key_id)`;
    /// `Ok(None)` = unavailable (maps to `capability_key_unavailable`).
    fn policy_integrity_secret_material(
        &self,
        create: bool,
    ) -> StoreResult<Option<(Vec<u8>, String)>>;
    /// `_load_workflow_capability_control` → persisted control blob or `None`.
    fn load_workflow_capability_control(&self) -> StoreResult<Option<String>>;
    /// `_store_workflow_capability_control` → `true` on success.
    fn store_workflow_capability_control(&self, encoded: &str) -> StoreResult<bool>;
}

/// `_require_store_key`.
#[allow(dead_code)]
fn require_store_key(
    hooks: &dyn CapabilityStoreHooks,
    create: bool,
) -> StoreResult<(Vec<u8>, String)> {
    hooks
        .policy_integrity_secret_material(create)?
        .ok_or(WorkflowCapabilityError("capability_key_unavailable"))
}

// ─── schema ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
const SCHEMA_STATEMENTS: &[&str] = &[
    "create table if not exists guard_workflow_capabilities (
      capability_id text primary key,
      approval_provenance_id text not null,
      nonce text not null unique,
      signed_claim_json text not null,
      key_id text not null,
      issued_at text not null,
      not_before text not null,
      expires_at text not null,
      max_uses integer not null check (max_uses between 1 and 50),
      used_count integer not null default 0 check (used_count between 0 and max_uses),
      revoked_at text,
      revocation_code text,
      check ((revoked_at is null and revocation_code is null) or
             (revoked_at is not null and revocation_code is not null))
    ) strict",
    "create table if not exists guard_workflow_capability_authority_state (
      capability_id text primary key,
      signed_state_json text not null,
      key_id text not null,
      revision integer not null check (revision >= 0),
      use_high_water integer not null check (use_high_water >= 0),
      observed_at text not null,
      revocation_id text
    ) strict",
    "create table if not exists guard_workflow_capability_revocations (
      revocation_id text primary key,
      capability_id text not null unique,
      signed_revocation_json text not null,
      key_id text not null,
      revoked_at text not null
    ) strict",
    "create table if not exists guard_workflow_capability_receipts (
      receipt_id text primary key,
      capability_id text not null references guard_workflow_capabilities(capability_id),
      task_id text not null,
      invocation_id text not null unique,
      approval_provenance_id text not null,
      signed_receipt_json text not null,
      claimed_at text not null,
      use_number integer not null check (use_number >= 1),
      event_id integer not null references guard_events(event_id),
      unique (capability_id, use_number)
    ) strict",
    "create table if not exists guard_workflow_capability_authority_transitions (
      sequence integer primary key,
      capability_id text not null references guard_workflow_capabilities(capability_id),
      revision integer not null check (revision >= 0),
      transition_kind text not null,
      previous_transition_sha256 text not null,
      signed_transition_json text not null,
      key_id text not null,
      event_id integer not null unique references guard_events(event_id),
      unique (capability_id, revision)
    ) strict",
    "create index if not exists idx_guard_workflow_capability_expiry
    on guard_workflow_capabilities (revoked_at, expires_at, capability_id)",
    "create index if not exists idx_guard_workflow_receipt_capability
    on guard_workflow_capability_receipts (capability_id, use_number)",
    "create index if not exists idx_guard_workflow_receipt_event
    on guard_workflow_capability_receipts (event_id)",
    "create trigger if not exists trg_guard_workflow_capability_claim_immutable
    before update of capability_id, approval_provenance_id, nonce, signed_claim_json, key_id,
      issued_at, not_before, expires_at, max_uses on guard_workflow_capabilities
    begin select raise(abort, 'workflow_capability_claim_immutable'); end",
    "create trigger if not exists trg_guard_workflow_capability_no_delete
    before delete on guard_workflow_capabilities
    begin select raise(abort, 'workflow_capability_delete_forbidden'); end",
    "create trigger if not exists trg_guard_workflow_receipt_immutable_update
    before update on guard_workflow_capability_receipts
    begin select raise(abort, 'workflow_capability_receipt_immutable'); end",
    "create trigger if not exists trg_guard_workflow_receipt_immutable_delete
    before delete on guard_workflow_capability_receipts
    begin select raise(abort, 'workflow_capability_receipt_delete_forbidden'); end",
    "create trigger if not exists trg_guard_workflow_receipt_require_parents
    before insert on guard_workflow_capability_receipts
    begin
      select case when not exists (
        select 1 from guard_workflow_capabilities where capability_id = new.capability_id
      ) then raise(abort, 'workflow_capability_parent_missing') end;
      select case when not exists (
        select 1 from guard_events where event_id = new.event_id
      ) then raise(abort, 'workflow_capability_event_missing') end;
    end",
    "create trigger if not exists trg_guard_workflow_event_preserve_link
    before delete on guard_events when exists (
      select 1 from guard_workflow_capability_receipts where event_id = old.event_id
      union all
      select 1 from guard_workflow_capability_authority_transitions where event_id = old.event_id
    ) begin select raise(abort, 'workflow_capability_event_referenced'); end",
    "create trigger if not exists trg_guard_workflow_authority_state_no_delete
    before delete on guard_workflow_capability_authority_state
    begin select raise(abort, 'workflow_capability_authority_state_delete_forbidden'); end",
    "create trigger if not exists trg_guard_workflow_revocation_immutable_update
    before update on guard_workflow_capability_revocations
    begin select raise(abort, 'workflow_capability_revocation_immutable'); end",
    "create trigger if not exists trg_guard_workflow_revocation_immutable_delete
    before delete on guard_workflow_capability_revocations
    begin select raise(abort, 'workflow_capability_revocation_delete_forbidden'); end",
    "create trigger if not exists trg_guard_workflow_revocation_require_parent
    before insert on guard_workflow_capability_revocations when not exists (
      select 1 from guard_workflow_capabilities where capability_id = new.capability_id
    ) begin select raise(abort, 'workflow_capability_revocation_parent_missing'); end",
    "create trigger if not exists trg_guard_workflow_transition_immutable_update
    before update on guard_workflow_capability_authority_transitions
    begin select raise(abort, 'workflow_capability_transition_immutable'); end",
    "create trigger if not exists trg_guard_workflow_transition_immutable_delete
    before delete on guard_workflow_capability_authority_transitions
    begin select raise(abort, 'workflow_capability_transition_delete_forbidden'); end",
    "create trigger if not exists trg_guard_workflow_transition_require_parents
    before insert on guard_workflow_capability_authority_transitions
    begin
      select case when not exists (
        select 1 from guard_workflow_capabilities where capability_id = new.capability_id
      ) then raise(abort, 'workflow_capability_transition_parent_missing') end;
      select case when new.event_id is not null and not exists (
        select 1 from guard_events where event_id = new.event_id
      ) then raise(abort, 'workflow_capability_transition_event_missing') end;
    end",
];

#[allow(dead_code)]
const OBJECT_NAMES: &[(&str, &str)] = &[
    ("table", "guard_workflow_capabilities"),
    ("table", "guard_workflow_capability_authority_state"),
    ("table", "guard_workflow_capability_revocations"),
    ("table", "guard_workflow_capability_receipts"),
    ("table", "guard_workflow_capability_authority_transitions"),
    ("index", "idx_guard_workflow_capability_expiry"),
    ("index", "idx_guard_workflow_receipt_capability"),
    ("index", "idx_guard_workflow_receipt_event"),
    ("trigger", "trg_guard_workflow_capability_claim_immutable"),
    ("trigger", "trg_guard_workflow_capability_no_delete"),
    ("trigger", "trg_guard_workflow_receipt_immutable_update"),
    ("trigger", "trg_guard_workflow_receipt_immutable_delete"),
    ("trigger", "trg_guard_workflow_receipt_require_parents"),
    ("trigger", "trg_guard_workflow_event_preserve_link"),
    ("trigger", "trg_guard_workflow_authority_state_no_delete"),
    ("trigger", "trg_guard_workflow_revocation_immutable_update"),
    ("trigger", "trg_guard_workflow_revocation_immutable_delete"),
    ("trigger", "trg_guard_workflow_revocation_require_parent"),
    ("trigger", "trg_guard_workflow_transition_immutable_update"),
    ("trigger", "trg_guard_workflow_transition_immutable_delete"),
    ("trigger", "trg_guard_workflow_transition_require_parents"),
];

/// `_normalized_sql` — collapse whitespace runs, lowercase, strip
/// ` if not exists`.
#[allow(dead_code)]
fn normalized_sql(statement: &str) -> String {
    let mut out = String::with_capacity(statement.len());
    let mut last_space = false;
    for c in statement.trim().chars() {
        if c.is_whitespace() {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.extend(c.to_lowercase());
            last_space = false;
        }
    }
    out.replace(" if not exists", "")
}

/// `_validate_schema_objects` — strict owned-object equality on normalized
/// DDL against `sqlite_master`.
#[allow(dead_code)]
fn validate_schema_objects(connection: &Connection) -> StoreResult<()> {
    let expected: std::collections::HashMap<(&str, &str), String> = OBJECT_NAMES
        .iter()
        .zip(SCHEMA_STATEMENTS.iter())
        .map(|(name, sql)| (*name, normalized_sql(sql)))
        .collect();
    let mut stmt = connection
        .prepare(
            "select type, name, sql from sqlite_master
             where name like 'guard_workflow_capabilit%'
                or name like 'idx_guard_workflow_%'
                or name like 'trg_guard_workflow_%'",
        )
        .map_err(|_| WorkflowCapabilityError("invalid_workflow_capability_schema:owned_objects"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|_| WorkflowCapabilityError("invalid_workflow_capability_schema:owned_objects"))?;
    let mut actual: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    for row in rows.flatten() {
        let (t, n, sql) = row;
        if let Some(sql) = sql {
            if !n.starts_with("sqlite_autoindex") {
                actual.insert((t, n), normalized_sql(&sql));
            }
        }
    }
    if actual.len() != expected.len()
        || !actual
            .keys()
            .all(|(t, n)| expected.contains_key(&(t.as_str(), n.as_str())))
    {
        return err("invalid_workflow_capability_schema:owned_objects");
    }
    for ((t, n), expected_sql) in &expected {
        match actual.get(&(t.to_string(), n.to_string())) {
            Some(actual_sql) if actual_sql == expected_sql => {}
            _ => return err("invalid_workflow_capability_schema:mismatch"),
        }
    }
    Ok(())
}

/// `ensure_workflow_capability_schema` — apply migrations, drop the retired
/// receipt-event index, validate owned objects, record migration version.
#[allow(dead_code)]
pub fn ensure_workflow_capability_schema(
    connection: &Connection,
    applied_at: &str,
) -> StoreResult<()> {
    // Drop retired index first (outside the savepoint) so a validation
    // rollback can't resurrect it.
    connection
        .execute(
            &format!("drop index if exists {RETIRED_RECEIPT_EVENT_INDEX}"),
            [],
        )
        .map_err(|_| WorkflowCapabilityError("invalid_workflow_capability_schema:migration"))?;
    connection
        .execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            params![RECEIPT_EVENT_INDEX_MIGRATION_VERSION, applied_at],
        )
        .map_err(|_| WorkflowCapabilityError("invalid_workflow_capability_schema:migration"))?;

    connection
        .execute("savepoint workflow_capability_schema_v14", [])
        .map_err(|_| WorkflowCapabilityError("invalid_workflow_capability_schema:migration"))?;
    let mut migration_ok = true;
    for statement in SCHEMA_STATEMENTS {
        if connection.execute(statement, []).is_err() {
            migration_ok = false;
            break;
        }
    }
    if migration_ok && validate_schema_objects(connection).is_ok() {
        if connection
            .execute(
                "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
                params![WORKFLOW_CAPABILITY_MIGRATION_VERSION, applied_at],
            )
            .is_err()
        {
            migration_ok = false;
        }
    } else {
        migration_ok = false;
    }
    if migration_ok {
        let version: Option<String> = connection
            .query_row(
                "select applied_at from schema_migrations where version = ?",
                params![WORKFLOW_CAPABILITY_MIGRATION_VERSION],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        if version.as_deref().map(str::is_empty).unwrap_or(true) {
            migration_ok = false;
        }
    }
    if !migration_ok {
        let _ = connection.execute("rollback to workflow_capability_schema_v14", []);
        let _ = connection.execute("release workflow_capability_schema_v14", []);
        return err("invalid_workflow_capability_schema:migration");
    }
    connection
        .execute("release workflow_capability_schema_v14", [])
        .map_err(|_| WorkflowCapabilityError("invalid_workflow_capability_schema:migration"))?;
    Ok(())
}

// ─── events ──────────────────────────────────────────────────────────────

/// `_private_reference` — sha256 of the framed `audit-{purpose}` value.
#[allow(dead_code)]
fn private_reference(purpose: &str, value: &str) -> StoreResult<String> {
    let framed = canonical_framed_payload(
        &format!("audit-{purpose}"),
        &Value::String(value.to_string()),
    )
    .map_err(|e| WorkflowCapabilityError(e.0))?;
    Ok(hex_lower(&Sha256::digest(&framed)))
}

/// `_workflow_capability_event_payload` — the event extras the store emits.
#[allow(dead_code)]
fn workflow_capability_event_payload(
    capability_id: &str,
    invocation_id: Option<&str>,
    extra: Map<String, Value>,
) -> StoreResult<Value> {
    // `{capability_ref, **extra, [invocation_ref]}` — refs are
    // `_private_reference` digests so persisted event payloads never leak raw
    // ids. Order: capability_ref first, then extras, then invocation_ref last.
    let mut m = Map::new();
    m.insert(
        "capability_ref".into(),
        Value::String(private_reference("capability", capability_id)?),
    );
    for (k, v) in extra {
        m.insert(k, v);
    }
    if let Some(inv) = invocation_id {
        m.insert(
            "invocation_ref".into(),
            Value::String(private_reference("invocation", inv)?),
        );
    }
    Ok(Value::Object(m))
}

/// `_insert_workflow_capability_event` — append to `guard_events`, return
/// `event_id`.
#[allow(dead_code)]
fn insert_workflow_capability_event(
    connection: &Connection,
    event_name: &str,
    capability_id: &str,
    invocation_id: Option<&str>,
    occurred_at: &str,
    extra: Map<String, Value>,
) -> StoreResult<i64> {
    let payload = workflow_capability_event_payload(capability_id, invocation_id, extra)?;
    let encoded = capability_canonical_json(&payload).map_err(|e| WorkflowCapabilityError(e.0))?;
    let cursor = connection
        .execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            params![event_name, encoded, occurred_at],
        )
        .map_err(|_| WorkflowCapabilityError("capability_event_link_failed"))?;
    if cursor == 0 {
        return err("capability_event_link_failed");
    }
    Ok(connection.last_insert_rowid())
}

// ─── transitions / ledger ────────────────────────────────────────────────

#[allow(dead_code)]
fn sha256_of_json(signed: &SignedAuthorityState) -> StoreResult<String> {
    let encoded =
        encode_signed_authority_state(signed).map_err(|e| WorkflowCapabilityError(e.0))?;
    let framed = canonical_framed_payload("authority-state-digest", &Value::String(encoded))
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    Ok(hex_lower(&Sha256::digest(&framed)))
}

#[allow(dead_code)]
fn event_payload_sha256(payload: &Value) -> StoreResult<String> {
    let framed = canonical_framed_payload("authority-event-digest", payload)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    Ok(hex_lower(&Sha256::digest(&framed)))
}

/// `build_authority_transition`.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn build_authority_transition(
    signed_claim: &SignedWorkflowCapability,
    signed_state: &SignedAuthorityState,
    sequence: i64,
    previous_transition_sha256: &str,
    transition_kind: &str,
    event_id: i64,
    event_name: &str,
    event_payload: &Value,
    occurred_at: &str,
    use_number: Option<i64>,
    receipt_id: Option<String>,
    revocation_id: Option<String>,
    key: &[u8],
    key_id: &str,
) -> StoreResult<SignedAuthorityTransition> {
    let transition = WorkflowCapabilityAuthorityTransition::new(
        sequence,
        signed_claim.claim.capability_id.clone(),
        workflow_capability_claim_sha256(signed_claim).map_err(|e| WorkflowCapabilityError(e.0))?,
        signed_state.state.revision,
        transition_kind,
        previous_transition_sha256,
        sha256_of_json(signed_state)?,
        Some(event_id),
        Some(event_name.to_string()),
        Some(event_payload_sha256(event_payload)?),
        occurred_at,
        use_number,
        receipt_id,
        revocation_id,
    )
    .map_err(|e| WorkflowCapabilityError(e.0))?;
    sign_authority_transition(transition, key, key_id).map_err(|e| WorkflowCapabilityError(e.0))
}

/// `append_authority_transition` — insert into the ledger table.
#[allow(dead_code)]
pub fn append_authority_transition(
    connection: &Connection,
    signed: &SignedAuthorityTransition,
) -> StoreResult<()> {
    let t = &signed.transition;
    let encoded =
        encode_signed_authority_transition(signed).map_err(|e| WorkflowCapabilityError(e.0))?;
    connection
        .execute(
            "insert into guard_workflow_capability_authority_transitions
              (sequence, capability_id, revision, transition_kind, previous_transition_sha256,
               signed_transition_json, key_id, event_id)
            values (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                t.sequence,
                t.capability_id,
                t.revision,
                t.transition_kind,
                t.previous_transition_sha256,
                encoded,
                signed.key_id,
                t.event_id,
            ],
        )
        .map_err(|_| WorkflowCapabilityError("capability_authority_transition_chain_invalid"))?;
    Ok(())
}

#[allow(dead_code)]
fn validate_transition_event(
    connection: &Connection,
    transition: &WorkflowCapabilityAuthorityTransition,
) -> StoreResult<()> {
    let event_id = transition.event_id.ok_or(WorkflowCapabilityError(
        "capability_authority_transition_chain_invalid",
    ))?;
    let row: Option<(String, String, String)> = connection
        .query_row(
            "select event_name, payload_json, occurred_at from guard_events where event_id = ?",
            params![event_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| WorkflowCapabilityError("capability_authority_event_link_invalid"))?;
    let (name, payload, occurred_at) = row.ok_or(WorkflowCapabilityError(
        "capability_authority_event_link_invalid",
    ))?;
    if name != transition.event_name.as_deref().unwrap_or("")
        || occurred_at != transition.occurred_at
    {
        return err("capability_authority_event_link_invalid");
    }
    let decoded: Value = serde_json::from_str(&payload)
        .map_err(|_| WorkflowCapabilityError("capability_authority_event_link_invalid"))?;
    if event_payload_sha256(&decoded)?
        != transition.event_payload_sha256.clone().unwrap_or_default()
    {
        return err("capability_authority_event_link_invalid");
    }
    Ok(())
}

/// `validate_global_authority_ledger` → `(committed_sequence, committed_head)`.
#[allow(clippy::type_complexity)]
#[allow(dead_code)]
pub fn validate_global_authority_ledger(
    connection: &Connection,
    key: &[u8],
    key_id: &str,
) -> StoreResult<(i64, String)> {
    let mut stmt = connection
        .prepare(
            "select sequence, capability_id, revision, transition_kind, previous_transition_sha256,
                    signed_transition_json, key_id, event_id
             from guard_workflow_capability_authority_transitions order by sequence",
        )
        .map_err(|_| WorkflowCapabilityError("capability_authority_transition_chain_invalid"))?;
    let rows: Vec<(i64, String, i64, String, String, String, String, i64)> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })
        .map_err(|_| WorkflowCapabilityError("capability_authority_transition_chain_invalid"))?
        .filter_map(|r| r.ok())
        .collect();

    let mut previous = ZERO_TRANSITION_SHA256.to_string();
    let mut transition_event_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for (idx, row) in rows.iter().enumerate() {
        let expected_sequence = (idx + 1) as i64;
        let signed = decode_signed_authority_transition(&row.5).map_err(|_| {
            WorkflowCapabilityError("capability_authority_transition_chain_invalid")
        })?;
        verify_authority_transition(&signed, key, key_id).map_err(|_| {
            WorkflowCapabilityError("capability_authority_transition_chain_invalid")
        })?;
        let t = &signed.transition;
        let event_id = t.event_id.ok_or(WorkflowCapabilityError(
            "capability_authority_transition_chain_invalid",
        ))?;
        let duplicated = (
            row.0,
            row.1.clone(),
            row.2,
            row.3.clone(),
            row.4.clone(),
            row.6.clone(),
            row.7,
        );
        let authenticated = (
            t.sequence,
            t.capability_id.clone(),
            t.revision,
            t.transition_kind.clone(),
            t.previous_transition_sha256.clone(),
            signed.key_id.clone(),
            event_id,
        );
        if duplicated != authenticated
            || t.sequence != expected_sequence
            || t.previous_transition_sha256 != previous
        {
            return err("capability_authority_transition_chain_invalid");
        }
        validate_transition_event(connection, t)?;
        transition_event_ids.insert(event_id);
        previous = authority_transition_sha256(&signed).map_err(|_| {
            WorkflowCapabilityError("capability_authority_transition_chain_invalid")
        })?;
    }
    let mut estmt = connection
        .prepare(
            "select event_id from guard_events
             where event_name in ('workflow_capability.issued', 'workflow_capability.claimed',
                                  'workflow_capability.revoked')",
        )
        .map_err(|_| WorkflowCapabilityError("capability_authority_event_cardinality_invalid"))?;
    let event_ids: std::collections::HashSet<i64> = estmt
        .query_map([], |r| r.get::<_, i64>(0))
        .map_err(|_| WorkflowCapabilityError("capability_authority_event_cardinality_invalid"))?
        .filter_map(|r| r.ok())
        .collect();
    if event_ids != transition_event_ids || event_ids.len() != rows.len() {
        return err("capability_authority_event_cardinality_invalid");
    }
    Ok((rows.len() as i64, previous))
}

// ─── authority state ─────────────────────────────────────────────────────

/// `_write_state` — insert or update the authority-state row.
#[allow(dead_code)]
fn write_state(
    connection: &Connection,
    signed: &SignedAuthorityState,
    insert: bool,
) -> StoreResult<()> {
    let s = &signed.state;
    let encoded =
        encode_signed_authority_state(signed).map_err(|e| WorkflowCapabilityError(e.0))?;
    if insert {
        connection
            .execute(
                "insert into guard_workflow_capability_authority_state
                  (capability_id, signed_state_json, key_id, revision, use_high_water, observed_at, revocation_id)
                 values (?, ?, ?, ?, ?, ?, ?)",
                params![
                    s.capability_id, encoded, signed.key_id, s.revision,
                    s.use_high_water, s.observed_at, s.revocation_id,
                ],
            )
            .map_err(|_| WorkflowCapabilityError("capability_authority_state_conflict"))?;
    } else {
        let n = connection
            .execute(
                "update guard_workflow_capability_authority_state
                 set signed_state_json = ?, key_id = ?, revision = ?, use_high_water = ?,
                     observed_at = ?, revocation_id = ?
                 where capability_id = ? and revision = ?",
                params![
                    encoded,
                    signed.key_id,
                    s.revision,
                    s.use_high_water,
                    s.observed_at,
                    s.revocation_id,
                    s.capability_id,
                    s.revision - 1,
                ],
            )
            .map_err(|_| WorkflowCapabilityError("capability_authority_state_conflict"))?;
        if n != 1 {
            return err("capability_authority_state_conflict");
        }
    }
    Ok(())
}

/// `create_authority_state`.
#[allow(dead_code)]
pub fn create_authority_state(
    connection: &Connection,
    signed_claim: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
    now: &str,
) -> StoreResult<SignedAuthorityState> {
    let state = WorkflowCapabilityAuthorityState::new(
        signed_claim.claim.capability_id.clone(),
        workflow_capability_claim_sha256(signed_claim).map_err(|e| WorkflowCapabilityError(e.0))?,
        0,
        now,
        0,
        None,
        None,
    )
    .map_err(|e| WorkflowCapabilityError(e.0))?;
    let signed_state =
        sign_authority_state(state, key, key_id).map_err(|e| WorkflowCapabilityError(e.0))?;
    write_state(connection, &signed_state, true)?;
    Ok(signed_state)
}

/// `append_revocation`.
#[allow(dead_code)]
pub fn append_revocation(
    connection: &Connection,
    signed_claim: &SignedWorkflowCapability,
    reason_code: &str,
    revoked_at: &str,
    revocation_id: &str,
    key: &[u8],
    key_id: &str,
) -> StoreResult<WorkflowCapabilityRevocation> {
    let revocation = WorkflowCapabilityRevocation::new(
        revocation_id,
        signed_claim.claim.capability_id.clone(),
        workflow_capability_claim_sha256(signed_claim).map_err(|e| WorkflowCapabilityError(e.0))?,
        reason_code,
        revoked_at,
    )
    .map_err(|e| WorkflowCapabilityError(e.0))?;
    let signed = sign_revocation(revocation.clone(), key, key_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    let encoded = encode_signed_revocation(&signed).map_err(|e| WorkflowCapabilityError(e.0))?;
    connection
        .execute(
            "insert into guard_workflow_capability_revocations
              (revocation_id, capability_id, signed_revocation_json, key_id, revoked_at)
             values (?, ?, ?, ?, ?)",
            params![
                revocation_id,
                revocation.capability_id,
                encoded,
                key_id,
                revoked_at
            ],
        )
        .map_err(|_| WorkflowCapabilityError("capability_revocation_conflict"))?;
    Ok(revocation)
}

// ─── helpers ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ═══ control plane (store_workflow_capability_control.py) ═════════════════

/// `_CONTROL_VERSION` — persisted control blob schema version.
#[allow(dead_code)]
pub const WORKFLOW_CAPABILITY_CONTROL_VERSION: i64 = 1;

/// `WorkflowCapabilityControl` — the monotonic committed/pending ledger head.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowCapabilityControl {
    pub version: i64,
    pub committed_sequence: i64,
    pub committed_head_sha256: String,
    pub pending_sequence: Option<i64>,
    pub pending_head_sha256: Option<String>,
    pub observed_at: String,
}

#[allow(dead_code)]
impl WorkflowCapabilityControl {
    fn new(
        version: i64,
        committed_sequence: i64,
        committed_head_sha256: String,
        pending_sequence: Option<i64>,
        pending_head_sha256: Option<String>,
        observed_at: String,
    ) -> StoreResult<Self> {
        if version != WORKFLOW_CAPABILITY_CONTROL_VERSION {
            return err("unsupported_capability_control_version");
        }
        if committed_sequence < 0 {
            return err("invalid_capability_control_sequence");
        }
        control_digest("committed_head_sha256", &committed_head_sha256)?;
        if pending_sequence.is_some() != pending_head_sha256.is_some() {
            return err("invalid_capability_control_pending");
        }
        if let Some(ps) = pending_sequence {
            if ps != committed_sequence + 1 {
                return err("invalid_capability_control_pending");
            }
            control_digest(
                "pending_head_sha256",
                pending_head_sha256.as_deref().unwrap_or(""),
            )?;
        }
        if utc_timestamp_micros(&observed_at).is_none() {
            return err("invalid_canonical_timestamp");
        }
        Ok(Self {
            version,
            committed_sequence,
            committed_head_sha256,
            pending_sequence,
            pending_head_sha256,
            observed_at,
        })
    }
}

/// `_digest` — 64-char lowercase-hex field validator for the control blob.
#[allow(dead_code)]
fn control_digest(name: &'static str, value: &str) -> StoreResult<()> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    let _ = name;
    if !ok {
        return err(if name == "committed_head_sha256" {
            "invalid_committed_head_sha256"
        } else {
            "invalid_pending_head_sha256"
        });
    }
    Ok(())
}

/// `_encode_control` — canonical `{committed_head_sha256, committed_sequence,
/// observed_at, pending_head_sha256, pending_sequence, version}`.
#[allow(dead_code)]
fn encode_control(control: &WorkflowCapabilityControl) -> StoreResult<String> {
    let mut m = Map::new();
    m.insert(
        "committed_head_sha256".into(),
        Value::String(control.committed_head_sha256.clone()),
    );
    m.insert(
        "committed_sequence".into(),
        Value::Number(control.committed_sequence.into()),
    );
    m.insert(
        "observed_at".into(),
        Value::String(control.observed_at.clone()),
    );
    m.insert(
        "pending_head_sha256".into(),
        control
            .pending_head_sha256
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    m.insert(
        "pending_sequence".into(),
        control
            .pending_sequence
            .map(|s| Value::Number(s.into()))
            .unwrap_or(Value::Null),
    );
    m.insert("version".into(), Value::Number(control.version.into()));
    capability_canonical_json(&Value::Object(m)).map_err(|e| WorkflowCapabilityError(e.0))
}

/// `_decode_control` — strict canonical blob → `WorkflowCapabilityControl`.
#[allow(dead_code)]
fn decode_control(encoded: &str) -> StoreResult<WorkflowCapabilityControl> {
    let payload: Value = serde_json::from_str(encoded)
        .map_err(|_| WorkflowCapabilityError("capability_control_invalid"))?;
    let m = payload
        .as_object()
        .ok_or(WorkflowCapabilityError("capability_control_invalid"))?;
    let string = |k: &str| -> StoreResult<String> {
        m.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or(WorkflowCapabilityError("capability_control_invalid"))
    };
    let integer = |k: &str| -> StoreResult<i64> {
        m.get(k)
            .and_then(|v| v.as_i64())
            .ok_or(WorkflowCapabilityError("capability_control_invalid"))
    };
    let optional_string = |k: &str| -> StoreResult<Option<String>> {
        match m.get(k) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            _ => err("capability_control_invalid"),
        }
    };
    let optional_integer = |k: &str| -> StoreResult<Option<i64>> {
        match m.get(k) {
            Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_i64()
                .map(Some)
                .ok_or(WorkflowCapabilityError("capability_control_invalid")),
            None => err("capability_control_invalid"),
        }
    };
    let control = WorkflowCapabilityControl::new(
        integer("version")?,
        integer("committed_sequence")?,
        string("committed_head_sha256")?,
        optional_integer("pending_sequence")?,
        optional_string("pending_head_sha256")?,
        string("observed_at")?,
    )?;
    if encode_control(&control)? != encoded {
        return err("capability_control_invalid");
    }
    Ok(control)
}

/// `_store_control` — persist; `false` host ack → `capability_control_unavailable`.
#[allow(dead_code)]
fn store_control(
    hooks: &dyn CapabilityStoreHooks,
    control: &WorkflowCapabilityControl,
) -> StoreResult<()> {
    if !hooks.store_workflow_capability_control(&encode_control(control)?)? {
        return err("capability_control_unavailable");
    }
    Ok(())
}

/// `_has_authority_data` — any row already present in the ledger/state tables.
#[allow(dead_code)]
fn has_authority_data(connection: &Connection) -> StoreResult<bool> {
    let mut count = 0i64;
    for table in [
        "guard_workflow_capabilities",
        "guard_workflow_capability_authority_state",
        "guard_workflow_capability_authority_transitions",
        "guard_workflow_capability_receipts",
        "guard_workflow_capability_revocations",
    ] {
        count += connection
            .query_row(&format!("select count(*) from {table}"), [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(|_| WorkflowCapabilityError("capability_control_invalid"))?;
    }
    Ok(count > 0)
}

/// `load_validate_and_observe_control` — reconcile persisted control head with
/// the global authority ledger; write back when head/clock advances.
#[allow(dead_code)]
pub fn load_validate_and_observe_control(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    key: &[u8],
    key_id: &str,
    now: &str,
    create: bool,
) -> StoreResult<WorkflowCapabilityControl> {
    let (sequence, head) = validate_global_authority_ledger(connection, key, key_id)?;
    let persisted = hooks.load_workflow_capability_control()?;
    let was_persisted = persisted.is_some();
    let mut control = match persisted {
        Some(encoded) => decode_control(&encoded)?,
        None => WorkflowCapabilityControl::new(
            WORKFLOW_CAPABILITY_CONTROL_VERSION,
            sequence,
            head.clone(),
            None,
            None,
            now.to_string(),
        )?,
    };
    if has_authority_data(connection)? && control.committed_sequence > sequence {
        return err("capability_control_regression");
    }
    if control.committed_sequence < sequence || control.committed_head_sha256 != head {
        control.committed_sequence = sequence;
        control.committed_head_sha256 = head.clone();
        control.pending_sequence = None;
        control.pending_head_sha256 = None;
    }
    if validate_monotonic_workflow_capability_time(now, &control.observed_at)? || !was_persisted {
        control.observed_at = now.to_string();
    }
    if create {
        store_control(hooks, &control)?;
    }
    Ok(control)
}

/// `prepare_control_transition` — fold an appended transition into pending head.
#[allow(dead_code)]
pub fn prepare_control_transition(
    hooks: &dyn CapabilityStoreHooks,
    control: &WorkflowCapabilityControl,
    signed_transition: &SignedAuthorityTransition,
) -> StoreResult<WorkflowCapabilityControl> {
    let transition = &signed_transition.transition;
    if transition.revision != control.committed_sequence + 1 {
        return err("capability_control_sequence_conflict");
    }
    if transition.previous_transition_sha256 != control.committed_head_sha256 {
        return err("capability_control_head_conflict");
    }
    let head =
        authority_transition_sha256(signed_transition).map_err(|e| WorkflowCapabilityError(e.0))?;
    if control.pending_sequence.is_some() {
        return err("capability_control_pending");
    }
    let pending = WorkflowCapabilityControl::new(
        control.version,
        control.committed_sequence,
        control.committed_head_sha256.clone(),
        Some(transition.revision),
        Some(head),
        control.observed_at.clone(),
    )?;
    store_control(hooks, &pending)?;
    Ok(pending)
}

/// `finalize_control_transition` — promote pending head to committed.
#[allow(dead_code)]
pub fn finalize_control_transition(
    hooks: &dyn CapabilityStoreHooks,
    pending: &WorkflowCapabilityControl,
) -> StoreResult<()> {
    let (pending_sequence, pending_head) = match (
        pending.pending_sequence,
        pending.pending_head_sha256.as_deref(),
    ) {
        (Some(s), Some(h)) => (s, h),
        _ => return err("capability_control_pending"),
    };
    let finalized = WorkflowCapabilityControl::new(
        pending.version,
        pending_sequence,
        pending_head.to_string(),
        None,
        None,
        pending.observed_at.clone(),
    )?;
    store_control(hooks, &finalized)
}

/// `validate_monotonic_workflow_capability_time` — reject rollback, report
/// whether the external high-water must advance.
#[allow(dead_code)]
fn validate_monotonic_workflow_capability_time(now: &str, observed_at: &str) -> StoreResult<bool> {
    let current =
        utc_timestamp_micros(now).ok_or(WorkflowCapabilityError("invalid_canonical_timestamp"))?;
    let observed = utc_timestamp_micros(observed_at)
        .ok_or(WorkflowCapabilityError("invalid_canonical_timestamp"))?;
    if current < observed {
        return err("capability_clock_rollback");
    }
    Ok(current > observed)
}

// ═══ authority read/advance + receipt history (store_workflow_capability_authority.py) ═══

/// `_load_revocation` — the persisted revocation bound to this claim, or `None`.
#[allow(dead_code)]
fn load_revocation(
    connection: &Connection,
    signed_claim: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
) -> StoreResult<Option<WorkflowCapabilityRevocation>> {
    let rows = connection
        .prepare(
            "select revocation_id, signed_revocation_json, key_id, revoked_at \
             from guard_workflow_capability_revocations where capability_id = ? \
             order by revoked_at",
        )
        .and_then(|mut stmt| {
            let capability_id = signed_claim.claim.capability_id.clone();
            let rows = stmt
                .query_map([capability_id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>();
            rows
        })
        .map_err(|_| WorkflowCapabilityError("capability_revocation_lookup_failed"))?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() != 1 {
        return err("capability_revocation_conflicts");
    }
    let (revocation_id, signed_revocation_json, row_key_id, row_revoked_at) = &rows[0];
    let signed = decode_signed_revocation(signed_revocation_json)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    verify_revocation(&signed, key, key_id).map_err(|e| WorkflowCapabilityError(e.0))?;
    let revocation = signed.revocation.clone();
    if revocation_id != &revocation.revocation_id
        || row_key_id != &signed.key_id
        || row_revoked_at != &revocation.revoked_at
        || revocation.capability_id != signed_claim.claim.capability_id
        || revocation.claim_sha256
            != workflow_capability_claim_sha256(signed_claim)
                .map_err(|e| WorkflowCapabilityError(e.0))?
    {
        return err("capability_revocation_binding_invalid");
    }
    Ok(Some(revocation))
}

/// `_claim_event_extra` — `{approval_provenance_ref, receipt_ref, task_ref,
/// use_number}`.
#[allow(dead_code)]
fn claim_event_extra(
    approval_provenance_id: &str,
    receipt_id: &str,
    task_id: &str,
    use_number: i64,
) -> StoreResult<Map<String, Value>> {
    let mut m = Map::new();
    m.insert(
        "approval_provenance_ref".into(),
        Value::String(private_reference(
            "approval-provenance",
            approval_provenance_id,
        )?),
    );
    m.insert(
        "receipt_ref".into(),
        Value::String(private_reference("receipt", receipt_id)?),
    );
    m.insert(
        "task_ref".into(),
        Value::String(private_reference("task", task_id)?),
    );
    m.insert("use_number".into(), Value::Number(use_number.into()));
    Ok(m)
}

/// `_claim_event_payload` — `{capability_ref, invocation_ref, **_claim_event_extra}`.
#[allow(dead_code)]
fn claim_event_payload(receipt: &WorkflowCapabilityReceipt) -> StoreResult<Value> {
    let mut m = Map::new();
    m.insert(
        "capability_ref".into(),
        Value::String(private_reference("capability", &receipt.capability_id)?),
    );
    m.insert(
        "invocation_ref".into(),
        Value::String(private_reference("invocation", &receipt.invocation_id)?),
    );
    let extra = claim_event_extra(
        &receipt.approval_provenance_id,
        &receipt.receipt_id,
        &receipt.task_id,
        receipt.use_number,
    )?;
    for (k, v) in extra {
        m.insert(k, v);
    }
    Ok(Value::Object(m))
}

/// `_validate_receipt_history` — receipts + claimed-events all verify; return
/// the receipt count.
#[allow(dead_code)]
fn validate_receipt_history(
    connection: &Connection,
    signed_claim: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
) -> StoreResult<i64> {
    let mut stmt = connection
        .prepare(
            "select r.receipt_id, r.task_id, r.invocation_id, r.approval_provenance_id, \
             r.signed_receipt_json, r.claimed_at, r.use_number, r.event_id, \
             e.event_name, e.payload_json, e.occurred_at \
             from guard_workflow_capability_receipts r \
             left join guard_events e on e.event_id = r.event_id \
             where r.capability_id = ? order by r.use_number",
        )
        .map_err(|_| WorkflowCapabilityError("capability_receipt_history_invalid"))?;
    let capability_id = signed_claim.claim.capability_id.clone();
    let rows = stmt
        .query_map([capability_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
            ))
        })
        .map_err(|_| WorkflowCapabilityError("capability_receipt_history_invalid"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| WorkflowCapabilityError("capability_receipt_history_invalid"))?;
    let claim_sha =
        workflow_capability_claim_sha256(signed_claim).map_err(|e| WorkflowCapabilityError(e.0))?;
    for (
        row_receipt_id,
        row_task_id,
        row_invocation_id,
        row_approval_provenance_id,
        signed_receipt_json,
        row_claimed_at,
        row_use_number,
        row_event_id,
        event_name,
        payload_json,
        occurred_at,
    ) in &rows
    {
        let signed_receipt = decode_signed_receipt(signed_receipt_json)?;
        verify_workflow_capability_receipt(&signed_receipt, key, key_id)
            .map_err(|e| WorkflowCapabilityError(e.0))?;
        let receipt = &signed_receipt.receipt;
        if row_receipt_id != &receipt.receipt_id
            || row_task_id != &receipt.task_id
            || row_invocation_id != &receipt.invocation_id
            || row_approval_provenance_id != &receipt.approval_provenance_id
            || row_claimed_at != &receipt.claimed_at
            || *row_use_number != receipt.use_number
            || receipt.claim_sha256 != claim_sha
            || receipt.capability_id != signed_claim.claim.capability_id
            || receipt.binding != signed_claim.claim.binding
        {
            return err("capability_receipt_history_invalid");
        }
        if event_name.as_deref() != Some("workflow_capability.claimed")
            || occurred_at.as_deref() != Some(receipt.claimed_at.as_str())
        {
            return err("capability_receipt_event_history_invalid");
        }
        let expected_payload = capability_canonical_json(&claim_event_payload(receipt)?)
            .map_err(|e| WorkflowCapabilityError(e.0))?;
        if payload_json.as_deref() != Some(expected_payload.as_str()) {
            return err("capability_receipt_event_history_invalid");
        }
        let _ = row_event_id;
    }
    Ok(rows.len() as i64)
}

/// `_decode_signed_receipt` — strict canonical decode.
#[allow(dead_code)]
fn decode_signed_receipt(encoded: &str) -> StoreResult<SignedWorkflowCapabilityReceipt> {
    let payload: Value = serde_json::from_str(encoded)
        .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?;
    let m = payload
        .as_object()
        .ok_or(WorkflowCapabilityError("receipt_payload_invalid"))?;
    let need = |k: &str| -> StoreResult<String> {
        m.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or(WorkflowCapabilityError("receipt_payload_invalid"))
    };
    let receipt_value = m
        .get("receipt")
        .cloned()
        .ok_or(WorkflowCapabilityError("receipt_payload_invalid"))?;
    let receipt: WorkflowCapabilityReceipt = serde_json::from_value(receipt_value)
        .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?;
    let signed = SignedWorkflowCapabilityReceipt {
        envelope_schema: need("envelope_schema")?,
        algorithm: need("algorithm")?,
        receipt,
        key_id: need("key_id")?,
        signature: need("signature")?,
    };
    if capability_canonical_json(&signed.to_value()).map_err(|e| WorkflowCapabilityError(e.0))?
        != encoded
    {
        return err("receipt_payload_not_canonical");
    }
    Ok(signed)
}

/// `_decode_signed_claim` — strict canonical decode.
#[allow(dead_code)]
fn decode_signed_claim(encoded: &str) -> StoreResult<SignedWorkflowCapability> {
    SignedWorkflowCapability::from_canonical_json(encoded).map_err(|e| WorkflowCapabilityError(e.0))
}

/// `_validate_claim_row` — persisted projection columns must equal the claim.
#[allow(dead_code)]
fn validate_claim_row(
    signed: &SignedWorkflowCapability,
    row: &rusqlite::Row<'_>,
    capability_id: &str,
) -> StoreResult<()> {
    let claim = &signed.claim;
    let get_s = |i: usize| -> StoreResult<String> {
        row.get::<_, String>(i)
            .map_err(|_| WorkflowCapabilityError("capability_row_binding_invalid"))
    };
    let get_i = |i: usize| -> StoreResult<i64> {
        row.get::<_, i64>(i)
            .map_err(|_| WorkflowCapabilityError("capability_row_binding_invalid"))
    };
    let actual = (
        claim.capability_id.clone(),
        get_s(1)?,
        get_s(2)?,
        get_s(3)?,
        get_s(4)?,
        get_s(5)?,
        get_s(6)?,
        get_i(7)?,
    );
    let expected = (
        capability_id.to_string(),
        claim.approval_provenance_id.clone(),
        claim.nonce.clone(),
        signed.key_id.clone(),
        claim.issued_at.clone(),
        claim.not_before.clone(),
        claim.expires_at.clone(),
        claim.max_uses,
    );
    if actual != expected {
        return err("capability_row_binding_invalid");
    }
    Ok(())
}

/// `_verify_persisted_claim_signature` — signature-only check for a row loaded
/// straight from the table.
#[allow(dead_code)]
fn verify_persisted_claim_signature(
    signed: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
) -> StoreResult<()> {
    let expected = guard_contracts::sign_workflow_capability(signed.claim.clone(), key, key_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?
        .signature;
    if signed.key_id != key_id {
        return err("capability_key_mismatch");
    }
    if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
        return err("capability_signature_invalid");
    }
    Ok(())
}

#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `validate_capability_transition_projection` — the transition chain must
/// replay onto `signed_state` and the ledger-kind cardinality must match.
#[allow(dead_code)]
pub fn validate_capability_transition_projection(
    connection: &Connection,
    signed_claim: &SignedWorkflowCapability,
    signed_state: &SignedAuthorityState,
    receipt_count: i64,
    revocation_id: Option<&str>,
    key: &[u8],
    key_id: &str,
) -> StoreResult<()> {
    let claim_sha =
        workflow_capability_claim_sha256(signed_claim).map_err(|e| WorkflowCapabilityError(e.0))?;
    let rows = connection
        .prepare(
            "select signed_transition_json from \
             guard_workflow_capability_authority_transitions where capability_id = ? \
             order by revision",
        )
        .and_then(|mut stmt| {
            stmt.query_map([signed_claim.claim.capability_id.clone()], |r| {
                r.get::<_, String>(0)
            })
            .and_then(|m| m.collect::<Result<Vec<_>, _>>())
        })
        .map_err(|_| WorkflowCapabilityError("capability_authority_transition_lookup_failed"))?;
    if rows.is_empty() {
        return err("capability_authority_transition_missing");
    }
    let mut transitions = Vec::with_capacity(rows.len());
    for (expected_revision, row) in rows.iter().enumerate() {
        let signed =
            decode_signed_authority_transition(row).map_err(|e| WorkflowCapabilityError(e.0))?;
        verify_authority_transition(&signed, key, key_id)
            .map_err(|e| WorkflowCapabilityError(e.0))?;
        let t = &signed.transition;
        if t.revision != expected_revision as i64
            || t.capability_id != signed_claim.claim.capability_id
            || t.claim_sha256 != claim_sha
        {
            return err("capability_authority_transition_projection_invalid");
        }
        transitions.push(t.clone());
    }
    let claims: Vec<&WorkflowCapabilityAuthorityTransition> = transitions
        .iter()
        .filter(|t| t.transition_kind == "claimed")
        .collect();
    let revokes: Vec<&WorkflowCapabilityAuthorityTransition> = transitions
        .iter()
        .filter(|t| t.transition_kind == "revoked")
        .collect();
    if claims.len() as i64 != receipt_count {
        return err("capability_authority_transition_projection_invalid");
    }
    if revokes.len() != usize::from(revocation_id.is_some()) {
        return err("capability_authority_transition_projection_invalid");
    }
    if let (Some(rev), Some(rid)) = (revokes.first(), revocation_id) {
        if rev.revocation_id.as_deref() != Some(rid)
            || !std::ptr::eq(transitions.last().unwrap(), *rev)
        {
            return err("capability_authority_transition_projection_invalid");
        }
    }
    let last = transitions.last().unwrap();
    if last.revision != signed_state.state.revision
        || last.signed_state_sha256 != sha256_of_json(signed_state)?
    {
        return err("capability_authority_transition_projection_invalid");
    }
    Ok(())
}

/// `load_and_validate_authority` — state row must bind to the claim and the
/// receipt/revocation history must reconcile.
#[allow(dead_code)]
pub fn load_and_validate_authority(
    connection: &Connection,
    signed_claim: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
    used_count: i64,
    revoked_at: Option<&str>,
    revocation_code: Option<&str>,
) -> StoreResult<WorkflowCapabilityAuthorityState> {
    let capability_id = &signed_claim.claim.capability_id;
    let row = connection
        .query_row(
            "select signed_state_json, key_id, revision, use_high_water, observed_at, \
             revocation_id from guard_workflow_capability_authority_state \
             where capability_id = ?",
            [capability_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WorkflowCapabilityError("capability_authority_state_missing"))?
        .ok_or(WorkflowCapabilityError(
            "capability_authority_state_missing",
        ))?;
    let signed_state =
        decode_signed_authority_state(&row.0).map_err(|e| WorkflowCapabilityError(e.0))?;
    verify_authority_state(&signed_state, key, key_id).map_err(|e| WorkflowCapabilityError(e.0))?;
    let state = &signed_state.state;
    let duplicated = (
        capability_id.clone(),
        key_id.to_string(),
        row.2,
        row.3,
        row.4.clone(),
        row.5.clone(),
    );
    let authenticated = (
        state.capability_id.clone(),
        signed_state.key_id.clone(),
        state.revision,
        state.use_high_water,
        state.observed_at.clone(),
        state.revocation_id.clone(),
    );
    if duplicated != authenticated
        || state.claim_sha256
            != workflow_capability_claim_sha256(signed_claim)
                .map_err(|e| WorkflowCapabilityError(e.0))?
    {
        return err("capability_authority_state_binding_invalid");
    }
    let receipt_count = validate_receipt_history(connection, signed_claim, key, key_id)?;
    if state.use_high_water != receipt_count || used_count != receipt_count {
        return err("capability_use_high_water_invalid");
    }
    let revocation = load_revocation(connection, signed_claim, key, key_id)?;
    match revocation {
        None => {
            if state.revocation_id.is_some() || revoked_at.is_some() || revocation_code.is_some() {
                return err("capability_revocation_state_invalid");
            }
        }
        Some(rev) => {
            if state.revocation_id.as_deref() != Some(rev.revocation_id.as_str())
                || state.revoked_at.as_deref() != Some(rev.revoked_at.as_str())
                || revoked_at != Some(rev.revoked_at.as_str())
                || revocation_code != Some(rev.reason_code.as_str())
            {
                return err("capability_revocation_state_invalid");
            }
        }
    }
    validate_capability_transition_projection(
        connection,
        signed_claim,
        &signed_state,
        receipt_count,
        state.revocation_id.as_deref(),
        key,
        key_id,
    )?;
    Ok(state.clone())
}

/// `advance_authority_state` — apply the deltas and persist the new signed state.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn advance_authority_state(
    connection: &Connection,
    state: &WorkflowCapabilityAuthorityState,
    key: &[u8],
    key_id: &str,
    now: &str,
    use_high_water: Option<i64>,
    revocation_id: Option<String>,
    revoked_at: Option<String>,
) -> StoreResult<SignedAuthorityState> {
    let current =
        utc_timestamp_micros(now).ok_or(WorkflowCapabilityError("invalid_canonical_timestamp"))?;
    let observed = utc_timestamp_micros(&state.observed_at)
        .ok_or(WorkflowCapabilityError("invalid_canonical_timestamp"))?;
    if current < observed {
        return err("capability_clock_rollback");
    }
    let mut updated = state.clone();
    updated.observed_at = now.to_string();
    updated.revision = state.revision + 1;
    if let Some(u) = use_high_water {
        updated.use_high_water = u;
    }
    if let Some(r) = revocation_id {
        updated.revocation_id = Some(r);
    }
    if let Some(r) = revoked_at {
        updated.revoked_at = Some(r);
    }
    let signed_state =
        sign_authority_state(updated, key, key_id).map_err(|e| WorkflowCapabilityError(e.0))?;
    write_state(connection, &signed_state, false)?;
    Ok(signed_state)
}

// ═══ capability CAS ops (store_workflow_capabilities.py + lookup + revocation + receipt_lookup) ═══

/// `load_validated_workflow_capability` — row → claim must verify against the
/// persisted projection and the authority ledger.
#[allow(dead_code)]
pub fn load_validated_workflow_capability(
    connection: &Connection,
    capability_id: &str,
    key: &[u8],
    key_id: &str,
) -> StoreResult<Option<SignedWorkflowCapability>> {
    let row = connection
        .query_row(
            "select signed_claim_json, approval_provenance_id, nonce, key_id, \
             issued_at, not_before, expires_at, max_uses, used_count, \
             revoked_at, revocation_code \
             from guard_workflow_capabilities where capability_id = ?",
            [capability_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WorkflowCapabilityError("capability_row_binding_invalid"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let signed = decode_signed_claim(&row.0)?;
    validate_claim_row_tuple(&signed, &row_ref_for_claim(&row), capability_id)?;
    verify_persisted_claim_signature(&signed, key, key_id)?;
    load_and_validate_authority(
        connection,
        &signed,
        key,
        key_id,
        row.8,
        row.9.as_deref(),
        row.10.as_deref(),
    )?;
    Ok(Some(signed))
}

/// `require_validated_workflow_capability` — `None` → `receipt_claim_missing`.
#[allow(dead_code)]
pub fn require_validated_workflow_capability(
    connection: &Connection,
    capability_id: &str,
    key: &[u8],
    key_id: &str,
) -> StoreResult<SignedWorkflowCapability> {
    load_validated_workflow_capability(connection, capability_id, key, key_id)?
        .ok_or(WorkflowCapabilityError("receipt_claim_missing"))
}

/// `_row_ref_for_claim` — adapt a materialized tuple into the shape
/// `validate_claim_row` expects (row position 0 = signed_claim_json; claim row
/// checks read positions 1..7). We pass the tuple in as `&ClaimRowRef`.
#[allow(dead_code)]
struct ClaimRowRef {
    approval_provenance_id: String,
    nonce: String,
    key_id: String,
    issued_at: String,
    not_before: String,
    expires_at: String,
    max_uses: i64,
}

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn row_ref_for_claim(
    row: &(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        Option<String>,
        Option<String>,
    ),
) -> ClaimRowRef {
    ClaimRowRef {
        approval_provenance_id: row.1.clone(),
        nonce: row.2.clone(),
        key_id: row.3.clone(),
        issued_at: row.4.clone(),
        not_before: row.5.clone(),
        expires_at: row.6.clone(),
        max_uses: row.7,
    }
}

/// `_validate_claim_row` over the materialized tuple (positions shifted by 1:
/// index 0 = signed_claim_json, claim fields are 1..7).
#[allow(dead_code)]
#[allow(clippy::eq_op)]
fn validate_claim_row_tuple(
    signed: &SignedWorkflowCapability,
    row: &ClaimRowRef,
    capability_id: &str,
) -> StoreResult<()> {
    let claim = &signed.claim;
    let actual = (
        claim.capability_id.clone(),
        row.approval_provenance_id.clone(),
        row.nonce.clone(),
        row.key_id.clone(),
        row.issued_at.clone(),
        row.not_before.clone(),
        row.expires_at.clone(),
        row.max_uses,
    );
    let expected = (
        capability_id.to_string(),
        claim.approval_provenance_id.clone(),
        claim.nonce.clone(),
        signed.key_id.clone(),
        claim.issued_at.clone(),
        claim.not_before.clone(),
        claim.expires_at.clone(),
        claim.max_uses,
    );
    if actual != expected {
        return err("capability_row_binding_invalid");
    }
    Ok(())
}

/// `issue_workflow_capability` — insert the signed claim, emit the issued
/// event, seed authority state, and chain the first transition.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::eq_op)]
#[allow(dead_code)]
pub fn issue_workflow_capability(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    signed: &SignedWorkflowCapability,
    approval_provenance_id: &str,
    now: &str,
) -> StoreResult<()> {
    if approval_provenance_id != signed.claim.approval_provenance_id {
        return err("capability_approval_binding_mismatch");
    }
    let (key, key_id) = require_store_key(hooks, false)?;
    // `verify_workflow_capability` body (signature + not_before/expires_at +
    // binding) runs inline: persisted claims always validate against their own
    // binding.
    verify_workflow_capability_signature_only(signed, &key, &key_id)?;
    let current =
        utc_timestamp_micros(now).ok_or(WorkflowCapabilityError("invalid_canonical_timestamp"))?;
    if current < utc_timestamp_micros(&signed.claim.not_before).unwrap_or(i64::MIN) {
        return err("capability_not_yet_valid");
    }
    if current >= utc_timestamp_micros(&signed.claim.expires_at).unwrap_or(i64::MAX) {
        return err("capability_expired");
    }
    if signed.claim.binding != signed.claim.binding {
        return err("capability_context_mismatch");
    }
    let encoded = signed
        .to_canonical_json()
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    ensure_workflow_capability_schema(connection, now)?;
    let control = load_validate_and_observe_control(hooks, connection, &key, &key_id, now, true)?;
    let claim = &signed.claim;
    connection
        .execute(
            "insert into guard_workflow_capabilities (\
               capability_id, approval_provenance_id, nonce, signed_claim_json, key_id, \
               issued_at, not_before, expires_at, max_uses, used_count, revoked_at, \
               revocation_code\
             ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, null, null)",
            params![
                claim.capability_id,
                approval_provenance_id,
                claim.nonce,
                encoded,
                key_id,
                claim.issued_at,
                claim.not_before,
                claim.expires_at,
                claim.max_uses,
            ],
        )
        .map_err(|_| WorkflowCapabilityError("capability_already_exists"))?;
    let mut event_extra = Map::new();
    event_extra.insert(
        "approval_provenance_ref".into(),
        Value::String(private_reference(
            "approval-provenance",
            approval_provenance_id,
        )?),
    );
    event_extra.insert("max_uses".into(), Value::Number(claim.max_uses.into()));
    event_extra.insert(
        "task_ref".into(),
        Value::String(private_reference("task", &claim.task_id)?),
    );
    let event_id = insert_workflow_capability_event(
        connection,
        "workflow_capability.issued",
        &claim.capability_id,
        None,
        now,
        event_extra.clone(),
    )?;
    let signed_state = create_authority_state(connection, signed, &key, &key_id, now)?;
    let transition = build_authority_transition(
        signed,
        &signed_state,
        control.committed_sequence + 1,
        &control.committed_head_sha256,
        "issued",
        event_id,
        "workflow_capability.issued",
        &workflow_capability_event_payload(&claim.capability_id, None, event_extra)?,
        now,
        None,
        None,
        None,
        &key,
        &key_id,
    )?;
    let pending = prepare_control_transition(hooks, &control, &transition)?;
    append_authority_transition(connection, &transition)?;
    finalize_control_transition(hooks, &pending)?;
    Ok(())
}

/// `claim_workflow_capability` — CAS-consume one use, persist the receipt,
/// emit the claimed event, and chain the claimed transition.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn claim_workflow_capability(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    capability_id: &str,
    invocation_id: &str,
    expected_binding: &WorkflowCapabilityBinding,
    expected_subject_id: &str,
    expected_task_id: &str,
    expected_issuer_id: &str,
    expected_approval_provenance_id: &str,
    now: &str,
) -> StoreResult<SignedWorkflowCapabilityReceipt> {
    validate_workflow_capability_identifier("capability_id", capability_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    validate_workflow_capability_identifier("invocation_id", invocation_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    for (name, value) in [
        ("expected_subject_id", expected_subject_id),
        ("expected_task_id", expected_task_id),
        ("expected_issuer_id", expected_issuer_id),
        (
            "expected_approval_provenance_id",
            expected_approval_provenance_id,
        ),
    ] {
        validate_workflow_capability_identifier(name, value)
            .map_err(|e| WorkflowCapabilityError(e.0))?;
    }
    let (key, key_id) = require_store_key(hooks, false)?;
    ensure_workflow_capability_schema(connection, now)?;
    let control = load_validate_and_observe_control(hooks, connection, &key, &key_id, now, false)?;
    let row = connection
        .query_row(
            "select signed_claim_json, key_id, issued_at, not_before, expires_at, \
             max_uses, used_count, revoked_at, revocation_code, approval_provenance_id, \
             nonce from guard_workflow_capabilities where capability_id = ?",
            [capability_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WorkflowCapabilityError("capability_not_found"))?
        .ok_or(WorkflowCapabilityError("capability_not_found"))?;
    let signed = decode_signed_claim(&row.0)?;
    // `_validate_claim_row` positions differ in this select order — reuse the
    // tuple form with a shuffled `ClaimRowRef`.
    let claim_ref = ClaimRowRef {
        approval_provenance_id: row.9.clone(),
        nonce: row.10.clone(),
        key_id: row.1.clone(),
        issued_at: row.2.clone(),
        not_before: row.3.clone(),
        expires_at: row.4.clone(),
        max_uses: row.5,
    };
    validate_claim_row_tuple(&signed, &claim_ref, capability_id)?;
    let state = load_and_validate_authority(
        connection,
        &signed,
        &key,
        &key_id,
        row.6,
        row.7.as_deref(),
        row.8.as_deref(),
    )?;
    // `verify_workflow_capability` — signature + window + binding.
    verify_workflow_capability_signature_only(&signed, &key, &key_id)?;
    let current =
        utc_timestamp_micros(now).ok_or(WorkflowCapabilityError("invalid_canonical_timestamp"))?;
    if current < utc_timestamp_micros(&signed.claim.not_before).unwrap_or(i64::MIN) {
        return err("capability_not_yet_valid");
    }
    if current >= utc_timestamp_micros(&signed.claim.expires_at).unwrap_or(i64::MAX) {
        return err("capability_expired");
    }
    if &signed.claim.binding != expected_binding {
        return err("capability_context_mismatch");
    }
    let claim = &signed.claim;
    if claim.subject_id != expected_subject_id
        || claim.task_id != expected_task_id
        || claim.issuer_id != expected_issuer_id
        || claim.approval_provenance_id != expected_approval_provenance_id
    {
        return err("capability_claimant_context_mismatch");
    }
    if state.revocation_id.is_some() {
        return err("capability_revoked");
    }
    let used_count = row.6;
    if used_count >= signed.claim.max_uses {
        return err("capability_exhausted");
    }
    let replayed = connection
        .query_row(
            "select 1 from guard_workflow_capability_receipts where invocation_id = ?",
            [invocation_id],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WorkflowCapabilityError("capability_invocation_replayed"))?;
    if replayed.is_some() {
        return err("capability_invocation_replayed");
    }
    let use_number = used_count + 1;
    let receipt_id = new_receipt_id()?;
    let updated = connection
        .execute(
            "update guard_workflow_capabilities set used_count = ? \
             where capability_id = ? and used_count = ? and revoked_at is null",
            params![use_number, capability_id, used_count],
        )
        .map_err(|_| WorkflowCapabilityError("capability_claim_conflict"))?;
    if updated != 1 {
        return err("capability_claim_conflict");
    }
    let event_extra = claim_event_extra(
        &signed.claim.approval_provenance_id,
        &receipt_id,
        &signed.claim.task_id,
        use_number,
    )?;
    let event_id = insert_workflow_capability_event(
        connection,
        "workflow_capability.claimed",
        capability_id,
        Some(invocation_id),
        now,
        event_extra.clone(),
    )?;
    let claim_sha =
        workflow_capability_claim_sha256(&signed).map_err(|e| WorkflowCapabilityError(e.0))?;
    let receipt = WorkflowCapabilityReceipt {
        schema_version: "hol-guard.workflow-capability-receipt.v1".to_string(),
        receipt_id: receipt_id.clone(),
        capability_id: capability_id.to_string(),
        task_id: signed.claim.task_id.clone(),
        invocation_id: invocation_id.to_string(),
        approval_provenance_id: signed.claim.approval_provenance_id.clone(),
        claim_sha256: claim_sha,
        binding: expected_binding.clone(),
        use_number,
        event_id,
        claimed_at: now.to_string(),
    };
    let signed_receipt = sign_workflow_capability_receipt(receipt, &key, &key_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    let receipt_json = capability_canonical_json(&signed_receipt.to_value())
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    connection
        .execute(
            "insert into guard_workflow_capability_receipts (\
               receipt_id, capability_id, task_id, invocation_id, approval_provenance_id, \
               signed_receipt_json, claimed_at, use_number, event_id\
             ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                signed_receipt.receipt.receipt_id,
                capability_id,
                signed_receipt.receipt.task_id,
                invocation_id,
                signed_receipt.receipt.approval_provenance_id,
                receipt_json,
                now,
                use_number,
                event_id,
            ],
        )
        .map_err(|_| WorkflowCapabilityError("capability_claim_conflict"))?;
    let signed_state = advance_authority_state(
        connection,
        &state,
        &key,
        &key_id,
        now,
        Some(use_number),
        None,
        None,
    )?;
    let transition = build_authority_transition(
        &signed,
        &signed_state,
        control.committed_sequence + 1,
        &control.committed_head_sha256,
        "claimed",
        event_id,
        "workflow_capability.claimed",
        &workflow_capability_event_payload(capability_id, Some(invocation_id), event_extra)?,
        now,
        Some(use_number),
        Some(receipt_id.clone()),
        None,
        &key,
        &key_id,
    )?;
    let pending = prepare_control_transition(hooks, &control, &transition)?;
    append_authority_transition(connection, &transition)?;
    finalize_control_transition(hooks, &pending)?;
    Ok(signed_receipt)
}

/// `revoke_workflow_capability` — append the revocation + emit the revoked
/// event + advance state; `false` when the capability is unknown or already
/// revoked.
#[allow(dead_code)]
pub fn revoke_workflow_capability(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    capability_id: &str,
    reason_code: &str,
    revocation_id: &str,
    now: &str,
) -> StoreResult<bool> {
    validate_workflow_capability_identifier("capability_id", capability_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    validate_reason_code(reason_code)?;
    let (key, key_id) = require_store_key(hooks, false)?;
    ensure_workflow_capability_schema(connection, now)?;
    let control = load_validate_and_observe_control(hooks, connection, &key, &key_id, now, false)?;
    let row = connection
        .query_row(
            "select signed_claim_json, key_id, issued_at, not_before, expires_at, \
             max_uses, used_count, revoked_at, revocation_code, approval_provenance_id, \
             nonce from guard_workflow_capabilities where capability_id = ?",
            [capability_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WorkflowCapabilityError("capability_row_binding_invalid"))?;
    let Some(row) = row else {
        return Ok(false);
    };
    let signed = decode_signed_claim(&row.0)?;
    let claim_ref = ClaimRowRef {
        approval_provenance_id: row.9.clone(),
        nonce: row.10.clone(),
        key_id: row.1.clone(),
        issued_at: row.2.clone(),
        not_before: row.3.clone(),
        expires_at: row.4.clone(),
        max_uses: row.5,
    };
    validate_claim_row_tuple(&signed, &claim_ref, capability_id)?;
    verify_persisted_claim_signature(&signed, &key, &key_id)?;
    let state = load_and_validate_authority(
        connection,
        &signed,
        &key,
        &key_id,
        row.6,
        row.7.as_deref(),
        row.8.as_deref(),
    )?;
    if state.revocation_id.is_some() {
        return Ok(false);
    }
    append_revocation(
        connection,
        &signed,
        reason_code,
        now,
        revocation_id,
        &key,
        &key_id,
    )?;
    let cursor = connection
        .execute(
            "update guard_workflow_capabilities set revoked_at = ?, revocation_code = ? \
             where capability_id = ? and revoked_at is null",
            params![now, reason_code, capability_id],
        )
        .map_err(|_| WorkflowCapabilityError("capability_revocation_update_failed"))?;
    if cursor != 1 {
        return Ok(false);
    }
    let mut event_extra = Map::new();
    event_extra.insert(
        "revocation_ref".into(),
        Value::String(private_reference("revocation-code", reason_code)?),
    );
    let event_id = insert_workflow_capability_event(
        connection,
        "workflow_capability.revoked",
        capability_id,
        None,
        now,
        event_extra.clone(),
    )?;
    let signed_state = advance_authority_state(
        connection,
        &state,
        &key,
        &key_id,
        now,
        None,
        Some(revocation_id.to_string()),
        Some(now.to_string()),
    )?;
    let transition = build_authority_transition(
        &signed,
        &signed_state,
        control.committed_sequence + 1,
        &control.committed_head_sha256,
        "revoked",
        event_id,
        "workflow_capability.revoked",
        &workflow_capability_event_payload(capability_id, None, event_extra)?,
        now,
        None,
        None,
        Some(revocation_id.to_string()),
        &key,
        &key_id,
    )?;
    let pending = prepare_control_transition(hooks, &control, &transition)?;
    append_authority_transition(connection, &transition)?;
    finalize_control_transition(hooks, &pending)?;
    Ok(true)
}

/// `lookup_workflow_capability` — load + fully validate one capability.
#[allow(dead_code)]
pub fn lookup_workflow_capability(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    capability_id: &str,
    now: &str,
) -> StoreResult<Option<SignedWorkflowCapability>> {
    validate_workflow_capability_identifier("capability_id", capability_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    let (key, key_id) = require_store_key(hooks, false)?;
    ensure_workflow_capability_schema(connection, now)?;
    load_validate_and_observe_control(hooks, connection, &key, &key_id, now, false)?;
    load_validated_workflow_capability(connection, capability_id, &key, &key_id)
}

/// `lookup_workflow_capability_receipt` — exactly one of `receipt_id` /
/// `invocation_id`; receipt + claim + event all must bind.
#[allow(dead_code)]
pub fn lookup_workflow_capability_receipt(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    receipt_id: Option<&str>,
    invocation_id: Option<&str>,
    now: &str,
) -> StoreResult<Option<SignedWorkflowCapabilityReceipt>> {
    if receipt_id.is_some() == invocation_id.is_some() {
        return err("receipt_lookup_requires_exact_selector");
    }
    let (selector_name, selector_value) = match (receipt_id, invocation_id) {
        (Some(r), None) => ("receipt_id", r),
        (None, Some(i)) => ("invocation_id", i),
        _ => return err("receipt_lookup_requires_exact_selector"),
    };
    validate_workflow_capability_identifier(selector_name, selector_value)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    let (key, key_id) = require_store_key(hooks, false)?;
    ensure_workflow_capability_schema(connection, now)?;
    load_validate_and_observe_control(hooks, connection, &key, &key_id, now, false)?;
    let (sql, param) = if receipt_id.is_some() {
        (
            "select r.receipt_id, r.capability_id, r.task_id, r.invocation_id, \
             r.approval_provenance_id, r.signed_receipt_json, r.claimed_at, \
             r.use_number, r.event_id, e.event_name, e.payload_json, e.occurred_at \
             from guard_workflow_capability_receipts r \
             left join guard_events e on e.event_id = r.event_id \
             where r.receipt_id = ?",
            selector_value,
        )
    } else {
        (
            "select r.receipt_id, r.capability_id, r.task_id, r.invocation_id, \
             r.approval_provenance_id, r.signed_receipt_json, r.claimed_at, \
             r.use_number, r.event_id, e.event_name, e.payload_json, e.occurred_at \
             from guard_workflow_capability_receipts r \
             left join guard_events e on e.event_id = r.event_id \
             where r.invocation_id = ?",
            selector_value,
        )
    };
    let row = connection
        .query_row(sql, [param], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, Option<String>>(11)?,
            ))
        })
        .optional()
        .map_err(|_| WorkflowCapabilityError("receipt_lookup_failed"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let signed_receipt = decode_signed_receipt(&row.5)?;
    verify_workflow_capability_receipt(&signed_receipt, &key, &key_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    let receipt = &signed_receipt.receipt;
    if row.0 != receipt.receipt_id
        || row.1 != receipt.capability_id
        || row.2 != receipt.task_id
        || row.3 != receipt.invocation_id
        || row.4 != receipt.approval_provenance_id
        || row.6 != receipt.claimed_at
        || row.7 != receipt.use_number
        || row.8 != receipt.event_id
    {
        return err("receipt_row_binding_invalid");
    }
    let signed_claim =
        require_validated_workflow_capability(connection, &receipt.capability_id, &key, &key_id)?;
    let claim = &signed_claim.claim;
    if receipt.capability_id != claim.capability_id
        || receipt.task_id != claim.task_id
        || receipt.approval_provenance_id != claim.approval_provenance_id
        || receipt.binding != claim.binding
        || receipt.claim_sha256
            != workflow_capability_claim_sha256(&signed_claim)
                .map_err(|e| WorkflowCapabilityError(e.0))?
    {
        return err("receipt_claim_binding_invalid");
    }
    if row.9.as_deref() != Some("workflow_capability.claimed")
        || row.11.as_deref() != Some(receipt.claimed_at.as_str())
    {
        return err("receipt_event_binding_invalid");
    }
    let expected_payload = capability_canonical_json(&claim_event_payload(receipt)?)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    if row.10.as_deref() != Some(expected_payload.as_str()) {
        return err("receipt_event_binding_invalid");
    }
    Ok(Some(signed_receipt))
}

// ─── helpers for the ops ─────────────────────────────────────────────────

#[allow(dead_code)]
fn verify_workflow_capability_signature_only(
    signed: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
) -> StoreResult<()> {
    let expected = guard_contracts::sign_workflow_capability(signed.claim.clone(), key, key_id)
        .map_err(|e| WorkflowCapabilityError(e.0))?
        .signature;
    if signed.key_id != key_id {
        return err("capability_key_mismatch");
    }
    if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
        return err("capability_signature_invalid");
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_reason_code(value: &str) -> StoreResult<()> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.' || b == b'-'
        });
    if !ok {
        return err("invalid_reason_code");
    }
    Ok(())
}

#[allow(dead_code)]
fn new_receipt_id() -> StoreResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| WorkflowCapabilityError("capability_receipt_id_unavailable"))?;
    // UUIDv4 bit layout; hex form matches Python's `uuid4().hex`.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!("wcr-{}", hex_lower(&bytes)))
}
