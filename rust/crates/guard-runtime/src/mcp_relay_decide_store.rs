//! What the store holds for the saved lookups a relayed call names.
//!
//! The proxy reads saved policy rows, one-shot approvals and the cloud policy
//! bundle for every call (`policy_lookup_evidence`, `store_policy.py`). With
//! none of them, each lookup misses and the diagnostic has nothing to explain.
//! With saved rows the resident reads them itself, on one read-only snapshot,
//! with the integrity evidence the proxy would ship: the key and state the
//! daemon published, which the store must still hold, protected. Remote
//! rows need no more evidence than the proxy ships: the lookup never serves a
//! cloud-sync or team-policy row and verifies no remote row's integrity. A
//! cached policy bundle with a policy-bundle row to match, an integrity state other than the published
//! protected one, a newer or unknown schema, and a store it cannot read all
//! defer the call; a row bound to a portable identity defers every lookup but one whose
//! workspace resolves to that identity.

use crate::local_store_read::{
    open_read_only_cached, schema_version, table_exists, CachedConnection, STORE_FILE_NAME,
    SUPPORTED_SCHEMA_VERSION,
};
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) const STORE_UNREADABLE: &str = "mcp_relay_store_unreadable";
pub(super) const SAVED_REMOTE: &str = "mcp_relay_saved_remote_policy";
const SAVED_UNVERIFIABLE: &str = "mcp_relay_saved_policy_unverifiable";
/// The tables whose rows a lookup reads under a workspace.
const PORTABLE_TABLES: [&str; 2] = ["policy_decisions", "guard_local_once_approvals"];

/// `REMOTE_POLICY_SOURCES` (`policy_integrity.py`).
const REMOTE_SOURCES_SQL: &str = "('cloud-sync', 'team-policy', 'policy-bundle', \
     'policy-bundle-canonical', 'cloud-signed-memory')";

/// The guard store, read-only, at a schema the resident reads; `None` when
/// there is no store yet, so nothing is saved. A connection an earlier call
/// kept for the same file is reused; the schema is still read every call.
pub(super) fn open(guard_home: &Path) -> Result<Option<CachedConnection>, &'static str> {
    let Some(connection) =
        open_read_only_cached(&guard_home.join(STORE_FILE_NAME)).map_err(|_| STORE_UNREADABLE)?
    else {
        return Ok(None);
    };
    match schema_version(&connection).map_err(|_| STORE_UNREADABLE)? {
        Some(version) if version <= SUPPORTED_SCHEMA_VERSION => Ok(Some(connection)),
        _ => Err(STORE_UNREADABLE),
    }
}

/// The evidence `policy_lookup_evidence` ships for every lookup of one call,
/// on the snapshot the caller holds open.
pub(super) struct Saved<'c> {
    pub(super) connection: &'c Connection,
    pub(super) store_path: String,
    pub(super) guard_home: String,
    pub(super) now: String,
    /// A row from a local source: only then does the proxy ship the policy
    /// key and the refreshed integrity state.
    pub(super) has_local_policy: bool,
    pub(super) integrity_state: Value,
    pub(super) key_b64: Zeroizing<String>,
    pub(super) key_id: String,
    /// The tables holding a row bound to a portable identity.
    pub(super) portable_tables: Vec<&'static str>,
}

/// `None` when the store holds no saved row, so every lookup misses; the
/// saved-row evidence when the resident reads the rows as the proxy would;
/// a defer code for every other store.
pub(super) fn saved<'c>(
    connection: &'c Connection,
    binding: &DirectLaneBinding,
    guard_home: &str,
) -> Result<Option<Saved<'c>>, &'static str> {
    let shape = Shape { connection };
    // The bundle's decision identities come from a synced, signed payload
    // the resident does not validate. The lookup reads them only for a
    // policy-bundle row: with none, the proxy's identities change nothing.
    if shape.any(
        "policy_decisions",
        "select 1 from policy_decisions where source = 'policy-bundle'",
    )? && shape.any(
        "sync_state",
        "select 1 from sync_state where state_key = 'policy_bundle'",
    )? {
        return Err(SAVED_REMOTE);
    }
    let has_local_policy = shape.any(
        "policy_decisions",
        &format!("select 1 from policy_decisions where source not in {REMOTE_SOURCES_SQL}"),
    )?;
    let has_local_once = shape.any(
        "guard_local_once_approvals",
        "select 1 from guard_local_once_approvals",
    )?;
    let has_remote_policy = shape.any(
        "policy_decisions",
        &format!("select 1 from policy_decisions where source in {REMOTE_SOURCES_SQL}"),
    )?;
    if !has_local_policy && !has_remote_policy && !has_local_once {
        return Ok(None);
    }
    // A row bound to a portable identity is read only by a lookup whose
    // workspace the resident resolves to that identity.
    let mut portable_tables = Vec::new();
    for table in PORTABLE_TABLES {
        if shape.any(
            table,
            &format!("select 1 from {table} where workspace like 'git-project:v1:%'"),
        )? {
            portable_tables.push(table);
        }
    }
    let (integrity_state, key) = published_integrity(binding)?;
    if shape.stored_integrity_state()?.as_ref() != Some(&integrity_state) {
        return Err(SAVED_UNVERIFIABLE);
    }
    Ok(Some(Saved {
        connection,
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: guard_home.to_owned(),
        now: utc_now().ok_or(SAVED_UNVERIFIABLE)?,
        has_local_policy,
        integrity_state,
        key_b64: Zeroizing::new(Base64UrlUnpadded::encode_string(&key.key)),
        key_id: key.key_id.clone(),
        portable_tables,
    }))
}

/// The integrity state and key the daemon published, when they are the
/// protected, enforced, cut-over state its key signs.
pub(super) fn published_integrity(
    binding: &DirectLaneBinding,
) -> Result<
    (
        Value,
        &crate::policy_store::policy_store_direct_lane::DirectLaneIntegrityKey,
    ),
    &'static str,
> {
    let (Some(state), Some(key)) = (
        binding.policy_integrity_state.as_ref(),
        binding.integrity_key.as_ref(),
    ) else {
        return Err(SAVED_UNVERIFIABLE);
    };
    if state.enforcement != "enforce"
        || state.mode != "protected"
        || !state.cutover_complete
        || !state.degraded_reasons.is_empty()
        || state.generation.is_none()
        || state.key_id.as_deref() != Some(key.key_id.as_str())
    {
        return Err(SAVED_UNVERIFIABLE);
    }
    let state = serde_json::to_value(state).map_err(|_| SAVED_UNVERIFIABLE)?;
    Ok((state, key))
}

/// `_canonical_utc_timestamp(_now())`.
pub(super) fn utc_now() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    let now =
        crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")?;
    guard_contracts::canonical_utc_timestamp(&now)
}

struct Shape<'c> {
    connection: &'c Connection,
}

impl Shape<'_> {
    /// Whether `table` exists and `query` finds a row in it.
    fn any(&self, table: &str, query: &str) -> Result<bool, &'static str> {
        if !table_exists(self.connection, table).map_err(|_| STORE_UNREADABLE)? {
            return Ok(false);
        }
        self.connection
            .prepare_cached(&format!("{query} limit 1"))
            .and_then(|mut statement| statement.query_row([], |_| Ok(())))
            .optional()
            .map(|found| found.is_some())
            .map_err(|_| STORE_UNREADABLE)
    }

    fn stored_integrity_state(&self) -> Result<Option<Value>, &'static str> {
        if !table_exists(self.connection, "sync_state").map_err(|_| STORE_UNREADABLE)? {
            return Ok(None);
        }
        let stored: Option<String> = self
            .connection
            .query_row(
                "select payload_json from sync_state where state_key = 'policy_integrity'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| STORE_UNREADABLE)?;
        Ok(stored.and_then(|text| serde_json::from_str(&text).ok()))
    }
}

impl Saved<'_> {
    /// `policy_decision_lookup_request` for one non-consuming probe.
    pub(super) fn lookup_request(
        &self,
        probe: &Probe<'_>,
    ) -> guard_contracts::PolicyDecisionLookupRequestV1 {
        let policy_key = self.has_local_policy;
        guard_contracts::PolicyDecisionLookupRequestV1 {
            schema: guard_contracts::POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            store_path: self.store_path.clone(),
            guard_home: self.guard_home.clone(),
            harness: probe.harness.to_owned(),
            artifact_id: Some(probe.artifact_id.to_owned()),
            artifact_hash: probe.artifact_hash.map(str::to_owned),
            workspace: probe.workspace.map(str::to_owned),
            publisher: probe.publisher.map(str::to_owned),
            now: self.now.clone(),
            runtime_exact_match_context: probe.exact_match_context.map(str::to_owned),
            consume_one_shot: false,
            local_once_only: false,
            integrity_state: Some(if policy_key {
                self.integrity_state.clone()
            } else {
                json!({})
            }),
            integrity_key_b64: policy_key.then(|| self.key_b64.to_string()),
            integrity_key_id: policy_key.then(|| self.key_id.clone()),
            local_once_integrity_key_b64: Some(self.key_b64.to_string()),
            local_once_integrity_key_id: Some(self.key_id.clone()),
            policy_bundle_decision_identities: None,
            probe_groups: None,
        }
    }

    /// The evidence `approval_reuse_diagnostic` procures for the rows the
    /// resident names.
    pub(super) fn diagnostic_evidence(
        &self,
        policy: bool,
        local_once: bool,
    ) -> guard_contracts::ApprovalReuseDiagnosticEvidenceV1 {
        let key = || Some(self.key_b64.to_string());
        let key_id = || Some(self.key_id.clone());
        let mut evidence = guard_contracts::ApprovalReuseDiagnosticEvidenceV1::default();
        if policy {
            evidence.integrity_state = Some(self.integrity_state.clone());
            evidence.integrity_key_b64 = key();
            evidence.integrity_key_id = key_id();
        }
        if local_once {
            evidence.local_once_integrity_key_b64 = key();
            evidence.local_once_integrity_key_id = key_id();
        }
        evidence
    }
}

/// One probe's selectors.
pub(super) struct Probe<'a> {
    pub(super) harness: &'a str,
    pub(super) artifact_id: &'a str,
    pub(super) artifact_hash: Option<&'a str>,
    pub(super) workspace: Option<&'a str>,
    pub(super) publisher: Option<&'a str>,
    pub(super) exact_match_context: Option<&'a str>,
}
