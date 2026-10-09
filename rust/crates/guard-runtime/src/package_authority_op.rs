//! `PackageAuthority` resident ops — `PackageIntentParse`, `SupplyChainEval`,
//! and `PackageAuthorityDecide` dispatch evaluators plus the resident-side
//! seams they need.
//!
//! `ResidentSupplyChainStore` is the rusqlite-backed impl of
//! `guard_command::local_supply_chain::SupplyChainStore`, opening
//! `guard.db` under `guard_home` on demand and mirroring the Python
//! `GuardStore` SQL (`store_*.py`). `ResidentEvalDeps` satisfies the
//! `SupplyChainEvalDeps` seam traits, delegating to the ported
//! `guard_command` fns where they exist and returning the same fail-closed
//! `EvalError` the Python callers degrade on for the unported seams (HTTP
//! guard-sync, native archive inspection).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::{
    apply_stored_package_policy_override, resolve_package_firewall_entitlement,
    resolve_package_firewall_entitlement_with_refresh, ApprovalContextApi, CommandExecution,
    GuardConfig, LocalSupplyChainError, PackageEvalApi, PackageFirewallEntitlementApi,
    PackageIntentParserApi, PackageRequestEvaluation, PathSupportApi, PolicyDecisionLookup,
    RuntimeRunnerApi, SupplyChainStore,
};
use guard_command::package_intent_common::{
    build_package_request_artifact, resolve_path_within_workspace, GuardArtifact, PackageIntent,
};
use guard_command::package_intent_parser::parse_package_intent;
use guard_command::pep440::{SpecifierSet, Version};
use guard_command::supply_chain_bundle;
use guard_command::supply_chain_package_eval::{
    evaluate_package_request_artifact, CanonicalPackageIdentity as EvalCanonicalPackageIdentity,
    ConfigLoaderApi, EntitlementRefreshApi, EvalError, EvalResult, GuardSyncRequest,
    GuardSyncRunnerApi, JsSemverApi, LockfileParseApi, LockfileParseResult, ManifestDepsApi,
    NativeArchiveApi, PackageIdentityApi, RestrictedArchiveApi,
    RestrictedArchiveDownload as EvalRestrictedArchiveDownload, RestrictedArchiveDownloadResult,
    RestrictedArchiveFailure, RiskDetectApi, StoreExtrasApi, SupplyChainBundleApi,
    SupplyChainBundleResponse as EvalBundleResponse, SupplyChainEvalDeps, WorkspaceIoApi,
};
use guard_command::supply_chain_package_identity;
use guard_contracts::{
    ApplyStoredPackagePolicyRequestV1, ApplyStoredPackagePolicyResultV1,
    PackageAuthorityDecideRequestV1, PackageAuthorityDecideResultV1, PackageIntentParseRequestV1,
    PackageIntentParseResultV1, SupplyChainEvalRequestV1, SupplyChainEvalResultV1,
    PACKAGE_AUTHORITY_REQUEST_SCHEMA, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
// ---------------------------------------------------------------------------
// Shared result helpers
// ---------------------------------------------------------------------------

fn err_result(request_id: &str, request_sha256: &str, code: &str) -> Value {
    json!({
        "schema": PACKAGE_AUTHORITY_RESULT_SCHEMA,
        "request_id": request_id,
        "request_sha256": request_sha256,
        "status": "error",
        "code": code,
        "payload": Value::Null,
    })
}

/// Convert a rusqlite `types::Value` cell into the equivalent `serde_json`
/// value for `_row_to_payload`-style dict construction.
fn db_value_to_json(v: rusqlite::types::Value) -> Value {
    match v {
        rusqlite::types::Value::Null => Value::Null,
        rusqlite::types::Value::Integer(i) => Value::from(i),
        rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        rusqlite::types::Value::Text(t) => Value::String(t),
        rusqlite::types::Value::Blob(b) => Value::Array(b.into_iter().map(Value::from).collect()),
    }
}

/// Resolve `guard_home` to the canonical absolute path the scoped secret ref
/// is hashed from (`guard_home.expanduser().resolve()`), falling back to the
/// raw path when it does not exist yet.
fn resolve_runtime_home(guard_home: &Path) -> Option<PathBuf> {
    let resolved = std::fs::canonicalize(guard_home).unwrap_or_else(|_| guard_home.to_path_buf());
    Some(resolved)
}

fn reject_empty_resident_paths(
    request_id: &str,
    request_sha256: &str,
    store_path: &str,
    guard_home: &str,
) -> Option<Result<Vec<u8>, String>> {
    if !store_path.is_empty() && !guard_home.is_empty() {
        return None;
    }
    Some(
        serde_json::to_vec(&err_result(
            request_id,
            request_sha256,
            "native_package_authority_path_required",
        ))
        .map_err(|error| error.to_string()),
    )
}

fn eval_error_code(e: &EvalError) -> &'static str {
    match e {
        EvalError::Validation(_) => "validation",
        EvalError::NotFound(_) => "not_found",
        EvalError::Internal(_) => "internal",
        EvalError::HttpStatus(_, _) => "http_status",
    }
}

// ---------------------------------------------------------------------------
// ResidentSupplyChainStore — rusqlite impl of `SupplyChainStore`.
// ---------------------------------------------------------------------------

/// rusqlite-backed `SupplyChainStore`. Opens `store_path` per call so a
/// dropped connection never wedges the resident; SQL mirrors the Python
/// `store_*.py` bodies.
pub struct ResidentSupplyChainStore {
    store_path: PathBuf,
    guard_home: PathBuf,
}

impl ResidentSupplyChainStore {
    pub fn new(store_path: &Path, guard_home: &Path) -> Self {
        Self {
            store_path: store_path.to_path_buf(),
            guard_home: guard_home.to_path_buf(),
        }
    }

    fn conn(&self) -> Result<Connection, rusqlite::Error> {
        Connection::open(&self.store_path)
    }

    fn oauth_local_credentials(&self) -> Option<Value> {
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM sync_state \
                 WHERE state_key = 'oauth_local_credentials' LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// `store_oauth.py: get_oauth_local_credential_health` — derive the
    /// `state` field; delegates to the shared free fn so `ResidentStoreExtras`
    /// produces the identical result.
    fn oauth_local_credentials_state(&self) -> String {
        oauth_credential_state(&self.guard_home, self.oauth_local_credentials().as_ref())
    }

    /// `store_connect.py: get_latest_connect_state` — most-recent
    /// `guard_connect_states` row as a dict (request_id, sync_url,
    /// allowed_origin, status, milestone, reason, created_at, updated_at,
    /// expires_at, completed_at, proof).
    fn latest_connect_state(&self, now: &str) -> Option<Map<String, Value>> {
        let conn = self.conn().ok()?;
        let request_id: String = conn
            .query_row(
                "SELECT request_id FROM guard_connect_states                  ORDER BY updated_at DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok()?;
        self.connect_state(&conn, &request_id, now)
    }

    /// `store_connect.py: load_connect_state` — read one connect-state row and
    /// flip a still-waiting browser pairing to expired when past `expires_at`.
    fn connect_state(
        &self,
        conn: &Connection,
        request_id: &str,
        now: &str,
    ) -> Option<Map<String, Value>> {
        let mut stmt = conn
            .prepare(
                "SELECT request_id, sync_url, allowed_origin, status, milestone, reason,                         created_at, updated_at, expires_at, completed_at, proof_json                  FROM guard_connect_states WHERE request_id = ?1",
            )
            .ok()?;
        let mut rows = stmt.query([request_id]).ok()?;
        let row = rows.next().ok()??;
        let proof_raw: String = row.get(10).ok()?;
        let proof = serde_json::from_str::<Value>(&proof_raw)
            .ok()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        let get = |i: usize| -> Value {
            row.get::<_, Option<String>>(i)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        };
        let mut m = Map::new();
        m.insert("request_id".to_string(), get(0));
        m.insert("sync_url".to_string(), get(1));
        m.insert("allowed_origin".to_string(), get(2));
        m.insert("status".to_string(), get(3));
        m.insert("milestone".to_string(), get(4));
        m.insert("reason".to_string(), get(5));
        m.insert("created_at".to_string(), get(6));
        m.insert("updated_at".to_string(), get(7));
        m.insert("expires_at".to_string(), get(8));
        m.insert("completed_at".to_string(), get(9));
        m.insert("proof".to_string(), proof);
        // `load_connect_state` flips a still-waiting pairing to expired.
        if m.get("status").and_then(Value::as_str) == Some("waiting")
            && m.get("milestone").and_then(Value::as_str) == Some("waiting_for_browser")
        {
            let expires = m
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(guard_command::local_supply_chain::parse_timestamp);
            let now_ts = guard_command::local_supply_chain::parse_timestamp(now);
            if let (Some(e), Some(n)) = (expires, now_ts) {
                if e <= n {
                    let _ = conn.execute(
                        "UPDATE guard_connect_states                          SET status = 'expired', milestone = 'expired',                              reason = 'request_expired', updated_at = ?1                          WHERE request_id = ?2",
                        rusqlite::params![now, request_id],
                    );
                    m.insert("status".to_string(), Value::String("expired".into()));
                    m.insert("milestone".to_string(), Value::String("expired".into()));
                    m.insert(
                        "reason".to_string(),
                        Value::String("request_expired".into()),
                    );
                    m.insert("updated_at".to_string(), Value::String(now.into()));
                }
            }
        }
        Some(m)
    }

    /// `store_oauth.py: _guard_connect_state_requires_oauth`.
    fn connect_state_requires_oauth(latest_state: &Map<String, Value>) -> bool {
        let request_id = latest_state
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if request_id.trim().is_empty() {
            return false;
        }
        latest_state.get("status").and_then(Value::as_str) == Some("connected")
    }

    /// `store_oauth.py: _coerce_guard_connect_state_status` — rebuild the
    /// connect-state dict with a new status/milestone/reason, folding
    /// `sync_summary` into the proof. Does not persist (read path only).
    fn coerce_connect_state(
        state: Map<String, Value>,
        status: &str,
        milestone: &str,
        reason: Option<&str>,
        sync_summary: Option<&Map<String, Value>>,
        now: &str,
    ) -> Map<String, Value> {
        let mut proof = state
            .get("proof")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let synced_at = sync_summary
            .and_then(|s| s.get("synced_at"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if let Some(sa) = synced_at {
            proof.insert("first_synced_at".to_string(), Value::String(sa));
        } else {
            proof
                .entry("first_synced_at".to_string())
                .or_insert(Value::Null);
        }
        let receipts = sync_summary
            .and_then(|s| s.get("receipts_stored"))
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0);
        let existing_receipts = proof
            .get("receipts_stored")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        proof.insert(
            "receipts_stored".to_string(),
            Value::from(receipts.max(existing_receipts)),
        );
        let inventory = sync_summary
            .and_then(|s| s.get("inventory_tracked").or_else(|| s.get("inventory")))
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0);
        let existing_inventory = proof
            .get("inventory_items")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        proof.insert(
            "inventory_items".to_string(),
            Value::from(inventory.max(existing_inventory)),
        );
        if let Some(rsid) = sync_summary
            .and_then(|s| s.get("runtime_session_id"))
            .and_then(Value::as_str)
        {
            proof.insert(
                "runtime_session_id".to_string(),
                Value::String(rsid.to_owned()),
            );
        }
        if let Some(rat) = sync_summary
            .and_then(|s| s.get("runtime_session_synced_at"))
            .and_then(Value::as_str)
        {
            proof.insert(
                "runtime_session_synced_at".to_string(),
                Value::String(rat.to_owned()),
            );
        }
        proof
            .entry("pairing_completed_at".to_string())
            .or_insert_with(|| state.get("completed_at").cloned().unwrap_or(Value::Null));

        let mut m = Map::new();
        m.insert(
            "request_id".to_string(),
            state.get("request_id").cloned().unwrap_or(Value::Null),
        );
        m.insert(
            "sync_url".to_string(),
            state.get("sync_url").cloned().unwrap_or(Value::Null),
        );
        m.insert(
            "allowed_origin".to_string(),
            state.get("allowed_origin").cloned().unwrap_or(Value::Null),
        );
        m.insert("status".to_string(), Value::String(status.to_owned()));
        m.insert("milestone".to_string(), Value::String(milestone.to_owned()));
        m.insert(
            "reason".to_string(),
            reason
                .map(|r| Value::String(r.to_owned()))
                .unwrap_or(Value::Null),
        );
        m.insert(
            "created_at".to_string(),
            state.get("created_at").cloned().unwrap_or(Value::Null),
        );
        m.insert(
            "updated_at".to_string(),
            state
                .get("updated_at")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_owned()))
                .unwrap_or_else(|| Value::String(now.to_owned())),
        );
        m.insert(
            "expires_at".to_string(),
            state.get("expires_at").cloned().unwrap_or(Value::Null),
        );
        m.insert(
            "completed_at".to_string(),
            state
                .get("completed_at")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_owned()))
                .or_else(|| proof.get("pairing_completed_at").cloned())
                .unwrap_or(Value::Null),
        );
        m.insert("proof".to_string(), Value::Object(proof));
        m
    }

    /// `store_oauth.py: _allowed_origin_from_sync_url` — `scheme://netloc`.
    fn allowed_origin_from_sync_url(sync_url: &str) -> Option<String> {
        let (scheme, rest) = sync_url.split_once("://")?;
        if scheme.is_empty() {
            return None;
        }
        let netloc = rest.split('/').next().unwrap_or("");
        if netloc.is_empty() {
            return None;
        }
        Some(format!("{scheme}://{netloc}"))
    }

    /// `store_oauth.py: _hydrate_guard_connect_state_from_cloud_profile`.
    fn hydrate_connect_state_from_cloud_profile(
        latest_state: Option<Map<String, Value>>,
        cloud_profile: &Map<String, Value>,
        sync_summary: Option<&Map<String, Value>>,
        now: &str,
    ) -> Option<Map<String, Value>> {
        let sync_url = cloud_profile
            .get("sync_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let allowed_origin = Self::allowed_origin_from_sync_url(&sync_url);
        let milestone = if sync_summary.is_some() {
            "first_sync_succeeded"
        } else {
            "first_sync_pending"
        };
        let reason = if sync_summary.is_some() {
            Some("first_sync_succeeded")
        } else {
            Some("waiting_for_first_sync")
        };
        match latest_state {
            None => Some(Self::coerce_connect_state(
                {
                    let mut s = Map::new();
                    s.insert("request_id".to_string(), Value::Null);
                    s.insert("sync_url".to_string(), Value::String(sync_url));
                    s.insert(
                        "allowed_origin".to_string(),
                        allowed_origin
                            .clone()
                            .map(Value::String)
                            .unwrap_or(Value::Null),
                    );
                    s.insert("status".to_string(), Value::String("connected".into()));
                    s.insert(
                        "milestone".to_string(),
                        Value::String("first_sync_pending".into()),
                    );
                    s.insert(
                        "reason".to_string(),
                        Value::String("waiting_for_first_sync".into()),
                    );
                    s.insert("created_at".to_string(), Value::Null);
                    s.insert("updated_at".to_string(), Value::String(now.to_owned()));
                    s.insert("expires_at".to_string(), Value::Null);
                    s.insert("completed_at".to_string(), Value::Null);
                    s.insert("proof".to_string(), Value::Object(Map::new()));
                    s
                },
                "connected",
                milestone,
                reason,
                sync_summary,
                now,
            )),
            Some(state) => {
                // Keep persisted sync_url/allowed_origin when present, else
                // hydrate from the live cloud profile.
                let mut s = state;
                let existing_url = s
                    .get("sync_url")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned);
                s.insert(
                    "sync_url".to_string(),
                    Value::String(existing_url.unwrap_or(sync_url)),
                );
                let existing_origin = s
                    .get("allowed_origin")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned);
                s.insert(
                    "allowed_origin".to_string(),
                    Value::String(existing_origin.or(allowed_origin).unwrap_or_default()),
                );
                let status = s
                    .get("status")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .unwrap_or("connected")
                    .to_owned();
                let milestone_owned = s
                    .get("milestone")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| milestone.to_owned());
                let reason_owned = match s.get("reason") {
                    Some(Value::String(r)) => Some(r.clone()),
                    _ => reason.map(str::to_owned),
                };
                Some(Self::coerce_connect_state(
                    s,
                    &status,
                    &milestone_owned,
                    reason_owned.as_deref(),
                    sync_summary,
                    now,
                ))
            }
        }
    }

    /// `_row_to_payload` — map the raw column values to the request payload
    /// dict. The canonical-surface re-derivation is intentionally not ported
    /// here (no Rust `canonical_approval_surfaces`); the stored
    /// `policy_action`/`decision_v2_json`/`action_envelope_json` are emitted
    /// as persisted, and the JSON text columns are parsed to objects/arrays.
    fn approval_row_payload(cols: &[&str], vals: &[Value]) -> Value {
        let mut map = Map::new();
        for (k, v) in cols.iter().zip(vals.iter()) {
            map.insert(k.to_string(), v.clone());
        }
        let get = |m: &Map<String, Value>, k: &str| m.get(k).cloned().unwrap_or(Value::Null);
        // JSON-list columns -> arrays.
        for (src, dst) in [
            ("changed_fields_json", "changed_fields"),
            ("risk_signals_json", "risk_signals"),
            ("scanner_evidence_json", "scanner_evidence"),
        ] {
            let parsed = get(&map, src)
                .as_str()
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
                .filter(|v| v.is_array())
                .unwrap_or(Value::Array(Vec::new()));
            map.insert(dst.to_string(), parsed);
        }
        // JSON-object columns -> objects (or Null).
        for (src, dst) in [
            ("browser_intent_json", "browser_intent"),
            ("continuation_snapshot_json", "continuation_snapshot"),
            ("action_envelope_json", "action_envelope_json"),
            ("decision_v2_json", "decision_v2_json"),
        ] {
            let parsed = get(&map, src)
                .as_str()
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
                .unwrap_or(Value::Null);
            map.insert(dst.to_string(), parsed);
        }
        // Integer/bool normalizations.
        let dedupe = get(&map, "dedupe_count").as_i64().unwrap_or(1);
        map.insert("dedupe_count".to_string(), Value::from(dedupe));
        let watch = get(&map, "watch_only_observation").as_i64().unwrap_or(0) != 0;
        map.insert("watch_only_observation".to_string(), Value::from(watch));
        // display_status mirrors status; resolution_intent mirrors
        // resolution_action in Python.
        if let Some(st) = map.get("status").cloned() {
            map.insert("display_status".to_string(), st);
        }
        if let Some(ra) = map.get("resolution_action").cloned() {
            map.insert("resolution_intent".to_string(), ra);
        }
        Value::Object(map)
    }
}

/// `store_oauth.py: get_oauth_local_credential_health` — `healthy` only when the
/// oauth metadata is valid AND the referenced secret payload loads from the
/// secret store AND yields a valid local-credentials result; `not_configured`
/// when there is no payload; `degraded` on any earlier failure.
fn oauth_credential_state(guard_home: &Path, payload: Option<&Value>) -> String {
    let payload = match payload {
        Some(p) if p.is_object() => p,
        _ => return "not_configured".to_owned(),
    };
    let nonempty = |k: &str| {
        payload
            .get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    if nonempty("issuer").is_none() || nonempty("client_id").is_none() {
        return "degraded".to_owned();
    }
    let secret = match load_oauth_secret_payload(guard_home, payload) {
        Some(s) => s,
        None => return "degraded".to_owned(),
    };
    if valid_oauth_credentials_result(&secret) {
        "healthy".to_owned()
    } else {
        "degraded".to_owned()
    }
}

/// `_load_oauth_secret_payload` — resolve the scoped secret ref from
/// `credentials_ref` (falling back to the home-scoped default ref), read the
/// secret from the encrypted file store, and verify it against the record's
/// `credentials_sha256` (`store_base._secret_matches_hash`, all three accepted
/// prefixes). Bytes that no longer match the fingerprint they were stored with
/// are not usable, so the caller degrades instead of trusting them.
fn load_oauth_secret_raw(guard_home: &Path, payload: &Value) -> Option<String> {
    let resolved_home = resolve_runtime_home(guard_home)?;
    let default_ref = crate::policy_integrity_resolver::build_scoped_secret_ref(
        "guard-oauth-local-credentials",
        &resolved_home,
    );
    let secret_ref = payload
        .get("credentials_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .unwrap_or(default_ref);
    let mut store = crate::encrypted_secret_store::EncryptedFileSecretStore::new(&resolved_home);
    let raw = store.get_secret(&secret_ref)?;
    let expected = payload
        .get(crate::oauth_secret_authority::CREDENTIALS_HASH_KEY)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())?;
    crate::oauth_secret_authority::verified_secret_matches(&raw, expected)
        .ok()
        .filter(|matches| *matches)?;
    Some(raw)
}

/// `_load_oauth_secret_payload` — the parsed form of `load_oauth_secret_raw`.
fn load_oauth_secret_payload(guard_home: &Path, payload: &Value) -> Option<Value> {
    serde_json::from_str(&load_oauth_secret_raw(guard_home, payload)?).ok()
}

/// `_build_oauth_local_credentials_result` — a secret payload is usable only
/// when it carries a non-empty refresh token plus DPoP key material.
fn valid_oauth_credentials_result(secret: &Value) -> bool {
    let nonempty = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some()
    };
    nonempty(secret.get("refresh_token"))
        && nonempty(secret.get("dpop_private_key_pem"))
        && secret.get("dpop_public_jwk").is_some_and(Value::is_object)
        && nonempty(secret.get("dpop_public_jwk_thumbprint"))
}

impl SupplyChainStore for ResidentSupplyChainStore {
    fn guard_home(&self) -> &Path {
        &self.guard_home
    }

    fn get_cloud_sync_profile(&self) -> Option<Value> {
        // store_oauth.py: get_cloud_sync_profile reads oauth local credentials,
        // not a separate profile row. Python gates the profile on
        // `get_oauth_local_credential_health()["state"] == "healthy"` — a
        // caller must not learn a usable sync target while the local grant is
        // degraded or unverifiable.
        if self.oauth_local_credentials_state() != "healthy" {
            return None;
        }
        let payload = self.oauth_local_credentials()?;
        let nonempty = |k: &str| {
            payload
                .get(k)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
        };
        let issuer = nonempty("issuer")?;
        nonempty("client_id")?;
        let mut profile = serde_json::json!({
            "auth_mode": "oauth",
            "sync_url": format!("{}/api/guard/receipts/sync", issuer.trim_end_matches('/')),
        });
        if let Some(ws) = nonempty("workspace_id") {
            profile["workspace_id"] = Value::String(ws.to_owned());
        }
        Some(profile)
    }

    fn get_cloud_workspace_id(&self) -> Option<String> {
        // store_oauth.py: _cloud_workspace_id_from_connection
        let payload = self.oauth_local_credentials()?;
        payload
            .get("workspace_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }

    fn get_cached_supply_chain_bundle(&self, workspace_id: &str) -> Option<Value> {
        // store_supply_chain.py: get_supply_chain_bundle
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT response_json, cached_at FROM guard_supply_chain_bundle_cache \
                 WHERE workspace_id = ?1 LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt.query([workspace_id]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        let cached_at: String = row.get(1).ok()?;
        let mut payload: Value = serde_json::from_str(&raw).ok()?;
        let Value::Object(map) = &mut payload else {
            return None;
        };
        map.insert("cached_at".into(), Value::String(cached_at));
        Some(payload)
    }

    fn get_sync_payload(&self, key: &str) -> Option<Value> {
        // store_cloud_events.py: get_sync_payload — `sync_state` KV table,
        // keyed by `state_key`.
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare("SELECT payload_json FROM sync_state WHERE state_key = ?1 LIMIT 1")
            .ok()?;
        let mut rows = stmt.query([key]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn get_oauth_local_credential_health(&self) -> Option<Map<String, Value>> {
        // store_oauth.py: get_oauth_local_credential_health — derive the
        // record the same way `ResidentStoreExtras` does.
        let mut health = Map::new();
        let payload = self.oauth_local_credentials();
        let configured = payload.as_ref().is_some_and(Value::is_object);
        health.insert("configured".to_string(), Value::Bool(configured));
        health.insert(
            "backend".to_string(),
            Value::String("encrypted_file".to_string()),
        );
        health.insert(
            "state".to_string(),
            Value::String(oauth_credential_state(&self.guard_home, payload.as_ref())),
        );
        Some(health)
    }

    fn get_effective_guard_connect_state(&self, now: &str) -> Option<Value> {
        // store_oauth.py: get_effective_guard_connect_state — normalize the
        // persisted connect state against the live cloud profile + sync summary.
        let latest_state = self.latest_connect_state(now);
        let cloud_profile = self.get_cloud_sync_profile();
        let sync_summary = self
            .get_sync_payload("sync_summary")
            .and_then(|v| v.as_object().cloned());
        let latest_state = match cloud_profile.as_ref().and_then(Value::as_object) {
            None => {
                // No cloud profile: a connected state that requires OAuth is
                // coerced to retry_required; anything else is returned as-is.
                match latest_state {
                    Some(state) if Self::connect_state_requires_oauth(&state) => {
                        Some(Self::coerce_connect_state(
                            state,
                            "retry_required",
                            "first_sync_failed",
                            Some(
                                "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again.",
                            ),
                            sync_summary.as_ref(),
                            now,
                        ))
                    }
                    other => other,
                }
            }
            Some(profile) => {
                let normalized = Self::hydrate_connect_state_from_cloud_profile(
                    latest_state,
                    profile,
                    sync_summary.as_ref(),
                    now,
                )?;
                let status = normalized
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let milestone = normalized
                    .get("milestone")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let has_sync_summary = sync_summary.is_some();
                if has_sync_summary
                    && status != "retry_required"
                    && !matches!(milestone, "first_sync_failed" | "sync_not_available")
                {
                    Some(Self::coerce_connect_state(
                        normalized,
                        "connected",
                        "first_sync_succeeded",
                        Some("first_sync_succeeded"),
                        sync_summary.as_ref(),
                        now,
                    ))
                } else if matches!(status, "expired" | "waiting")
                    || matches!(milestone, "expired" | "waiting_for_browser")
                {
                    Some(Self::coerce_connect_state(
                        normalized,
                        "connected",
                        "first_sync_pending",
                        Some("waiting_for_first_sync"),
                        sync_summary.as_ref(),
                        now,
                    ))
                } else {
                    Some(normalized)
                }
            }
        };
        latest_state.map(Value::Object)
    }

    fn set_sync_payload(&self, key: &str, payload: &Value) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO sync_state (state_key, payload_json, updated_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(state_key) DO UPDATE SET \
                   payload_json = excluded.payload_json, \
                   updated_at = excluded.updated_at",
                rusqlite::params![key, body, guard_command::local_supply_chain::utc_now_iso()],
            );
        }
    }

    fn list_cached_advisories(&self) -> Vec<Value> {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn.prepare(
            "SELECT publisher_key, payload_json, updated_at FROM publisher_cache \
             ORDER BY updated_at DESC LIMIT 100",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten()
            .filter_map(|(cache_key, raw, updated_at)| {
                let mut payload = serde_json::from_str::<Value>(&raw).ok()?;
                let object = payload.as_object_mut()?;
                object.insert("cache_key".into(), Value::String(cache_key));
                object.insert("updated_at".into(), Value::String(updated_at));
                Some(payload)
            })
            .collect()
    }

    fn list_managed_installs(&self) -> Vec<Value> {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        // `store_cloud_events.py:list_managed_installs` — rows carry
        // `harness`, `active`, `workspace`, `manifest_json`, `updated_at`.
        let mut stmt = match conn.prepare(
            "SELECT harness, active, workspace, manifest_json, updated_at \
             FROM managed_installs ORDER BY harness ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten()
            .map(|(harness, active, workspace, manifest_json, updated_at)| {
                let manifest = serde_json::from_str::<Value>(&manifest_json).unwrap_or(Value::Null);
                serde_json::json!({
                    "harness": harness,
                    "active": active != 0,
                    "workspace": workspace,
                    "manifest": manifest,
                    "updated_at": updated_at,
                })
            })
            .collect()
    }

    fn record_latest_guard_connect_sync_result(
        &self,
        status: &str,
        milestone: &str,
        now: &str,
        reason: Option<&str>,
    ) {
        // store_oauth.py: record_latest_guard_connect_sync_result (no
        // request_id path). Find the most recent connect state that is
        // already `connected`, then persist the sync result back onto it.
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let request_id: Option<String> = conn
            .query_row(
                "SELECT request_id FROM guard_connect_states \
                 WHERE status IN ('connected', 'retry_required') \
                 ORDER BY updated_at DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        let request_id = match request_id {
            Some(id) => id,
            None => return,
        };
        // With no request_id Python only mutates a state that is still
        // `connected`; a `retry_required` row is returned unchanged.
        let current: Option<String> = conn
            .query_row(
                "SELECT status FROM guard_connect_states WHERE request_id = ?1",
                [&request_id],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        if current.as_deref() != Some("connected") {
            return;
        }
        let proof: String = conn
            .query_row(
                "SELECT proof_json FROM guard_connect_states WHERE request_id = ?1",
                [&request_id],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}))
            .to_string();
        let _ = conn.execute(
            "UPDATE guard_connect_states \
             SET status = ?1, milestone = ?2, reason = ?3, \
                 updated_at = ?4, proof_json = ?5 \
             WHERE request_id = ?6",
            rusqlite::params![status, milestone, reason, now, proof, request_id],
        );
    }

    fn get_approval_request(&self, request_id: &str) -> Option<Value> {
        // store_approvals.py: get_approval_request -> _row_to_payload reads the
        // real `approval_requests` row, not a serialized blob.
        let conn = self.conn().ok()?;
        let cols = [
            "request_id",
            "harness",
            "artifact_id",
            "artifact_name",
            "artifact_type",
            "artifact_hash",
            "publisher",
            "policy_action",
            "recommended_scope",
            "changed_fields_json",
            "source_scope",
            "oauth_source",
            "config_path",
            "workspace",
            "launch_target",
            "normalized_identity_key",
            "action_identity",
            "queue_group_id",
            "dedupe_count",
            "last_seen_at",
            "transport",
            "risk_summary",
            "risk_signals_json",
            "artifact_label",
            "source_label",
            "trigger_summary",
            "why_now",
            "launch_summary",
            "risk_headline",
            "action_envelope_json",
            "decision_v2_json",
            "fallback_cli_command",
            "raw_command_text",
            "continuation_snapshot_json",
            "guard_version",
            "first_seen_guard_version",
            "last_seen_guard_version",
            "watch_only_observation",
            "review_command",
            "approval_url",
            "status",
            "resolution_action",
            "resolution_scope",
            "reason",
            "created_at",
            "resolved_at",
            "scanner_evidence_json",
            "browser_intent_json",
        ];
        let sql = format!(
            "SELECT {} FROM approval_requests WHERE request_id = ?1 LIMIT 1",
            cols.join(", ")
        );
        let mut stmt = conn.prepare(&sql).ok()?;
        let row_values: Option<Vec<Value>> = stmt
            .query_row([request_id], |row| {
                let mut out = Vec::with_capacity(cols.len());
                for i in 0..cols.len() {
                    let v: rusqlite::types::Value = row.get(i)?;
                    out.push(db_value_to_json(v));
                }
                Ok(out)
            })
            .ok();
        let row_values = row_values?;
        Some(Self::approval_row_payload(&cols, &row_values))
    }

    fn resolve_policy_decision_lookup(
        &self,
        _harness: &str,
        artifact_id: &str,
        _artifact_hash: Option<&str>,
        _workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
        _consume_one_shot: bool,
    ) -> PolicyDecisionLookup {
        // store_policy.py: resolve_policy_decision_lookup — look up the
        // materialized decision row for the artifact.
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return PolicyDecisionLookup::default(),
        };
        // `_policy_row_payload` — project the `policy_decisions` columns into
        // the decision dict the callers inspect.
        let mut stmt = match conn.prepare(
            "SELECT harness, scope, artifact_id, artifact_hash, workspace, \
                    publisher, action, reason, owner, source, expires_at, \
                    policy_document_schema_version, policy_document_id, \
                    policy_document_digest, policy_rule_id, \
                    policy_provenance_json, updated_at \
             FROM policy_decisions \
             WHERE artifact_id = ?1 ORDER BY decision_id DESC LIMIT 1",
        ) {
            Ok(st) => st,
            Err(_) => return PolicyDecisionLookup::default(),
        };
        let decision = stmt
            .query_row([artifact_id], |row| {
                let mut map = Map::new();
                for (i, name) in [
                    "harness",
                    "scope",
                    "artifact_id",
                    "artifact_hash",
                    "workspace",
                    "publisher",
                    "action",
                    "reason",
                    "owner",
                    "source",
                    "expires_at",
                    "policy_document_schema_version",
                    "policy_document_id",
                    "policy_document_digest",
                    "policy_rule_id",
                    "policy_provenance_json",
                    "updated_at",
                ]
                .iter()
                .enumerate()
                {
                    let v: rusqlite::types::Value = row.get(i)?;
                    let jv = db_value_to_json(v);
                    // `policy_provenance_json` is stored as a JSON blob text —
                    // emit it parsed like the Python `_row_to_payload` does.
                    let jv = if *name == "policy_provenance_json" {
                        jv.as_str()
                            .and_then(|t| serde_json::from_str::<Value>(t).ok())
                            .unwrap_or(jv)
                    } else {
                        jv
                    };
                    map.insert(name.to_string(), jv);
                }
                Ok(Value::Object(map))
            })
            .ok();
        PolicyDecisionLookup {
            decision,
            ignored_local_integrity: None,
        }
    }

    fn approval_reuse_diagnostic(
        &self,
        _harness: &str,
        _artifact_id: &str,
        _artifact_hash: &str,
        _workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
    ) -> (Option<String>, Option<String>) {
        (None, None)
    }

    fn approval_reuse_claim_disposition(&self, decision: &Value) -> Option<String> {
        crate::claim_reuse::approval_reuse_claim_disposition(decision).map(str::to_owned)
    }

    fn claim_approval_reuse_decision(&self, decision: &Value, now: &str) -> bool {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        crate::claim_reuse::claim_approval_reuse_decisions(
            &conn,
            std::slice::from_ref(decision),
            Some(now),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or(false)
    }

    fn claim_local_once_approval(
        &self,
        approval_id: &str,
        claimed_at: &str,
        expected_decision: &Value,
    ) -> bool {
        let mut conn = match self.conn() {
            Ok(connection) => connection,
            Err(_) => return false,
        };
        let resolved_home =
            std::fs::canonicalize(&self.guard_home).unwrap_or_else(|_| self.guard_home.clone());
        let mut secret_store =
            crate::encrypted_secret_store::EncryptedFileSecretStore::new(&resolved_home);
        let (material, _) = crate::policy_integrity_resolver::resolve_integrity_state(
            &mut secret_store,
            &resolved_home,
        );
        let Some(material) = material else {
            return false;
        };
        let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(_) => return false,
        };
        let expected = if expected_decision.is_null() {
            None
        } else {
            Some(expected_decision)
        };
        let claimed = crate::local_once_store::claim_local_once_approval_by_id_locked(
            &tx,
            approval_id,
            claimed_at,
            expected,
            Some(material.raw_key.as_slice()),
            Some(material.key_id.as_str()),
            true,
        );
        let Ok(Some(decision)) = claimed else {
            return false;
        };
        let payload = serde_json::json!({
            "approval_id": decision.get("approval_id"),
            "request_id": decision.get("request_id"),
            "harness": decision.get("harness"),
            "artifact_id": decision.get("artifact_id"),
        });
        let body = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
        if tx
            .execute(
                "INSERT INTO guard_events (event_name, payload_json, occurred_at) VALUES (?1, ?2, ?3)",
                rusqlite::params!["approval.local_once_applied", body, claimed_at],
            )
            .is_err()
        {
            return false;
        }
        tx.commit().is_ok()
    }

    fn add_receipt(&self, receipt: &Value) {
        // store_receipts.py:add_receipt — persist into `runtime_receipts`,
        // not a serialized blob table. `receipt` is a `GuardReceipt.to_dict()`
        // value; list fields are re-serialized to their `*_json` columns.
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let g = |k: &str| receipt.get(k).cloned().unwrap_or(Value::Null);
        let txt = |k: &str| g(k).as_str().map(str::to_owned).unwrap_or_default();
        let opt = |k: &str| {
            receipt
                .get(k)
                .filter(|v| !v.is_null())
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let list_json = |k: &str| serde_json::to_string(&g(k)).unwrap_or_else(|_| "[]".into());
        let receipt_id = txt("receipt_id");
        let _ = conn.execute(
            "INSERT INTO runtime_receipts ( \
               receipt_id, harness, artifact_id, artifact_hash, policy_decision, \
               capabilities_summary, changed_capabilities_json, provenance_summary, \
               user_override, artifact_name, source_scope, scanner_evidence_json, \
               diff_summary, approval_source, approval_request_id, timestamp, \
               raw_command_text \
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            rusqlite::params![
                receipt_id,
                txt("harness"),
                txt("artifact_id"),
                txt("artifact_hash"),
                txt("policy_decision"),
                txt("capabilities_summary"),
                list_json("changed_capabilities"),
                txt("provenance_summary"),
                opt("user_override"),
                opt("artifact_name"),
                opt("source_scope"),
                list_json("scanner_evidence"),
                opt("diff_summary"),
                opt("approval_source"),
                opt("approval_request_id"),
                txt("timestamp"),
                opt("raw_command_text"),
            ],
        );
    }

    fn set_receipt_action_envelope(&self, receipt_id: &str, metadata: &Value) {
        // store_receipts.py:set_receipt_action_envelope — upsert into
        // `runtime_receipt_envelopes` (only when the receipt exists). The
        // canonical-rollup re-derivation isn't ported; `metadata` already
        // carries the caller's full/redacted envelope.
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM runtime_receipts WHERE receipt_id = ?1 LIMIT 1",
                [receipt_id],
                |_| Ok(()),
            )
            .is_ok();
        if !exists {
            return;
        }
        let full = serde_json::to_string(metadata).unwrap_or_else(|_| "null".into());
        let redacted = metadata
            .get("redacted")
            .cloned()
            .or_else(|| metadata.get("envelope_redacted").cloned())
            .unwrap_or_else(|| metadata.clone());
        let redacted = serde_json::to_string(&redacted).unwrap_or_else(|_| "null".into());
        let _ = conn.execute(
            "INSERT INTO runtime_receipt_envelopes \
               (receipt_id, envelope_full_json, envelope_redacted_json) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(receipt_id) DO UPDATE SET \
               envelope_full_json = excluded.envelope_full_json, \
               envelope_redacted_json = excluded.envelope_redacted_json",
            rusqlite::params![receipt_id, full, redacted],
        );
    }

    fn add_event(&self, kind: &str, payload: &Value, now: &str) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO guard_events (event_name, payload_json, occurred_at) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![kind, body, now],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ResidentEvalDeps — concrete `SupplyChainEvalDeps` impls.
// ---------------------------------------------------------------------------

/// Resident `.runtime.runner` guard-sync seam — owns the OAuth credential
/// read, DPoP proof signing (ES256/ring), origin-allowlist endpoint
/// validation, and the ureq-backed HTTPS transport with the Python retry
/// state machine (`_urlopen_with_sync_retries`). Token refresh is not yet
/// ported (stage B) — a cached-token-miss surfaces `EvalError::Validation`
/// (`GuardSyncAuthorizationExpiredError` mirror, fail-closed to `ask`).
///
/// `auth_context_override` is a test-only seam: when the originating Python
/// process is running under pytest (`PYTEST_CURRENT_TEST` set) and exports
/// `HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON`, `supply_chain_eval_native` forwards
/// the parsed dict on the request as `sync_auth_context_override`. Two forms:
///   * `{"sync_url": ..., "access_token": ...}` — used verbatim as the auth
///     context so the resident reaches the transport and surfaces
///     `cloud_http_error` rather than silently degrading;
///   * `{"error": "authorization_expired"}` — surfaces as
///     `EvalError::Validation`, which `evaluate_with_cloud` maps to the
///     `cloud_auth_error` fail-closed path (parity with
///     `GuardSyncAuthorizationExpiredError`).
struct ResidentGuardSyncRunner {
    auth_context_override: Option<Map<String, Value>>,
}

impl GuardSyncRunnerApi for ResidentGuardSyncRunner {
    fn resolve_guard_sync_auth_context(
        &self,
        store: &dyn SupplyChainStore,
        _allow_primary_repair: bool,
        force_refresh: bool,
    ) -> EvalResult<Map<String, Value>> {
        use guard_command::guard_sync_transport as gst;
        if let Some(override_ctx) = &self.auth_context_override {
            if override_ctx.get("error").and_then(Value::as_str) == Some("authorization_expired") {
                return Err(EvalError::Validation(
                    "guard sync authorization expired (test override)".into(),
                ));
            }
            let mut ctx = override_ctx.clone();
            if let Some(sync_url) = ctx.get("sync_url").and_then(Value::as_str) {
                let issuer = ctx.get("issuer").and_then(Value::as_str);
                ctx.insert(
                    "sync_url".to_owned(),
                    Value::String(
                        gst::validate_guard_sync_endpoint(sync_url, issuer)
                            .map_err(EvalError::Validation)?,
                    ),
                );
            }
            return Ok(ctx);
        }
        if let Some(mut env_ctx) = gst::test_sync_auth_context_from_env() {
            if let Some(sync_url) = env_ctx.get("sync_url").and_then(Value::as_str) {
                let issuer = env_ctx.get("issuer").and_then(Value::as_str);
                env_ctx.insert(
                    "sync_url".to_owned(),
                    Value::String(
                        gst::validate_guard_sync_endpoint(sync_url, issuer)
                            .map_err(EvalError::Validation)?,
                    ),
                );
            }
            return Ok(env_ctx);
        }
        // `_resolve_guard_sync_auth_context` (:4733) — read the stored OAuth
        // credentials through the scoped secret authority: metadata from the
        // `oauth_local_credentials` payload, secret material (refresh token,
        // DPoP key, cached access token) from the verified secret behind
        // `credentials_ref`. `store_oauth` never inlines the secret, so the
        // payload alone cannot start a sync. Token refresh (the network leg +
        // rotation persist) is still the stage-B port: a missing/expired token
        // surfaces `EvalError::Validation` (the
        // `GuardSyncAuthorizationExpiredError` mirror) so `_evaluate_with_cloud`
        // fail-closes to `ask` rather than mislabeling a refresh-needed
        // credential as `NotFound` ("not configured") and falling back to
        // local-only evaluation.
        // The writer replaces the secret before it republishes the record's
        // fingerprint, so a read landing inside that window can see a valid pair
        // torn apart and must not turn a healthy credential into a denial. One
        // re-read settles it; anything else fails closed.
        let mut attempt = 0_u8;
        let oauth_credentials = loop {
            attempt += 1;
            let payload = match store.get_sync_payload("oauth_local_credentials") {
                Some(payload) if payload.is_object() => payload,
                _ => return Err(EvalError::NotFound("Guard is not logged in.".to_owned())),
            };
            match crate::oauth_secret_authority::resolve_credentials(&payload, &|_| {
                load_oauth_secret_raw(store.guard_home(), &payload)
            }) {
                Ok(credentials) => break credentials,
                Err(reason)
                    if (reason == "credentials_secret_fingerprint_mismatch"
                        || reason == "credentials_secret_unavailable")
                        && attempt < 2 =>
                {
                    continue;
                }
                Err(reason) => return Err(EvalError::Validation(reason)),
            }
        };
        let issuer = oauth_credentials
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty());
        let client_id = oauth_credentials
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty());
        let refresh_token = oauth_credentials
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty());
        let (issuer, client_id, refresh_token) = match (issuer, client_id, refresh_token) {
            (Some(i), Some(c), Some(r)) => (i, c, r),
            _ => {
                return Err(EvalError::Validation(
                    "Guard OAuth credentials are incomplete; reauthorize Guard.".to_owned(),
                ))
            }
        };
        let dpop_key_material = gst::oauth_dpop_key_material(&oauth_credentials)?;
        // `(origin, authorize_url, token_endpoint, device_authorize_url,
        // jwks_url, client_id)` — `token_endpoint` is element 2.
        let oauth_client_config = gst::resolve_guard_oauth_client_config(issuer).map_err(|e| {
            EvalError::Validation(format!("Reconnect Guard to Guard Cloud to continue. {e}"))
        })?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let cached_access_token = if force_refresh {
            None
        } else {
            gst::cached_oauth_access_token(&oauth_credentials, now_unix)
        };
        let access_token = match cached_access_token {
            Some(t) => t,
            None => {
                // `runner.py` refresh leg — `_refresh_guard_oauth_access_token`:
                // circuit-checked, `invalid_grant`-retried, rotation-persisted
                // under `oauth-refresh.lock`. The reloader hands the loop the
                // latest stored credential when a peer rotated mid-flight.
                let store_ref = store;
                let refreshed = crate::oauth_refresh::refresh_oauth_access_token(
                    store,
                    &oauth_credentials,
                    &oauth_client_config.2,
                    client_id,
                    refresh_token,
                    &dpop_key_material,
                    &move || {
                        store_ref
                            .get_sync_payload("oauth_local_credentials")
                            .and_then(|payload| {
                                crate::oauth_secret_authority::resolve_credentials(
                                    &payload,
                                    &|_| {
                                        crate::package_authority_op::load_oauth_secret_raw(
                                            store_ref.guard_home(),
                                            &payload,
                                        )
                                    },
                                )
                                .ok()
                            })
                            .and_then(|creds| {
                                let rt = creds
                                    .get("refresh_token")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned)?;
                                let mat = gst::oauth_dpop_key_material(&creds).ok()?;
                                Some((rt, mat))
                            })
                    },
                );
                match refreshed {
                    Ok(auth) => auth.access_token,
                    Err(e) => return Err(e),
                }
            }
        };
        let sync_url = gst::validate_guard_sync_endpoint(
            &gst::oauth_sync_url_from_issuer(issuer).map_err(EvalError::Validation)?,
            Some(issuer),
        )
        .map_err(EvalError::Validation)?;
        let mut ctx = Map::new();
        ctx.insert("sync_url".to_owned(), Value::String(sync_url));
        ctx.insert("access_token".to_owned(), Value::String(access_token));
        ctx.insert(
            "dpop_key_material".to_owned(),
            Value::Object(dpop_key_material),
        );
        ctx.insert("issuer".to_owned(), Value::String(issuer.to_owned()));
        Ok(ctx)
    }
    fn validate_guard_sync_url(&self, sync_url: &str, issuer: Option<&str>) -> EvalResult<String> {
        guard_command::guard_sync_transport::validate_guard_sync_endpoint(sync_url, issuer)
            .map_err(EvalError::Validation)
    }
    fn guard_sync_request(
        &self,
        auth_context: &Value,
        request_url: &str,
        method: &str,
        data: Option<&[u8]>,
        extra_headers: Option<&Map<String, Value>>,
        dpop_nonce: Option<&str>,
    ) -> EvalResult<GuardSyncRequest> {
        guard_command::guard_sync_transport::guard_sync_request(
            auth_context,
            request_url,
            method,
            data,
            extra_headers,
            dpop_nonce,
        )
    }
    fn urlopen_json_with_timeout_retry(
        &self,
        request: &GuardSyncRequest,
        timeout_seconds: u64,
        retry_timeout_seconds: u64,
    ) -> EvalResult<Map<String, Value>> {
        let payload = guard_command::guard_sync_transport::urlopen_json_with_timeout_retry(
            request,
            timeout_seconds as f64,
            retry_timeout_seconds as f64,
        )?;
        match payload {
            Value::Object(map) => Ok(map),
            _ => Err(EvalError::Internal(
                "Guard Cloud sync returned an invalid response payload.".into(),
            )),
        }
    }
    fn is_timeout_error(&self, error: &(dyn std::error::Error + 'static)) -> bool {
        // `_is_timeout_error` (:4997) — urllib surfaces `TimeoutError`,
        // `URLError` with a `timeout` reason, and (rarely) `HTTPException`.
        // The transport folds all of those into `EvalError::Internal` with a
        // `timeout:` prefix.
        error
            .downcast_ref::<EvalError>()
            .is_some_and(|e| matches!(e, EvalError::Internal(m) if m.starts_with("timeout:")))
    }
    fn normalized_receipts_sync_url(&self, sync_url: &str) -> String {
        // `_normalized_receipts_sync_url` (:4927) — trailing `/`s trimmed,
        // the sync endpoint suffix stripped so error detail + nonce paths
        // compare origins.
        let trimmed = sync_url.trim_end_matches('/');
        let lower = trimmed.to_lowercase();
        if lower.ends_with("/api/guard/receipts/sync") {
            trimmed[..trimmed.len() - "/api/guard/receipts/sync".len()].to_owned()
        } else {
            trimmed.to_owned()
        }
    }
}

/// Lockfile parse seam — delegates to the ported
/// `package_manifest_diff::parse_manifest_dependencies` for formats with a
/// native parser; everything else returns `incomplete` like Python's
/// `incomplete_lockfile_result` degrade path.
struct ResidentLockfileParse;

impl LockfileParseApi for ResidentLockfileParse {
    fn collect_lockfile_parse_results(
        &self,
        workspace_dir: Option<&Path>,
        lockfile_paths: Option<&Value>,
        budget_ms: f64,
        parse_text_result: &dyn Fn(&str, &[u8]) -> LockfileParseResult,
    ) -> Vec<LockfileParseResult> {
        let mut results = Vec::new();
        let Some(ws) = workspace_dir else {
            return results;
        };
        let Some(Value::Array(paths)) = lockfile_paths else {
            return results;
        };
        for rel in paths.iter().filter_map(Value::as_str) {
            let Some(resolved) = resolve_path_within_workspace(ws, rel) else {
                results.push(self.incomplete_lockfile_result(
                    rel,
                    b"",
                    "path outside workspace",
                    budget_ms,
                    0.0,
                ));
                continue;
            };
            match std::fs::read(&resolved) {
                Ok(bytes) => results.push(parse_text_result(rel, &bytes)),
                Err(e) => results.push(self.incomplete_lockfile_result(
                    rel,
                    b"",
                    &format!("read failed: {e}"),
                    budget_ms,
                    0.0,
                )),
            }
        }
        results
    }

    fn parse_lockfile_with_budget(
        &self,
        path: &str,
        source_text: &[u8],
        budget_seconds: f64,
    ) -> LockfileParseResult {
        let text = String::from_utf8_lossy(source_text);
        let budget_ms = (budget_seconds * 1000.0).max(1.0);
        let map = guard_command::package_manifest_diff::parse_manifest_dependencies(
            path,
            &text,
            text.len(),
            budget_ms as u64,
        );
        if map.is_empty() {
            return self.incomplete_lockfile_result(
                path,
                source_text,
                "no parser produced entries",
                budget_ms,
                0.0,
            );
        }
        let entries = map
            .into_iter()
            .map(|(dependency_path, version)| {
                guard_command::supply_chain_package_eval::LockfileDependencyEntry {
                    dependency_path,
                    package_name: String::new(),
                    version,
                    direct: false,
                }
            })
            .collect();
        LockfileParseResult {
            entries,
            complete: true,
            format: Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned(),
            source_hash: guard_policy_snapshot::digest_bytes(source_text),
            elapsed_ms: 0.0,
            budget_ms,
            warnings: Vec::new(),
            error_reason: None,
            parser_version: "resident-lockfile-parse-v1".into(),
        }
    }

    fn incomplete_lockfile_result(
        &self,
        path: &str,
        source: &[u8],
        error_reason: &str,
        budget_ms: f64,
        elapsed_ms: f64,
    ) -> LockfileParseResult {
        LockfileParseResult {
            entries: Vec::new(),
            complete: false,
            format: Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned(),
            source_hash: if source.is_empty() {
                String::new()
            } else {
                guard_policy_snapshot::digest_bytes(source)
            },
            elapsed_ms,
            budget_ms,
            warnings: Vec::new(),
            error_reason: Some(error_reason.to_owned()),
            parser_version: "resident-lockfile-parse-v1".into(),
        }
    }
}

/// Bundle seam — delegates to `guard_command::supply_chain_bundle` loaders.
struct ResidentBundle;

impl SupplyChainBundleApi for ResidentBundle {
    fn load_supply_chain_bundle_response(
        &self,
        raw_json: &Value,
    ) -> EvalResult<EvalBundleResponse> {
        let resp = supply_chain_bundle::load_supply_chain_bundle_response(raw_json)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        Ok(EvalBundleResponse {
            bundle: resp
                .bundle
                .to_dict()
                .as_object()
                .cloned()
                .unwrap_or_default(),
            signed_bundle: resp.signed_bundle,
            payload_hash: resp.payload_hash,
            signature: resp.signature,
            signature_algorithm: resp.signature_algorithm,
            verification_keys: resp
                .verification_keys
                .iter()
                .filter_map(|k| k.to_dict().as_object().cloned())
                .collect(),
        })
    }

    fn check_supply_chain_bundle_freshness(
        &self,
        bundle: &Map<String, Value>,
        now: Option<f64>,
    ) -> EvalResult<()> {
        let parsed = supply_chain_bundle::SupplyChainBundle::from_dict(bundle)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        supply_chain_bundle::check_supply_chain_bundle_freshness(&parsed, now)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }

    fn evaluate_cached_supply_chain_bundle(
        &self,
        response: &EvalBundleResponse,
        package_name: &str,
        package_version: Option<&str>,
        ecosystem: Option<&str>,
        now: Option<f64>,
    ) -> EvalResult<Map<String, Value>> {
        let raw = response_to_bundle_json(response);
        let typed = supply_chain_bundle::load_supply_chain_bundle_response(&raw)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        let decision = supply_chain_bundle::evaluate_cached_supply_chain_bundle(
            &typed,
            package_name,
            package_version,
            ecosystem,
            now,
        );
        Ok(json!({
            "action": decision.action,
            "bundle_version": decision.bundle_version,
            "matched_advisory_ids": decision.matched_advisory_ids,
            "reason": decision.reason,
            "stale": decision.stale,
            "recommended_fix_version": decision.recommended_fix_version,
            "emergency_deny": decision.emergency_deny,
        })
        .as_object()
        .cloned()
        .unwrap_or_default())
    }

    fn supply_chain_bundle_meta(
        &self,
        bundle_payload: &Map<String, Value>,
    ) -> EvalResult<BTreeMap<String, String>> {
        let parsed = supply_chain_bundle::SupplyChainBundle::from_dict(bundle_payload)
            .map_err(|e| EvalError::Validation(e.to_string()))?;
        let mut out = BTreeMap::new();
        out.insert("bundle_version".into(), parsed.bundle_version);
        out.insert("feed_snapshot_hash".into(), parsed.feed_snapshot_hash);
        out.insert("policy_hash".into(), parsed.policy_hash);
        out.insert("scoring_version".into(), parsed.scoring_version);
        Ok(out)
    }
}

fn response_to_bundle_json(response: &EvalBundleResponse) -> Value {
    json!({
        "bundle": Value::Object(response.signed_bundle.clone()),
        "payloadHash": response.payload_hash,
        "signature": response.signature,
        "signatureAlgorithm": response.signature_algorithm,
        "verificationKeys": response
            .verification_keys
            .iter()
            .cloned()
            .map(Value::Object)
            .collect::<Vec<Value>>(),
    })
}

/// Native PEP 440 parsing and bounded npm selectors.
struct ResidentSemver;

impl JsSemverApi for ResidentSemver {
    fn specifier_set(&self, range: &str) -> EvalResult<SpecifierSet> {
        SpecifierSet::parse(range).map_err(EvalError::Validation)
    }
    fn version(&self, value: &str) -> EvalResult<Version> {
        Version::parse(value).map_err(EvalError::Validation)
    }
    fn version_in_specifier_set(&self, version: &Version, set: &SpecifierSet) -> bool {
        set.contains(version)
    }
    fn highest_js_version_for_selector(
        &self,
        versions: &[String],
        selector: &str,
    ) -> Option<String> {
        guard_command::js_semver::highest_js_version_for_selector(versions, selector)
            .map(str::to_owned)
    }
    fn version_matches_js_selector(&self, version: &str, selector: &str) -> bool {
        guard_command::js_semver::version_matches_js_selector(version, selector)
    }
}

/// Package risk detection delegates to the native supply-chain content rules.
struct ResidentRisk;

impl RiskDetectApi for ResidentRisk {
    fn detect_supply_chain_risk(
        &self,
        content: &str,
        _file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>> {
        guard_command::supply_chain_risk::detect_supply_chain_risk(content)
    }
    fn evaluate_supply_chain_risk_sync(
        &self,
        content: &str,
        _file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>> {
        guard_command::supply_chain_risk::detect_supply_chain_risk(content)
    }
}

/// Manifest seam — delegates to `package_manifest_diff::parse_manifest_dependencies`.
struct ResidentManifestDeps;

impl ManifestDepsApi for ResidentManifestDeps {
    fn dependency_map_for_path(
        &self,
        path: &str,
        text: &str,
        _deadline: f64,
    ) -> EvalResult<BTreeMap<String, String>> {
        Ok(
            guard_command::package_manifest_diff::parse_manifest_dependencies(
                path,
                text,
                text.len(),
                4000,
            ),
        )
    }

    fn parse_manifest_dependencies(
        &self,
        path: &str,
        text: &str,
        byte_limit: usize,
        deadline_ms: u64,
    ) -> BTreeMap<String, String> {
        guard_command::package_manifest_diff::parse_manifest_dependencies(
            path,
            text,
            byte_limit,
            deadline_ms,
        )
    }
}
/// Package-identity seam — delegates to `supply_chain_package_identity` fns.
struct ResidentPackageIdentity;

fn to_eval_identity(
    ident: supply_chain_package_identity::CanonicalPackageIdentity,
) -> EvalCanonicalPackageIdentity {
    EvalCanonicalPackageIdentity {
        ecosystem: ident.ecosystem,
        namespace: ident.namespace,
        name: ident.name,
        version: ident.version,
    }
}

impl PackageIdentityApi for ResidentPackageIdentity {
    fn canonical_package_identity(
        &self,
        ecosystem: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
    ) -> EvalResult<EvalCanonicalPackageIdentity> {
        supply_chain_package_identity::canonical_package_identity(
            ecosystem, namespace, name, version,
        )
        .map(to_eval_identity)
        .map_err(|e| EvalError::Validation(e.to_string()))
    }
    fn parse_package_identity(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> EvalResult<EvalCanonicalPackageIdentity> {
        supply_chain_package_identity::parse_package_identity(ecosystem, package_name, version)
            .map(to_eval_identity)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }
    fn normalize_ecosystem(&self, ecosystem: &str) -> EvalResult<String> {
        supply_chain_package_identity::normalize_ecosystem(ecosystem)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }
    fn normalize_qualified_package_name(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> EvalResult<String> {
        supply_chain_package_identity::normalize_qualified_package_name(ecosystem, package_name)
            .map_err(|e| EvalError::Validation(e.to_string()))
    }
}

/// Restricted-archive seam — bounded public-HTTPS-only acquisition via the
/// `guard_command::restricted_archive` policy engine over the ureq-backed
/// pinned transport.
struct ResidentRestrictedArchive;

impl RestrictedArchiveApi for ResidentRestrictedArchive {
    fn download_restricted_archive(
        &self,
        source_url: &str,
        max_bytes: u64,
        max_redirects: u32,
        timeout_seconds: f64,
        temp_dir: Option<&Path>,
    ) -> EvalResult<RestrictedArchiveDownloadResult> {
        let resolver = guard_command::restricted_archive_transport::SystemDnsResolver;
        let transport = guard_command::restricted_archive_transport::UreqPinnedTransport;
        Ok(
            match guard_command::restricted_archive::download_restricted_archive(
                source_url,
                max_bytes,
                max_redirects,
                timeout_seconds,
                temp_dir,
                &resolver,
                &transport,
            ) {
                guard_command::restricted_archive::RestrictedArchiveDownloadResult::Success(
                    blob,
                ) => RestrictedArchiveDownloadResult::Success(EvalRestrictedArchiveDownload {
                    path: blob.path,
                    sha256: blob.sha256,
                    size: blob.size,
                    source_url: blob.source_url,
                    final_url: blob.final_url,
                }),
                guard_command::restricted_archive::RestrictedArchiveDownloadResult::Failure(
                    failure,
                ) => RestrictedArchiveDownloadResult::Failure(RestrictedArchiveFailure {
                    code: failure.code,
                    message: failure.message,
                }),
            },
        )
    }
}

/// Native-archive inspection seam — delegated scanner not yet resident;
/// report unavailable so eval marks the archive uninspected.
struct ResidentNativeArchive;

impl NativeArchiveApi for ResidentNativeArchive {
    #[allow(clippy::too_many_arguments)]
    fn inspect_archive_native(
        &self,
        _path: &Path,
        _expected_sha256: &str,
        _state_dir: &Path,
        _timeout_seconds: f64,
        _max_archive_bytes: u64,
        _max_files: u64,
        _max_expanded_bytes: u64,
        _max_member_bytes: u64,
        _max_package_json_bytes: u64,
        _max_memory_bytes: u64,
        _max_decompression_ratio: f64,
        _max_nested_archives: u64,
        _max_path_depth: u64,
    ) -> EvalResult<Map<String, Value>> {
        Err(EvalError::Internal(
            "native archive inspection unavailable in resident".into(),
        ))
    }
}

/// Workspace IO — thin wrappers over `resolve_path_within_workspace` + `fs`.
struct ResidentWorkspaceIo;

impl WorkspaceIoApi for ResidentWorkspaceIo {
    fn read_text(&self, workspace_dir: &Path, relative_path: &str) -> Option<String> {
        std::fs::read_to_string(resolve_path_within_workspace(workspace_dir, relative_path)?).ok()
    }
    fn read_bytes_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<Vec<u8>> {
        std::fs::read(resolve_path_within_workspace(workspace_dir, relative_path)?).ok()
    }
}

/// Eval-cache / evidence / OAuth-health extras on the same `guard.db` conn.
struct ResidentStoreExtras {
    store_path: PathBuf,
    guard_home: PathBuf,
}

impl ResidentStoreExtras {
    fn conn(&self) -> Result<Connection, rusqlite::Error> {
        Connection::open(&self.store_path)
    }

    /// `oauth_local_credentials` sync_state payload (`state_key` =
    /// `oauth_local_credentials`); identical read to the supply-chain store.
    fn oauth_local_credentials(&self) -> Option<Value> {
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM sync_state \
                 WHERE state_key = 'oauth_local_credentials' LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        let row = rows.next().ok()??;
        let raw: String = row.get(0).ok()?;
        serde_json::from_str(&raw).ok()
    }
}

impl StoreExtrasApi for ResidentStoreExtras {
    fn get_cached_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
    ) -> Option<Map<String, Value>> {
        // store_supply_chain.py: get_supply_chain_evaluation
        let conn = self.conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT bundle_version, decision_json, updated_at \
                 FROM guard_supply_chain_eval_cache \
                 WHERE workspace_id = ?1 AND package_intent_hash = ?2 \
                 AND feed_snapshot_hash = ?3 AND policy_hash = ?4 \
                 AND scoring_version = ?5 AND bundle_version = ?6 LIMIT 1",
            )
            .ok()?;
        let mut rows = stmt
            .query(rusqlite::params![
                workspace_id,
                package_intent_hash,
                feed_snapshot_hash,
                policy_hash,
                scoring_version,
                bundle_version
            ])
            .ok()?;
        let row = rows.next().ok()??;
        let stored_bundle_version: String = row.get(0).ok()?;
        let raw: String = row.get(1).ok()?;
        let updated_at: String = row.get(2).ok()?;
        match serde_json::from_str::<Value>(&raw).ok()? {
            Value::Object(mut decision) => {
                decision.insert(
                    "bundle_version".into(),
                    Value::String(stored_bundle_version),
                );
                decision.insert("updated_at".into(), Value::String(updated_at));
                Some(decision)
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cache_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
        decision: &Map<String, Value>,
        now: &str,
    ) {
        if let Ok(conn) = self.conn() {
            let body = serde_json::to_string(&Value::Object(decision.clone()))
                .unwrap_or_else(|_| "{}".into());
            let _ = conn.execute(
                "INSERT INTO guard_supply_chain_eval_cache \
                 (workspace_id, package_intent_hash, feed_snapshot_hash, \
                  policy_hash, scoring_version, bundle_version, decision_json, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT(workspace_id, package_intent_hash, feed_snapshot_hash, \
                             policy_hash, scoring_version, bundle_version) \
                 DO UPDATE SET decision_json = excluded.decision_json, \
                               updated_at = excluded.updated_at",
                rusqlite::params![
                    workspace_id,
                    package_intent_hash,
                    feed_snapshot_hash,
                    policy_hash,
                    scoring_version,
                    bundle_version,
                    body,
                    now
                ],
            );
        }
    }

    fn add_evidence(&self, record: &Map<String, Value>) {
        // store_evidence.py:store_evidence — `insert or replace` into
        // `guard_evidence` real columns. `record` is the `EvidenceRecord` dict
        // the caller built; `details` serializes to `details_json`.
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let txt = |k: &str| {
            record
                .get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_default()
        };
        let confidence = record
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let details = record.get("details").cloned().unwrap_or(Value::Null);
        let details_json = serde_json::to_string(&details).unwrap_or_else(|_| "{}".into());
        let action_identity = record
            .get("action_identity")
            .filter(|v| !v.is_null())
            .and_then(Value::as_str)
            .map(str::to_owned);
        let _ = conn.execute(
            "INSERT OR REPLACE INTO guard_evidence \
               (evidence_id, action_id, request_id, harness, workspace, signal_id, \
                category, severity, confidence, summary, details_json, action_identity, \
                created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            rusqlite::params![
                txt("evidence_id"),
                txt("action_id"),
                txt("request_id"),
                txt("harness"),
                txt("workspace"),
                txt("signal_id"),
                txt("category"),
                txt("severity"),
                confidence,
                txt("summary"),
                details_json,
                action_identity,
                txt("created_at"),
            ],
        );
    }

    fn get_oauth_local_credential_health(&self) -> Map<String, Value> {
        // store_oauth.py:get_oauth_local_credential_health — the health record
        // is derived from the `oauth_local_credentials` sync_state payload plus
        // the secret store, not a cached `guard_oauth_metadata` row.
        let mut health = Map::new();
        let payload = self.oauth_local_credentials();
        let configured = payload.as_ref().is_some_and(Value::is_object);
        health.insert("configured".to_string(), Value::Bool(configured));
        health.insert(
            "backend".to_string(),
            Value::String("encrypted_file".to_string()),
        );
        let state = oauth_credential_state(&self.guard_home, payload.as_ref());
        health.insert("state".to_string(), Value::String(state));
        health
    }
}

/// Entitlement-refresh seam — `resolve_package_firewall_entitlement_with_refresh`
/// `.runtime.runner` seam for the resident edge. The resident has no
/// guard-cloud transport, so the sync/auth methods fail like the Python
/// `runner.GuardSyncNotAvailableError`/`OSError` path — `with_refresh` treats
/// them as non-fatal and still returns a freshly computed entitlement.
struct ResidentRuntimeRunner;

impl RuntimeRunnerApi for ResidentRuntimeRunner {
    fn resolve_guard_sync_auth_context(
        &self,
        store: &dyn SupplyChainStore,
    ) -> Result<Value, LocalSupplyChainError> {
        // `.runtime.runner` resolve delegates to the same resident
        // `GuardSyncRunnerApi` — the OAuth credential read + origin gate +
        // cached-token check live there. `EvalError` → `LocalSupplyChainError`
        // mapping: `NotFound` = `GuardSyncNotConfiguredError` (non-retryable
        // not-configured), `Validation` = `GuardSyncAuthorizationExpiredError`
        // (fail-closed auth-expired; still `retryable` at this seam so the
        // caller's `with_refresh` loop can retry once before surfacing).
        ResidentGuardSyncRunner {
            auth_context_override: None,
        }
        .resolve_guard_sync_auth_context(store, false, false)
        .map(Value::Object)
        .map_err(|e| match e {
            EvalError::NotFound(m) => LocalSupplyChainError::NotAvailable {
                message: m,
                retryable: false,
            },
            EvalError::Validation(m) => LocalSupplyChainError::NotAvailable {
                message: m,
                retryable: true,
            },
            other => LocalSupplyChainError::NotAvailable {
                message: other.to_string(),
                retryable: true,
            },
        })
    }
    fn sync_local_guard_cloud_proof(
        &self,
        _store: &dyn SupplyChainStore,
        _auth_context: Option<&Value>,
    ) -> Result<Value, LocalSupplyChainError> {
        Err(LocalSupplyChainError::NotAvailable {
            message: "guard-cloud sync unavailable in resident".into(),
            retryable: true,
        })
    }
    fn sync_supply_chain_bundle(
        &self,
        _store: &dyn SupplyChainStore,
        _auth_context: Option<&Value>,
    ) -> Result<Option<Value>, LocalSupplyChainError> {
        Err(LocalSupplyChainError::NotAvailable {
            message: "supply-chain bundle sync unavailable in resident".into(),
            retryable: true,
        })
    }
    fn guard_sync_headers(&self, auth_context: &Value) -> BTreeMap<String, String> {
        // `_guard_sync_headers` (:4783) without a request_url — the bundle
        // sync path only needs the Bearer + content-type set (no DPoP proof
        // is bound to a URL/method yet).
        let mut headers = BTreeMap::new();
        let access_token = auth_context
            .get("access_token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        headers.insert("Authorization".to_owned(), format!("Bearer {access_token}"));
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        headers.insert("Accept".to_owned(), "application/json".to_owned());
        headers.insert("User-Agent".to_owned(), "hol-guard-native".to_owned());
        headers
    }
    fn check_plan_restriction_403(&self, _status: u16, body: &str) -> (bool, String) {
        // `_check_plan_restriction_403` (:4955) — read the 403 body once,
        // prefer the `error`/`syncEnabled`/`code` fields, keyword-scan the
        // combined message+code for plan-restriction signals.
        const PLAN_403_KEYWORDS: &[&str] = &[
            "sync_not_available",
            "plan_restriction",
            "requires a pro",
            "requires a team",
            "upgrade your plan",
            "upgrade to",
            "subscription required",
            "not included in your plan",
            "guard sync requires",
        ];
        let fallback = {
            let trimmed = body.trim();
            if trimmed.is_empty() {
                "HTTP Error 403".to_owned()
            } else {
                trimmed.to_owned()
            }
        };
        let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(body) else {
            return (false, fallback);
        };
        let message_str = payload
            .get("error")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| fallback.clone());
        if payload.get("syncEnabled").and_then(Value::as_bool) == Some(false) {
            return (true, message_str);
        }
        let error_field = payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        let code_field = payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        let combined = format!("{error_field} {code_field}");
        if PLAN_403_KEYWORDS.iter().any(|kw| combined.contains(kw)) {
            return (true, message_str);
        }
        (false, message_str)
    }
    fn guard_cloud_http_error_details(&self, status: u16, body: &str) -> (String, bool) {
        // `_guard_cloud_http_error_details` (:2874) — retryable codes +
        // `guardError.retryable`/`guardError.code` signals, message preferring
        // the structured `guardError.message`/`error`/`message` field.
        let mut retryable = matches!(status, 429 | 503 | 524);
        let mut message: Option<String> = None;
        if let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(body) {
            for key in ["guardError", "error", "message"] {
                if let Some(s) = payload.get(key).and_then(Value::as_str).map(str::trim) {
                    if !s.is_empty() {
                        message = Some(s.to_owned());
                        break;
                    }
                }
                if let Some(inner) = payload.get(key).and_then(Value::as_object) {
                    if let Some(s) = inner.get("message").and_then(Value::as_str).map(str::trim) {
                        if !s.is_empty() {
                            message = Some(s.to_owned());
                            break;
                        }
                    }
                }
            }
            if let Some(guard_error) = payload.get("guardError").and_then(Value::as_object) {
                if guard_error.get("retryable").and_then(Value::as_bool) == Some(true) {
                    retryable = true;
                }
                if let Some(code) = guard_error.get("code").and_then(Value::as_str) {
                    let normalized = code.trim().to_lowercase();
                    if normalized == "guard_unavailable" || normalized == "guard_cloud_unavailable"
                    {
                        retryable = true;
                    }
                }
            }
        }
        let message = message.unwrap_or_else(|| {
            let trimmed = body.trim();
            if trimmed.is_empty() {
                format!("HTTP Error {status}")
            } else {
                trimmed.to_owned()
            }
        });
        (message, retryable)
    }
    fn sync_url_error_message(&self, error: &str) -> String {
        error.to_owned()
    }
    fn execute_package_command(
        &self,
        _command: &[String],
        _cwd: &Path,
        _environment: &BTreeMap<String, String>,
    ) -> Result<CommandExecution, String> {
        Err("package command execution unavailable in resident".into())
    }
}

/// `.package_firewall_entitlement` seam — read-only resolver + opportunistic
/// refresh. `resolve` is the store-reading port; `refresh` runs the
/// `with_refresh` heal loop (no-op in resident since the runner's sync always
/// fails, but the re-resolve still picks up any connect-state the store had).
struct ResidentPackageFirewallEntitlement;

impl PackageFirewallEntitlementApi for ResidentPackageFirewallEntitlement {
    fn resolve_package_firewall_entitlement(&self, store: &dyn SupplyChainStore) -> Value {
        Value::Object(resolve_package_firewall_entitlement(store))
    }
    fn refresh_package_firewall_entitlements(
        &self,
        store: &dyn SupplyChainStore,
        auth_context: Option<&Value>,
    ) -> Result<Value, LocalSupplyChainError> {
        let _ = auth_context;
        Ok(Value::Object(resolve_package_firewall_entitlement(store)))
    }
}

/// Entitlement-refresh seam — `resolve_package_firewall_entitlement_with_refresh`
/// now runs the real resolver over the resident store; the resident runner's
/// sync always fails so the refresh is a re-resolve, matching Python's
/// unavailable-transport path.
struct ResidentEntitlementRefresh {
    runner: ResidentRuntimeRunner,
    entitlement_api: ResidentPackageFirewallEntitlement,
    /// Test-only `package_entitlement_override` forwarded on the request when
    /// pytest exports `HOL_GUARD_TEST_PACKAGE_ENTITLEMENT_JSON`. Short-circuits
    /// the store read so the resident exercises the unpaid-entitlement
    /// fallback hermetically (parity with `_force_unpaid_entitlement`).
    entitlement_override: Option<Map<String, Value>>,
}

impl EntitlementRefreshApi for ResidentEntitlementRefresh {
    fn resolve_package_firewall_entitlement_with_refresh(
        &self,
        store: &dyn SupplyChainStore,
    ) -> EvalResult<Map<String, Value>> {
        if let Some(override_entitlement) = &self.entitlement_override {
            return Ok(override_entitlement.clone());
        }
        let value = resolve_package_firewall_entitlement_with_refresh(
            store,
            &self.runner,
            &self.entitlement_api,
        );
        value
            .as_object()
            .cloned()
            .ok_or_else(|| EvalError::Internal("entitlement resolution failed".into()))
    }
}

/// Config seam — `load_guard_config` is not ported; error → callers substitute
/// `GuardConfig::default()`, matching Python's missing-config path.
struct ResidentConfigLoader;

impl ConfigLoaderApi for ResidentConfigLoader {
    fn load_guard_config(
        &self,
        _guard_home: &Path,
        _workspace: Option<&Path>,
        _require_canonical_workspace: bool,
    ) -> EvalResult<GuardConfig> {
        Err(EvalError::Internal(
            "guard config loader unavailable in resident".into(),
        ))
    }
}

/// Aggregate `SupplyChainEvalDeps` wired to the resident impls.
pub struct ResidentEvalDeps {
    guard_sync: ResidentGuardSyncRunner,
    lockfile: ResidentLockfileParse,
    bundle: ResidentBundle,
    semver: ResidentSemver,
    risk: ResidentRisk,
    manifest: ResidentManifestDeps,
    identity: ResidentPackageIdentity,
    archive: ResidentRestrictedArchive,
    native_archive: ResidentNativeArchive,
    workspace_io: ResidentWorkspaceIo,
    store_extras: ResidentStoreExtras,
    entitlement: ResidentEntitlementRefresh,
    config: ResidentConfigLoader,
}

impl ResidentEvalDeps {
    pub fn new(store_path: &Path, guard_home: &Path) -> Self {
        Self::with_sync_auth_override(store_path, guard_home, None, None)
    }

    pub fn with_sync_auth_override(
        store_path: &Path,
        guard_home: &Path,
        auth_context_override: Option<Map<String, Value>>,
        entitlement_override: Option<Map<String, Value>>,
    ) -> Self {
        Self {
            guard_sync: ResidentGuardSyncRunner {
                auth_context_override,
            },
            lockfile: ResidentLockfileParse,
            bundle: ResidentBundle,
            semver: ResidentSemver,
            risk: ResidentRisk,
            manifest: ResidentManifestDeps,
            identity: ResidentPackageIdentity,
            archive: ResidentRestrictedArchive,
            native_archive: ResidentNativeArchive,
            workspace_io: ResidentWorkspaceIo,
            store_extras: ResidentStoreExtras {
                store_path: store_path.to_path_buf(),
                guard_home: guard_home.to_path_buf(),
            },
            entitlement: ResidentEntitlementRefresh {
                runner: ResidentRuntimeRunner,
                entitlement_api: ResidentPackageFirewallEntitlement,
                entitlement_override,
            },
            config: ResidentConfigLoader,
        }
    }

    pub fn as_deps(&self) -> SupplyChainEvalDeps<'_> {
        SupplyChainEvalDeps {
            guard_sync: &self.guard_sync,
            lockfile: &self.lockfile,
            bundle: &self.bundle,
            semver: &self.semver,
            risk: &self.risk,
            manifest: &self.manifest,
            identity: &self.identity,
            archive: &self.archive,
            native_archive: &self.native_archive,
            workspace_io: &self.workspace_io,
            store_extras: &self.store_extras,
            entitlement: &self.entitlement,
            config: &self.config,
        }
    }
}

// ---------------------------------------------------------------------------
// Op evaluators
// ---------------------------------------------------------------------------

fn request_digest<T: serde::Serialize>(request: &T) -> Result<String, String> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_package_authority_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_package_authority_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn string_environment(value: Option<&Value>) -> Option<BTreeMap<String, String>> {
    let Value::Object(object) = value? else {
        return None;
    };
    let mut environment = BTreeMap::new();
    for (key, item) in object {
        let Value::String(text) = item else {
            return None;
        };
        environment.insert(key.clone(), text.clone());
    }
    Some(environment)
}

/// `PackageIntentParse` — `parse_package_intent` port.
pub(crate) fn evaluate_package_intent_parse(
    request: &PackageIntentParseRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    let workspace = request.workspace.as_deref().map(Path::new);
    let home = request.home_dir.as_deref().map(Path::new);
    let environment = string_environment(request.environment.as_ref());
    let intent = parse_package_intent(
        &request.command_text,
        workspace,
        home,
        None,
        environment.as_ref(),
    );
    let (payload, runtime_private_metadata) = match intent {
        Some(intent) => {
            let mut private_metadata = Map::new();
            private_metadata.insert("command_tokens".to_owned(), json!(intent.command_tokens));
            private_metadata.insert(
                "package_targets".to_owned(),
                Value::Array(
                    intent
                        .targets
                        .iter()
                        .map(|target| target.to_execution_dict())
                        .collect(),
                ),
            );
            (intent.to_dict(), Some(Value::Object(private_metadata)))
        }
        None => (Value::Null, None),
    };
    let result = PackageIntentParseResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
        runtime_private_metadata,
    };
    crate::encode_response(&result)
}

// ---------------------------------------------------------------------------
// ApplyStoredPackagePolicy — `_apply_stored_package_policy_override` resident
// op. The override reads only `store` + `approval_context_api` live; the other
// seam params are parity placeholders carried through the ported signature.
// ---------------------------------------------------------------------------

/// `.approval_context` seam backed by the resident context-digest engine.
struct ResidentApprovalContext;

impl ApprovalContextApi for ResidentApprovalContext {
    fn parse_approval_context_token(&self, token: &Value) -> Option<Value> {
        let parsed = crate::context_digest::parse_context_token(token)?;
        Some(json!({
            "identity": parsed.identity,
            "content": parsed.content,
            "capabilities": parsed.capabilities,
            "policy": parsed.policy,
            "sandbox": parsed.sandbox,
        }))
    }
    fn approval_context_tokens_validation_reason(
        &self,
        saved_token: &Value,
        current_token: &Value,
    ) -> Option<String> {
        crate::context_digest::validate_context_tokens(saved_token, current_token)
    }
    fn build_approval_context_token(
        &self,
        identity: &Value,
        content: &Value,
        capabilities: &Value,
        policy: &Value,
        sandbox: &Value,
    ) -> String {
        // `extension_control_digest` is bound by the caller's snapshot; the
        // override path never builds tokens, so the empty digest is inert.
        let components = guard_contracts::ContextDigestComponentsV1 {
            identity: identity.clone(),
            content: content.clone(),
            capabilities: capabilities.clone(),
            policy: policy.clone(),
            sandbox: sandbox.clone(),
            extension_control_digest: String::new(),
        };
        crate::context_digest::build_context_token(&components).unwrap_or_default()
    }
    fn saved_allow_context_validation_reason(
        &self,
        decision: &Value,
        artifact_hash: &str,
    ) -> Option<String> {
        if decision.get("action").and_then(Value::as_str) != Some("allow") {
            return None;
        }
        self.approval_context_tokens_validation_reason(
            decision.get("artifact_hash").unwrap_or(&Value::Null),
            &Value::String(artifact_hash.to_string()),
        )
    }
}

/// Unused-in-override intent parser; satisfies the trait for the ported sig.
struct ResidentIntentParser;

impl PackageIntentParserApi for ResidentIntentParser {
    fn parse_package_intent(
        &self,
        command: &str,
        workspace: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Option<PackageIntent> {
        parse_package_intent(command, Some(workspace), None, None, Some(environment))
    }
}

/// Unused-in-override eval seam; the override never re-evaluates the package.
struct ResidentPackageEval;

impl PackageEvalApi for ResidentPackageEval {
    fn evaluate_package_request_artifact(
        &self,
        _artifact: &GuardArtifact,
        _store: &dyn SupplyChainStore,
        _workspace_dir: &Path,
        _now: &str,
        _external_archive_network_authorized: bool,
        _retain_external_archive_blob: bool,
    ) -> Result<PackageRequestEvaluation, String> {
        Err("resident_apply_stored_package_policy_no_eval".to_string())
    }
    fn supply_chain_user_copy(
        &self,
        title: &str,
        summary: &str,
        next_step: Option<&str>,
        dashboard_url: Option<&str>,
        harness_message: Option<&str>,
    ) -> Map<String, Value> {
        let mut copy = Map::new();
        copy.insert("title".into(), Value::String(title.to_string()));
        copy.insert("summary".into(), Value::String(summary.to_string()));
        copy.insert(
            "next_step".into(),
            next_step.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        copy.insert(
            "dashboard_url".into(),
            dashboard_url.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        copy.insert(
            "harness_message".into(),
            harness_message.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        copy
    }
}

/// Unused-in-override path seam; the override never reads workspace files.
struct ResidentPaths;

impl PathSupportApi for ResidentPaths {
    fn resolve_path_within_allowed_roots(
        &self,
        _candidate: &Path,
        _allowed_roots: &[PathBuf],
        _require_exists: bool,
    ) -> Option<PathBuf> {
        None
    }
    fn resolves_within_root(&self, _root: &Path, _candidate: &Path, _require_exists: bool) -> bool {
        false
    }
    fn read_text_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<String> {
        let resolved = resolve_path_within_workspace(workspace_dir, relative_path)?;
        if !resolved.is_file() {
            return None;
        }
        std::fs::read_to_string(resolved).ok()
    }
    fn read_bytes_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<Vec<u8>> {
        let resolved = resolve_path_within_workspace(workspace_dir, relative_path)?;
        if !resolved.is_file() {
            return None;
        }
        std::fs::read(resolved).ok()
    }
}

/// `ApplyStoredPackagePolicy` — `_apply_stored_package_policy_override` port.
pub(crate) fn evaluate_apply_stored_package_policy(
    request: &ApplyStoredPackagePolicyRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    if let Some(rejected) = reject_empty_resident_paths(
        &request.request_id,
        &request_sha256,
        &request.store_path,
        &request.guard_home,
    ) {
        return rejected;
    }
    let store_path = PathBuf::from(&request.store_path);
    let guard_home = PathBuf::from(&request.guard_home);
    let store = ResidentSupplyChainStore::new(&store_path, &guard_home);
    let mut artifact = artifact_from_value(&request.artifact);
    if let Some(meta) = request.runtime_private_metadata.clone() {
        artifact.runtime_private_metadata = meta;
    }
    let evaluation = PackageRequestEvaluation {
        value: request.evaluation.clone(),
    };
    let workspace_dir = PathBuf::from(&request.workspace_dir);
    let result = apply_stored_package_policy_override(
        &evaluation,
        &store,
        &artifact,
        &request.artifact_hash,
        &workspace_dir,
        &request.now,
        None,
        request.current_action.as_ref(),
        request.claim_saved_approval,
        &ResidentIntentParser,
        &ResidentPackageEval,
        &ResidentPaths,
        &ResidentApprovalContext,
    );
    let payload = ApplyStoredPackagePolicyResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_string(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_string(),
        code: "ok".to_string(),
        payload: Some(result.value),
    };
    crate::encode_response(&payload)
}

/// `SupplyChainEval` — `evaluate_package_request_artifact` port.
pub(crate) fn evaluate_supply_chain_eval(
    request: &SupplyChainEvalRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    if let Some(rejected) = reject_empty_resident_paths(
        &request.request_id,
        &request_sha256,
        &request.store_path,
        &request.guard_home,
    ) {
        return rejected;
    }
    let store_path = PathBuf::from(&request.store_path);
    let guard_home = PathBuf::from(&request.guard_home);
    let store = ResidentSupplyChainStore::new(&store_path, &guard_home);
    let test_overrides = std::env::var_os("HOL_GUARD_RESIDENT_TEST_SEAMS").is_some();
    let deps_holder = ResidentEvalDeps::with_sync_auth_override(
        &store_path,
        &guard_home,
        request
            .sync_auth_context_override
            .as_ref()
            .filter(|_| test_overrides)
            .and_then(Value::as_object)
            .cloned(),
        request
            .package_entitlement_override
            .as_ref()
            .filter(|_| test_overrides)
            .and_then(Value::as_object)
            .cloned(),
    );
    let deps = deps_holder.as_deps();
    let mut artifact = artifact_from_value(&request.artifact);
    if let Some(private) = &request.runtime_private_metadata {
        artifact.runtime_private_metadata = private.clone();
    }
    let workspace = request.workspace_dir.as_deref().map(Path::new);
    let result = match evaluate_package_request_artifact(
        &artifact,
        &store,
        &deps,
        workspace,
        request.now.as_deref(),
        request.external_archive_network_authorized,
        request.retain_external_archive_blob,
    ) {
        Ok(eval) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            payload: Some(eval.to_dict()),
        },
        Err(e) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: format!("native_supply_chain_eval_failed:{}", eval_error_code(&e)),
            payload: None,
        },
    };
    crate::encode_response(&result)
}

/// `PackageAuthorityDecide` — parse → artifact → eval in one call.
pub(crate) fn evaluate_package_authority_decide(
    request: &PackageAuthorityDecideRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    if let Some(rejected) = reject_empty_resident_paths(
        &request.request_id,
        &request_sha256,
        &request.store_path,
        &request.guard_home,
    ) {
        return rejected;
    }
    let workspace = request.workspace_dir.as_deref().map(Path::new);
    let intent = match parse_package_intent(&request.command_text, workspace, None, None, None) {
        Some(i) => i,
        None => {
            let result = PackageAuthorityDecideResultV1 {
                schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256,
                status: "ok".to_owned(),
                code: "no_intent".to_owned(),
                payload: None,
            };
            return crate::encode_response(&result);
        }
    };
    // `local_supply_chain.py:_workspace_local_evaluation` — the authority
    // path always builds the package request artifact with the canonical
    // config path + project scope; `artifact_type` is a label, not the scope.
    let artifact = build_package_request_artifact(
        &request.artifact_kind,
        &intent,
        "hol-guard.toml",
        "project",
    );
    let store_path = PathBuf::from(&request.store_path);
    let guard_home = PathBuf::from(&request.guard_home);
    let store = ResidentSupplyChainStore::new(&store_path, &guard_home);
    let deps_holder = ResidentEvalDeps::new(&store_path, &guard_home);
    let deps = deps_holder.as_deps();
    let result = match evaluate_package_request_artifact(
        &artifact,
        &store,
        &deps,
        workspace,
        request.now.as_deref(),
        request.external_archive_network_authorized,
        request.retain_external_archive_blob,
    ) {
        Ok(eval) => PackageAuthorityDecideResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            payload: Some(json!({
                "intent": intent.to_dict(),
                "artifact": artifact.to_dict(),
                "evaluation": eval.to_dict(),
                "policy_action": eval.policy_action,
                "decision": eval.decision,
            })),
        },
        Err(e) => PackageAuthorityDecideResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: format!(
                "native_package_authority_decide_failed:{}",
                eval_error_code(&e)
            ),
            payload: None,
        },
    };
    crate::encode_response(&result)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Reconstruct a `GuardArtifact` from the wire dict (`{artifact_id, name,
/// harness, artifact_type, source_scope, config_path, command, args, url,
/// transport, publisher, metadata}`).
fn artifact_from_value(v: &Value) -> GuardArtifact {
    let get_str = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let get_opt = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
    };
    GuardArtifact {
        artifact_id: get_str("artifact_id"),
        name: get_str("name"),
        harness: get_str("harness"),
        artifact_type: get_str("artifact_type"),
        source_scope: get_str("source_scope"),
        config_path: get_str("config_path"),
        command: get_opt("command"),
        args: v
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        url: get_opt("url"),
        transport: get_opt("transport"),
        publisher: get_opt("publisher"),
        metadata: v.get("metadata").cloned().unwrap_or(Value::Null),
        runtime_private_metadata: Value::Null,
    }
}

pub(crate) fn evaluate_package_advisory_ids(
    request: &guard_contracts::PackageAdvisoryIdsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_advisory_schema_mismatch".into());
    }
    if let Some(rejected) = reject_empty_resident_paths(
        &request.request_id,
        &request_sha256,
        &request.store_path,
        &request.guard_home,
    ) {
        return rejected;
    }
    let artifact = artifact_from_value(&request.artifact);
    let identities: Vec<Value> =
        guard_command::target_identities::package_target_identities(&artifact)
            .iter()
            .map(|identity| Value::Object(identity.to_dict()))
            .collect();
    let model = guard_command::target_identities::NativeAdvisoryModel;
    let connection = rusqlite::Connection::open_with_flags(
        &request.store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "native_package_advisory_store_unavailable".to_owned())?;
    let mut statement = connection
        .prepare("SELECT payload_json FROM publisher_cache ORDER BY updated_at DESC")
        .map_err(|_| "native_package_advisory_store_unavailable".to_owned())?;
    let mut rows = statement
        .query([])
        .map_err(|_| "native_package_advisory_store_unavailable".to_owned())?;
    let mut matched_ids = std::collections::BTreeSet::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| "native_package_advisory_store_unavailable".to_owned())?
    {
        let raw = row
            .get_ref(0)
            .map_err(|_| "native_package_advisory_cache_invalid".to_owned())?;
        let rusqlite::types::ValueRef::Text(raw) = raw else {
            return Err("native_package_advisory_cache_invalid".to_owned());
        };
        let mut advisory: Value = serde_json::from_slice(raw)
            .map_err(|_| "native_package_advisory_cache_invalid".to_owned())?;
        if !advisory.is_object() {
            continue;
        }
        if identities.iter().any(|identity| {
            guard_command::local_supply_chain::AdvisoryModelApi::advisory_matches_target(
                &model, &advisory, identity,
            )
        }) {
            if let Some(Value::String(id)) =
                advisory.as_object_mut().and_then(|row| row.remove("id"))
            {
                if !id.is_empty() {
                    matched_ids.insert(id);
                }
            }
        }
    }
    let mut payload = Map::new();
    payload.insert(
        "matched_advisory_ids".into(),
        Value::Array(matched_ids.into_iter().map(Value::String).collect()),
    );
    serde_json::to_vec(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".into(),
        code: "ok".into(),
        payload: Some(Value::Object(payload)),
    })
    .map_err(|_| "native_package_advisory_result_invalid".to_owned())
}

#[cfg(test)]
mod package_advisory_tests {
    use super::*;

    struct CacheFixture {
        home: PathBuf,
        connection: Option<rusqlite::Connection>,
    }

    impl CacheFixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let home = std::env::temp_dir().join(format!(
                "hol-guard-package-advisory-{}-{nonce}",
                std::process::id(),
            ));
            std::fs::create_dir_all(&home).unwrap();
            let connection = rusqlite::Connection::open(home.join("guard.db")).unwrap();
            connection.execute_batch(
                "CREATE TABLE publisher_cache (publisher_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
            ).unwrap();
            Self {
                home,
                connection: Some(connection),
            }
        }

        fn request(&self) -> guard_contracts::PackageAdvisoryIdsRequestV1 {
            guard_contracts::PackageAdvisoryIdsRequestV1 {
                schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.into(),
                request_id: "package-policy-feed".into(),
                store_path: self.home.join("guard.db").to_string_lossy().into_owned(),
                guard_home: self.home.to_string_lossy().into_owned(),
                artifact: json!({
                    "artifact_id":"command:install",
                    "metadata":{"targets":[{"ecosystem":"npm","package_name":"@scope/résumé","requested_specifier":"2.0"}]}
                }),
            }
        }
    }

    impl Drop for CacheFixture {
        fn drop(&mut self) {
            drop(self.connection.take());
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    #[test]
    fn package_advisory_scan_includes_old_rows_and_deduplicates_matching_ids() {
        let mut fixture = CacheFixture::new();
        let transaction = fixture.connection.as_mut().unwrap().transaction().unwrap();
        for index in 0..150 {
            let advisory = if index == 0 || index == 149 {
                json!({"id":"older-risk","package_url":"pkg:npm/@scope/résumé@1.0"})
            } else {
                json!({"id":format!("unrelated-{index}"),"package":"not-the-target"})
            };
            transaction
                .execute(
                    "INSERT INTO publisher_cache VALUES (?1, ?2, ?3)",
                    rusqlite::params![
                        index.to_string(),
                        advisory.to_string(),
                        format!("{index:03}")
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        let result: Value =
            serde_json::from_slice(&evaluate_package_advisory_ids(&fixture.request()).unwrap())
                .unwrap();
        assert_eq!(
            result["payload"]["matched_advisory_ids"],
            json!(["older-risk"])
        );
        fixture
            .connection
            .as_ref()
            .unwrap()
            .execute(
                "DELETE FROM publisher_cache WHERE publisher_key = '149'",
                [],
            )
            .unwrap();
        let result: Value =
            serde_json::from_slice(&evaluate_package_advisory_ids(&fixture.request()).unwrap())
                .unwrap();
        assert_eq!(
            result["payload"]["matched_advisory_ids"],
            json!(["older-risk"])
        );
    }

    #[test]
    fn package_advisory_scan_fails_closed_on_corrupt_or_missing_cache() {
        let fixture = CacheFixture::new();
        fixture
            .connection
            .as_ref()
            .unwrap()
            .execute(
                "INSERT INTO publisher_cache VALUES ('broken', '{', '2026')",
                [],
            )
            .unwrap();
        assert_eq!(
            evaluate_package_advisory_ids(&fixture.request()).unwrap_err(),
            "native_package_advisory_cache_invalid",
        );
        let mut request = fixture.request();
        request.store_path = fixture
            .home
            .join("missing.db")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            evaluate_package_advisory_ids(&request).unwrap_err(),
            "native_package_advisory_store_unavailable",
        );
        assert!(!fixture.home.join("missing.db").exists());
    }
}

#[cfg(test)]
#[path = "apply_stored_package_policy_tests.rs"]
mod apply_stored_package_policy_tests;
