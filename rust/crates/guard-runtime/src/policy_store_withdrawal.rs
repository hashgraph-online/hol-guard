//! Authenticated authority controls; these operations supply no policy decision.

use super::policy_store_mutation::{acquire_writer, refresh_floor, DurableAuthority};
use super::*;
use guard_policy_snapshot::canonical_json_bytes;

const WITHDRAWAL_SCHEMA: &str = "guard-policy-snapshot-withdrawal.v1";
const WITHDRAWAL_DOMAIN: &[u8] = b"hol-guard-policy-snapshot-withdrawal-v1\0";
const OBSERVATION_SCHEMA: &str = "guard-policy-snapshot-observation.v1";
const OBSERVATION_DOMAIN: &[u8] = b"hol-guard-policy-snapshot-observation-v1\0";
const OBSERVATION_RESPONSE_DOMAIN: &[u8] = b"hol-guard-policy-snapshot-observation-response-v1\0";
const WITHDRAWAL_RESPONSE_DOMAIN: &[u8] = b"hol-guard-policy-snapshot-withdrawal-response-v1\0";

pub(crate) fn is_control_error(code: &str) -> bool {
    matches!(
        code,
        "native_policy_snapshot_control_invalid"
            | "native_policy_snapshot_control_bounds_exceeded"
            | "native_policy_snapshot_control_noncanonical"
            | "native_policy_snapshot_observation_invalid"
            | "native_policy_snapshot_observation_unauthenticated"
            | "native_policy_snapshot_withdrawal_invalid"
            | "native_policy_snapshot_withdrawal_unauthenticated"
            | "native_policy_snapshot_withdrawal_stale"
            | "native_policy_snapshot_writer_busy"
            | "native_policy_snapshot_durable_authority_changed"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationIntent {
    schema: String,
    runtime_identity: String,
    scope_digest: String,
    nonce: String,
}

fn signed_response(
    store: &PolicySnapshotStore,
    response: Value,
    domain: &[u8],
) -> Result<Vec<u8>, String> {
    let bytes = canonical_json_bytes(&response).map_err(snapshot_error)?;
    let mac = hex::encode(crate::hmac_sha256(&store.verifier_key, domain, &bytes));
    canonical_json_bytes(&serde_json::json!({"response": response, "mac": mac}))
        .map_err(snapshot_error)
}

fn request_digest(value: &Value) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(
        canonical_json_bytes(value).map_err(snapshot_error)?,
    )))
}

fn verified_observation(
    value: &Value,
    store: &PolicySnapshotStore,
) -> Result<ObservationIntent, String> {
    let object = value
        .as_object()
        .filter(|object| {
            object.len() == 2 && object.contains_key("intent") && object.contains_key("mac")
        })
        .ok_or_else(|| "native_policy_snapshot_observation_invalid".to_owned())?;
    let fields = object["intent"]
        .as_object()
        .filter(|fields| {
            fields.len() == 4
                && fields
                    .values()
                    .all(|value| value.as_str().is_some_and(|text| text.len() <= 64))
        })
        .ok_or_else(|| "native_policy_snapshot_observation_invalid".to_owned())?;
    let intent: ObservationIntent = serde_json::from_value(Value::Object(fields.clone()))
        .map_err(|_| "native_policy_snapshot_observation_invalid".to_owned())?;
    if intent.schema != OBSERVATION_SCHEMA
        || store.resident_generation == 0
        || intent.runtime_identity != store.expected_runtime_identity
        || intent.scope_digest != store.expected_scope_digest
        || !is_lower_hex(&intent.runtime_identity, 64)
        || !is_lower_hex(&intent.scope_digest, 64)
        || !is_lower_hex(&intent.nonce, 64)
    {
        return Err("native_policy_snapshot_observation_invalid".to_owned());
    }
    let mac = object["mac"]
        .as_str()
        .filter(|mac| is_lower_hex(mac, 64))
        .ok_or_else(|| "native_policy_snapshot_observation_invalid".to_owned())?;
    let expected = hex::encode(crate::hmac_sha256(
        &store.verifier_key,
        OBSERVATION_DOMAIN,
        &canonical_json_bytes(&object["intent"]).map_err(snapshot_error)?,
    ));
    if !crate::constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
        return Err("native_policy_snapshot_observation_unauthenticated".to_owned());
    }
    Ok(intent)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedAuthority {
    fingerprint: String,
    generation_floor: u64,
    policy_digest: String,
    usable_snapshot: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WithdrawalIntent {
    schema: String,
    runtime_identity: String,
    scope_digest: String,
    resident_generation: u64,
    expected_authority: Option<ExpectedAuthority>,
    retirement_generation: u64,
    retirement_policy_digest: String,
}

impl WithdrawalIntent {
    fn matches(&self, current: &DurableAuthority) -> bool {
        match (&self.expected_authority, &current.fingerprint) {
            (None, None) => {
                current.floor == 0 && current.policy_digest.is_none() && !current.usable_snapshot
            }
            (Some(expected), Some(fingerprint)) => {
                expected.fingerprint == *fingerprint
                    && expected.generation_floor == current.floor
                    && current.policy_digest.as_ref() == Some(&expected.policy_digest)
                    && expected.usable_snapshot == current.usable_snapshot
            }
            _ => false,
        }
    }

    fn validate(&self, store: &PolicySnapshotStore) -> Result<(), String> {
        if self.schema != WITHDRAWAL_SCHEMA
            || !is_lower_hex(&self.runtime_identity, 64)
            || self.runtime_identity != store.expected_runtime_identity
            || !is_lower_hex(&self.scope_digest, 64)
            || self.scope_digest != store.expected_scope_digest
            || self.resident_generation == 0
            || self.resident_generation != store.resident_generation
            || self.retirement_generation == 0
            || !is_lower_hex(&self.retirement_policy_digest, 64)
            || self.expected_authority.as_ref().is_some_and(|expected| {
                expected.generation_floor == 0
                    || !is_lower_hex(&expected.fingerprint, 64)
                    || !is_lower_hex(&expected.policy_digest, 64)
            })
        {
            return Err("native_policy_snapshot_withdrawal_invalid".to_owned());
        }
        Ok(())
    }
}

fn verified_intent(value: &Value, store: &PolicySnapshotStore) -> Result<WithdrawalIntent, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "native_policy_snapshot_withdrawal_invalid".to_owned())?;
    if object.len() != 2 || !object.contains_key("intent") || !object.contains_key("mac") {
        return Err("native_policy_snapshot_withdrawal_invalid".to_owned());
    }
    let intent_value = &object["intent"];
    let intent_object = intent_value
        .as_object()
        .ok_or_else(|| "native_policy_snapshot_withdrawal_invalid".to_owned())?;
    if intent_object.len() != 7 || !intent_object.contains_key("expected_authority") {
        return Err("native_policy_snapshot_withdrawal_invalid".to_owned());
    }
    // Check the finite shape before cloning into the typed request. No nested
    // values or unbounded strings can be smuggled into an authenticated intent.
    for (name, field) in intent_object {
        let valid = match name.as_str() {
            "schema" | "runtime_identity" | "scope_digest" | "retirement_policy_digest" => {
                field.as_str().is_some_and(|text| text.len() <= 64)
            }
            "resident_generation" | "retirement_generation" => {
                field.as_u64().is_some_and(|number| number > 0)
            }
            "expected_authority" => {
                field.is_null()
                    || field.as_object().is_some_and(|expected| {
                        expected.len() == 4
                            && expected.iter().all(|(name, field)| match name.as_str() {
                                "fingerprint" | "policy_digest" => {
                                    field.as_str().is_some_and(|text| text.len() == 64)
                                }
                                "generation_floor" => {
                                    field.as_u64().is_some_and(|number| number > 0)
                                }
                                "usable_snapshot" => field.is_boolean(),
                                _ => false,
                            })
                    })
            }
            _ => false,
        };
        if !valid {
            return Err("native_policy_snapshot_withdrawal_invalid".to_owned());
        }
    }
    let intent: WithdrawalIntent = serde_json::from_value(intent_value.clone())
        .map_err(|_| "native_policy_snapshot_withdrawal_invalid".to_owned())?;
    intent.validate(store)?;
    let mac = object["mac"]
        .as_str()
        .filter(|mac| is_lower_hex(mac, 64))
        .ok_or_else(|| "native_policy_snapshot_withdrawal_invalid".to_owned())?;
    let bytes = canonical_json_bytes(intent_value).map_err(snapshot_error)?;
    let expected = hex::encode(crate::hmac_sha256(
        &store.verifier_key,
        WITHDRAWAL_DOMAIN,
        &bytes,
    ));
    if !crate::constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
        return Err("native_policy_snapshot_withdrawal_unauthenticated".to_owned());
    }
    Ok(intent)
}

impl PolicySnapshotStore {
    /// Observe a durable precondition under the writer lock. This authenticates
    /// no source input and grants no evaluation or readiness authority.
    pub(crate) fn observe_authority(&self, value: &Value) -> Result<Vec<u8>, String> {
        let intent = verified_observation(value, self)?;
        let parent = self
            .authority_path
            .parent()
            .ok_or_else(|| "native_policy_snapshot_authority_parent_missing".to_owned())?;
        let _writer = acquire_writer(parent)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let current = refresh_floor(self, &mut state)?;
        let authority = current.fingerprint.map(|fingerprint| {
            serde_json::json!({
                "fingerprint": fingerprint,
                "generation_floor": current.floor,
                "policy_digest": current.policy_digest,
                "usable_snapshot": current.usable_snapshot,
            })
        });
        signed_response(
            self,
            serde_json::json!({
                "schema": "guard-policy-snapshot-observation-response.v1",
                "runtime_identity": self.expected_runtime_identity,
                "scope_digest": self.expected_scope_digest,
                "resident_generation": self.resident_generation,
                "nonce": intent.nonce,
                "request_sha256": request_digest(value)?,
                "authority": authority,
            }),
            OBSERVATION_RESPONSE_DOMAIN,
        )
    }

    /// Retire one exact current authority. No retry success is inferred from a
    /// floor-only record, which does not retain the original request reference.
    pub(crate) fn withdraw(&self, value: &Value) -> Result<Vec<u8>, String> {
        let intent = verified_intent(value, self)?;
        let parent = self
            .authority_path
            .parent()
            .ok_or_else(|| "native_policy_snapshot_authority_parent_missing".to_owned())?;
        let _writer = acquire_writer(parent)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let current = refresh_floor(self, &mut state)?;
        if !intent.matches(&current) || intent.retirement_generation <= state.generation_floor {
            return Err("native_policy_snapshot_withdrawal_stale".to_owned());
        }
        let mut observed = self.authority_observed.lock().map_err(|_| {
            self.authority_changed.store(true, Ordering::SeqCst);
            "native_policy_snapshot_context_mismatch".to_owned()
        })?;
        persist_authority_with_control_floor(
            &self.authority_path,
            intent.retirement_generation,
            &intent.retirement_policy_digest,
            None,
            &self.verifier_key,
            state.command_control_floor.as_ref(),
        )
        .inspect_err(|_| self.authority_changed.store(true, Ordering::SeqCst))?;
        state.generation_floor = intent.retirement_generation;
        state.policy_digest = Some(intent.retirement_policy_digest.clone());
        state.snapshot = None;
        state.canonical_bytes.clear();
        state.invalid_on_startup = false;
        *observed = authority_fingerprint(&self.authority_path);
        drop(observed);
        refresh_authority_for_ack(self)?;
        signed_response(
            self,
            serde_json::json!({
                "schema": "guard-policy-snapshot-withdrawal-response.v1",
                "status": "withdrawn",
                "runtime_identity": self.expected_runtime_identity,
                "scope_digest": self.expected_scope_digest,
                "generation": intent.retirement_generation,
                "policy_digest": intent.retirement_policy_digest,
                "resident_generation": self.resident_generation,
                "request_sha256": request_digest(value)?,
            }),
            WITHDRAWAL_RESPONSE_DOMAIN,
        )
    }
}
