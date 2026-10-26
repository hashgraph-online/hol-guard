//! Authenticated mutable authority state, append-only revocations and the
//! signed authority-transition ledger entries.

use serde_json::{json, Value};

use crate::guard_store_wfcap_error::{cap, WfResult};
use crate::guard_store_wfcap_frame::{
    canonical, digest, digests_equal, frame, hmac_hex, ident, is_reason_code, opt_int, opt_str,
    opt_value, parse_ts, req_int, req_str, sha256_hex, strict, validate_key,
};

pub(crate) const STATE_SCHEMA: &str = "hol-guard.workflow-capability-authority-state.v1";
pub(crate) const REVOCATION_SCHEMA: &str = "hol-guard.workflow-capability-revocation.v1";
pub(crate) const TRANSITION_SCHEMA: &str = "hol-guard.workflow-capability-authority-transition.v1";
pub(crate) const ZERO_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug)]
pub(crate) struct AuthorityState {
    pub capability_id: String,
    pub claim_sha256: String,
    pub use_high_water: i64,
    pub observed_at: String,
    pub revision: i64,
    pub revocation_id: Option<String>,
    pub revoked_at: Option<String>,
}

impl AuthorityState {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "schema_version": STATE_SCHEMA,
            "capability_id": self.capability_id,
            "claim_sha256": self.claim_sha256,
            "use_high_water": self.use_high_water,
            "observed_at": self.observed_at,
            "revision": self.revision,
            "revocation_id": opt_value(&self.revocation_id),
            "revoked_at": opt_value(&self.revoked_at),
        })
    }

    pub(crate) fn from_value(value: &Value) -> WfResult<Self> {
        let map = strict(
            value,
            &[
                "schema_version",
                "capability_id",
                "claim_sha256",
                "use_high_water",
                "observed_at",
                "revision",
                "revocation_id",
                "revoked_at",
            ],
        )?;
        let schema = req_str(map, "schema_version")?;
        let capability_id = req_str(map, "capability_id")?;
        let claim_sha256 = req_str(map, "claim_sha256")?;
        let use_high_water = req_int(map, "use_high_water", "invalid_use_high_water")?;
        let observed_at = req_str(map, "observed_at")?;
        let revision = req_int(map, "revision", "invalid_revision")?;
        let revocation_id = opt_str(map, "revocation_id")?;
        let revoked_at = opt_str(map, "revoked_at")?;
        if schema != STATE_SCHEMA {
            return cap("unsupported_authority_state_schema");
        }
        ident("capability_id", &capability_id)?;
        digest("claim_sha256", &claim_sha256)?;
        parse_ts(&observed_at)?;
        if use_high_water < 0 {
            return cap("invalid_authority_use_high_water");
        }
        if revision < 0 {
            return cap("invalid_authority_revision");
        }
        if revocation_id.is_none() != revoked_at.is_none() {
            return cap("invalid_authority_revocation_binding");
        }
        if let (Some(id), Some(at)) = (&revocation_id, &revoked_at) {
            ident("revocation_id", id)?;
            parse_ts(at)?;
        }
        Ok(Self {
            capability_id,
            claim_sha256,
            use_high_water,
            observed_at,
            revision,
            revocation_id,
            revoked_at,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Revocation {
    pub revocation_id: String,
    pub capability_id: String,
    pub claim_sha256: String,
    pub reason_code: String,
    pub revoked_at: String,
}

impl Revocation {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "schema_version": REVOCATION_SCHEMA,
            "revocation_id": self.revocation_id,
            "capability_id": self.capability_id,
            "claim_sha256": self.claim_sha256,
            "reason_code": self.reason_code,
            "revoked_at": self.revoked_at,
        })
    }

    pub(crate) fn from_value(value: &Value) -> WfResult<Self> {
        let map = strict(
            value,
            &[
                "schema_version",
                "revocation_id",
                "capability_id",
                "claim_sha256",
                "reason_code",
                "revoked_at",
            ],
        )?;
        for (name, item) in map {
            if !item.is_string() {
                return cap(format!("invalid_{name}"));
            }
        }
        let field = |name: &str| req_str(map, name).unwrap_or_default();
        if field("schema_version") != REVOCATION_SCHEMA {
            return cap("unsupported_revocation_schema");
        }
        ident("revocation_id", &field("revocation_id"))?;
        ident("capability_id", &field("capability_id"))?;
        digest("claim_sha256", &field("claim_sha256"))?;
        if !is_reason_code(&field("reason_code")) {
            return cap("invalid_reason_code");
        }
        parse_ts(&field("revoked_at"))?;
        Ok(Self {
            revocation_id: field("revocation_id"),
            capability_id: field("capability_id"),
            claim_sha256: field("claim_sha256"),
            reason_code: field("reason_code"),
            revoked_at: field("revoked_at"),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Transition {
    pub sequence: i64,
    pub capability_id: String,
    pub claim_sha256: String,
    pub revision: i64,
    pub kind: String,
    pub previous_sha256: String,
    pub signed_state_sha256: String,
    pub event_id: i64,
    pub event_name: String,
    pub event_payload_sha256: String,
    pub occurred_at: String,
    pub use_number: Option<i64>,
    pub receipt_id: Option<String>,
    pub revocation_id: Option<String>,
}

impl Transition {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "schema_version": TRANSITION_SCHEMA,
            "algorithm": "hmac-sha256",
            "sequence": self.sequence,
            "capability_id": self.capability_id,
            "claim_sha256": self.claim_sha256,
            "revision": self.revision,
            "transition_kind": self.kind,
            "previous_transition_sha256": self.previous_sha256,
            "signed_state_sha256": self.signed_state_sha256,
            "event_id": self.event_id,
            "event_name": self.event_name,
            "event_payload_sha256": self.event_payload_sha256,
            "occurred_at": self.occurred_at,
            "use_number": self.use_number,
            "receipt_id": opt_value(&self.receipt_id),
            "revocation_id": opt_value(&self.revocation_id),
        })
    }

    pub(crate) fn from_value(value: &Value) -> WfResult<Self> {
        let map = strict(
            value,
            &[
                "schema_version",
                "algorithm",
                "sequence",
                "capability_id",
                "claim_sha256",
                "revision",
                "transition_kind",
                "previous_transition_sha256",
                "signed_state_sha256",
                "event_id",
                "event_name",
                "event_payload_sha256",
                "occurred_at",
                "use_number",
                "receipt_id",
                "revocation_id",
            ],
        )?;
        let schema = req_str(map, "schema_version")?;
        let algorithm = req_str(map, "algorithm")?;
        let sequence = req_int(map, "sequence", "invalid_sequence")?;
        let capability_id = req_str(map, "capability_id")?;
        let claim_sha256 = req_str(map, "claim_sha256")?;
        let revision = req_int(map, "revision", "invalid_revision")?;
        let kind = req_str(map, "transition_kind")?;
        let previous_sha256 = req_str(map, "previous_transition_sha256")?;
        let signed_state_sha256 = req_str(map, "signed_state_sha256")?;
        let event_id = opt_int(map, "event_id", "invalid_event_id")?;
        let event_name = opt_str(map, "event_name")?;
        let event_payload_sha256 = opt_str(map, "event_payload_sha256")?;
        let occurred_at = req_str(map, "occurred_at")?;
        let use_number = opt_int(map, "use_number", "invalid_use_number")?;
        let receipt_id = opt_str(map, "receipt_id")?;
        let revocation_id = opt_str(map, "revocation_id")?;
        if schema != TRANSITION_SCHEMA {
            return cap("unsupported_authority_transition_schema");
        }
        if algorithm != "hmac-sha256" {
            return cap("unsupported_authority_transition_algorithm");
        }
        if sequence < 1 {
            return cap("invalid_authority_transition_sequence");
        }
        if revision < 0 {
            return cap("invalid_authority_transition_revision");
        }
        ident("capability_id", &capability_id)?;
        digest("claim_sha256", &claim_sha256)?;
        digest("previous_transition_sha256", &previous_sha256)?;
        digest("signed_state_sha256", &signed_state_sha256)?;
        parse_ts(&occurred_at)?;
        if !["issued", "claimed", "revoked"].contains(&kind.as_str()) {
            return cap("invalid_authority_transition_kind");
        }
        let Some(event_id) = event_id.filter(|id| *id >= 1) else {
            return cap("invalid_authority_transition_event");
        };
        let event_name = match event_name {
            Some(name) => {
                ident("event_name", &name)?;
                name
            }
            None => return cap("invalid_event_name"),
        };
        let event_payload_sha256 = match event_payload_sha256 {
            Some(hash) => {
                digest("event_payload_sha256", &hash)?;
                hash
            }
            None => return cap("invalid_event_payload_sha256"),
        };
        if use_number.is_some_and(|n| n < 1) {
            return cap("invalid_authority_transition_use_number");
        }
        if let Some(id) = &receipt_id {
            ident("receipt_id", id)?;
        }
        if let Some(id) = &revocation_id {
            ident("revocation_id", id)?;
        }
        let claimed = kind == "claimed";
        if claimed != receipt_id.is_some() {
            return cap("invalid_authority_transition_receipt");
        }
        if claimed != use_number.is_some() {
            return cap("invalid_authority_transition_use_number");
        }
        if (kind == "revoked") != revocation_id.is_some() {
            return cap("invalid_authority_transition_revocation");
        }
        Ok(Self {
            sequence,
            capability_id,
            claim_sha256,
            revision,
            kind,
            previous_sha256,
            signed_state_sha256,
            event_id,
            event_name,
            event_payload_sha256,
            occurred_at,
            use_number,
            receipt_id,
            revocation_id,
        })
    }
}

fn mac(purpose: &str, payload: &Value, key: &[u8], key_id: &str) -> WfResult<String> {
    validate_key(key)?;
    ident("key_id", key_id)?;
    let authenticated = json!({"key_id": key_id, "payload": payload});
    Ok(hmac_hex(key, &frame(purpose, &authenticated)))
}

fn check_envelope(
    actual_key: &str,
    actual: &str,
    expected: &str,
    key_id: &str,
    purpose: &str,
) -> WfResult<()> {
    if actual_key != key_id {
        return cap(format!("{purpose}_key_mismatch"));
    }
    digest("signature", actual)?;
    if !digests_equal(actual, expected) {
        return cap(format!("{purpose}_signature_invalid"));
    }
    Ok(())
}

/// A decoded, authenticated-envelope view shared by state and revocation.
#[derive(Clone, Debug)]
pub(crate) struct Signed<T> {
    pub inner: T,
    pub key_id: String,
    pub signature: String,
}

pub(crate) type SignedState = Signed<AuthorityState>;
pub(crate) type SignedRevocation = Signed<Revocation>;
pub(crate) type SignedTransition = Signed<Transition>;

pub(crate) fn sign_state(
    state: &AuthorityState,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedState> {
    let signature = mac("authority-state", &state.to_value(), key, key_id)?;
    Ok(Signed {
        inner: state.clone(),
        key_id: key_id.to_owned(),
        signature,
    })
}

pub(crate) fn verify_state(signed: &SignedState, key: &[u8], key_id: &str) -> WfResult<()> {
    let expected = sign_state(&signed.inner, key, key_id)?.signature;
    check_envelope(
        &signed.key_id,
        &signed.signature,
        &expected,
        key_id,
        "authority_state",
    )
}

pub(crate) fn encode_state(signed: &SignedState) -> String {
    canonical(&json!({
        "key_id": signed.key_id,
        "signature": signed.signature,
        "state": signed.inner.to_value(),
    }))
}

fn decode_envelope(encoded: &str, keys: &[&str], purpose: &str) -> WfResult<Value> {
    let Ok(payload) = serde_json::from_str::<Value>(encoded) else {
        return cap(format!("{purpose}_payload_invalid"));
    };
    strict(&payload, keys)?;
    Ok(payload)
}

pub(crate) fn decode_state(encoded: &str) -> WfResult<SignedState> {
    let payload = decode_envelope(
        encoded,
        &["key_id", "signature", "state"],
        "authority_state",
    )?;
    let map = payload.as_object().cloned().unwrap_or_default();
    let inner = AuthorityState::from_value(&payload["state"])?;
    let signed = Signed {
        inner,
        key_id: req_str(&map, "key_id")?,
        signature: req_str(&map, "signature")?,
    };
    if encode_state(&signed) != encoded {
        return cap("authority_state_not_canonical");
    }
    Ok(signed)
}

pub(crate) fn sign_revocation(
    revocation: &Revocation,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedRevocation> {
    let signature = mac("revocation", &revocation.to_value(), key, key_id)?;
    Ok(Signed {
        inner: revocation.clone(),
        key_id: key_id.to_owned(),
        signature,
    })
}

pub(crate) fn verify_revocation(
    signed: &SignedRevocation,
    key: &[u8],
    key_id: &str,
) -> WfResult<()> {
    let expected = sign_revocation(&signed.inner, key, key_id)?.signature;
    check_envelope(
        &signed.key_id,
        &signed.signature,
        &expected,
        key_id,
        "revocation",
    )
}

pub(crate) fn encode_revocation(signed: &SignedRevocation) -> String {
    canonical(&json!({
        "key_id": signed.key_id,
        "revocation": signed.inner.to_value(),
        "signature": signed.signature,
    }))
}

pub(crate) fn decode_revocation(encoded: &str) -> WfResult<SignedRevocation> {
    let payload = decode_envelope(
        encoded,
        &["key_id", "revocation", "signature"],
        "revocation",
    )?;
    let map = payload.as_object().cloned().unwrap_or_default();
    let inner = Revocation::from_value(&payload["revocation"])?;
    let signed = Signed {
        inner,
        key_id: req_str(&map, "key_id")?,
        signature: req_str(&map, "signature")?,
    };
    if encode_revocation(&signed) != encoded {
        return cap("revocation_not_canonical");
    }
    Ok(signed)
}

pub(crate) fn sign_transition(
    transition: &Transition,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedTransition> {
    validate_key(key)?;
    ident("key_id", key_id)?;
    let payload = json!({"key_id": key_id, "transition": transition.to_value()});
    let signature = hmac_hex(key, &frame("authority-transition", &payload));
    Ok(Signed {
        inner: transition.clone(),
        key_id: key_id.to_owned(),
        signature,
    })
}

pub(crate) fn verify_transition(
    signed: &SignedTransition,
    key: &[u8],
    key_id: &str,
) -> WfResult<()> {
    if signed.key_id != key_id {
        return cap("authority_transition_key_mismatch");
    }
    digest("signature", &signed.signature)?;
    let expected = sign_transition(&signed.inner, key, key_id)?.signature;
    if !digests_equal(&signed.signature, &expected) {
        return cap("authority_transition_signature_invalid");
    }
    Ok(())
}

pub(crate) fn encode_transition(signed: &SignedTransition) -> String {
    canonical(&json!({
        "key_id": signed.key_id,
        "signature": signed.signature,
        "transition": signed.inner.to_value(),
    }))
}

pub(crate) fn decode_transition(encoded: &str) -> WfResult<SignedTransition> {
    let payload = decode_envelope(
        encoded,
        &["key_id", "signature", "transition"],
        "authority_transition",
    )?;
    let map = payload.as_object().cloned().unwrap_or_default();
    let inner = Transition::from_value(&payload["transition"])?;
    let signed = Signed {
        inner,
        key_id: req_str(&map, "key_id")?,
        signature: req_str(&map, "signature")?,
    };
    if encode_transition(&signed) != encoded {
        return cap("authority_transition_not_canonical");
    }
    Ok(signed)
}

pub(crate) fn transition_sha256(signed: &SignedTransition) -> String {
    sha256_hex(&frame(
        "authority-transition-digest",
        &Value::from(encode_transition(signed)),
    ))
}

pub(crate) fn state_sha256(signed: &SignedState) -> String {
    sha256_hex(&frame(
        "authority-state-digest",
        &Value::from(encode_state(signed)),
    ))
}
