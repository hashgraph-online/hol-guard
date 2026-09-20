//! Preserve every authenticated policy field across resident storage and lookup.
use super::*;
use guard_policy_snapshot::{
    snapshot_bytes_v4, validate_v4, PolicySnapshotAckV2, PolicySnapshotPushV2, PolicySnapshotV4,
    POLICY_SNAPSHOT_V4_ACK_SCHEMA, POLICY_SNAPSHOT_V4_PUSH_SCHEMA,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum AuthenticatedPolicySnapshot {
    V3(PolicySnapshotV3),
    V4(PolicySnapshotV4),
}

macro_rules! snapshot_field {
    ($name:ident, $kind:ty) => {
        pub(crate) fn $name(&self) -> &$kind {
            match self {
                Self::V3(value) => &value.$name,
                Self::V4(value) => &value.$name,
            }
        }
    };
}

impl AuthenticatedPolicySnapshot {
    snapshot_field!(generation, u64);
    snapshot_field!(policy_digest, String);
    snapshot_field!(rule_digest, String);
    snapshot_field!(runtime_identity, String);
    snapshot_field!(scope_contract, guard_policy_snapshot::ScopeContractV3);
    snapshot_field!(expires_at_ms, u64);
    snapshot_field!(
        command_extensions,
        Option<guard_contracts::NativeCommandControlBindingV1>
    );

    pub(crate) fn source_input_digest(&self) -> Option<&str> {
        match self {
            Self::V3(_) => None,
            Self::V4(value) => Some(&value.source_input_digest),
        }
    }

    pub(super) fn from_push(value: &Value) -> Result<Self, String> {
        match value.get("schema").and_then(Value::as_str) {
            Some(POLICY_SNAPSHOT_PUSH_SCHEMA) => {
                serde_json::from_value::<PolicySnapshotPushV1>(value.clone())
                    .map(|request| Self::V3(request.snapshot))
            }
            Some(POLICY_SNAPSHOT_V4_PUSH_SCHEMA) => {
                serde_json::from_value::<PolicySnapshotPushV2>(value.clone())
                    .map(|request| Self::V4(request.snapshot))
            }
            _ => return Err("native_policy_snapshot_push_schema_mismatch".to_owned()),
        }
        .map_err(|_| "native_policy_snapshot_push_invalid".to_owned())
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::V3(value) => snapshot_bytes(value),
            Self::V4(value) => snapshot_bytes_v4(value),
        }
        .map_err(snapshot_error)
    }

    pub(super) fn validate(
        &self,
        minimum_generation: u64,
        runtime: &str,
        rules: &str,
        key: &[u8],
        now: u64,
    ) -> Result<(), String> {
        match self {
            Self::V3(value) => validate_v3(value, minimum_generation, runtime, rules, key, now),
            Self::V4(value) => validate_v4(value, minimum_generation, runtime, rules, key, now),
        }
        .map_err(snapshot_error)?;
        if let Self::V4(value) = self {
            crate::policy_scoped_managed::validate_authority(value.scoped_authority.managed())?;
        }
        Ok(())
    }

    pub(super) fn encode_ack(
        &self,
        idempotent: bool,
        resident_generation: u64,
    ) -> Result<Vec<u8>, String> {
        match self {
            Self::V3(value) => super::encode_ack(value, idempotent, resident_generation),
            Self::V4(value) => serde_json::to_vec(&PolicySnapshotAckV2 {
                schema: POLICY_SNAPSHOT_V4_ACK_SCHEMA.to_owned(),
                status: "accepted".to_owned(),
                generation: value.generation,
                policy_digest: value.policy_digest.clone(),
                source_input_digest: value.source_input_digest.clone(),
                idempotent,
                resident_generation,
            })
            .map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned()),
        }
    }

    pub(super) fn missing_snapshot_ack(
        &self,
        state: &PolicyState,
        resident_generation: u64,
    ) -> Result<Vec<u8>, String> {
        if matches!(self, Self::V3(_)) {
            return super::encode_requires_new_generation(state, resident_generation);
        }
        if *self.generation() != state.generation_floor
            || state.policy_digest.as_ref() != Some(self.policy_digest())
        {
            return Err("native_policy_snapshot_generation_reused".to_owned());
        }
        let mut ack: PolicySnapshotAckV2 =
            serde_json::from_slice(&self.encode_ack(false, resident_generation)?)
                .map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned())?;
        ack.status = POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION.to_owned();
        serde_json::to_vec(&ack).map_err(|_| "native_policy_snapshot_ack_encode_failed".to_owned())
    }
}

/// Immutable resident admission. Raw authenticated values stay the wire and
/// durable representation; selector and command indexes belong to one generation.
#[derive(Debug)]
pub(crate) enum AdmittedVersionedPolicySnapshot {
    V3(Arc<crate::policy_enforcement::AdmittedPolicySnapshot>),
    V4(Arc<crate::policy_enforcement::AdmittedScopedPolicySnapshot>),
}

impl AdmittedVersionedPolicySnapshot {
    pub(super) fn new(snapshot: AuthenticatedPolicySnapshot) -> Result<Self, String> {
        match snapshot {
            AuthenticatedPolicySnapshot::V3(value) => {
                crate::policy_enforcement::AdmittedPolicySnapshot::new(value)
                    .map(|value| Self::V3(Arc::new(value)))
            }
            AuthenticatedPolicySnapshot::V4(value) => {
                crate::policy_enforcement::AdmittedScopedPolicySnapshot::new(value)
                    .map(|value| Self::V4(Arc::new(value)))
            }
        }
    }

    snapshot_field!(generation, u64);
    snapshot_field!(policy_digest, String);
    snapshot_field!(rule_digest, String);
    snapshot_field!(runtime_identity, String);
    snapshot_field!(scope_contract, guard_policy_snapshot::ScopeContractV3);
    snapshot_field!(expires_at_ms, u64);

    pub(crate) fn command_extensions(
        &self,
    ) -> Option<&guard_contracts::NativeCommandControlBindingV1> {
        match self {
            Self::V3(value) => value.snapshot().command_extensions.as_ref(),
            Self::V4(value) => value.snapshot().command_extensions.as_ref(),
        }
    }

    pub(crate) fn source_input_digest(&self) -> Option<&str> {
        match self {
            Self::V3(_) => None,
            Self::V4(value) => Some(&value.source_input_digest),
        }
    }

    pub(crate) fn as_v3(
        &self,
    ) -> Result<&Arc<crate::policy_enforcement::AdmittedPolicySnapshot>, String> {
        match self {
            Self::V3(value) => Ok(value),
            Self::V4(_) => Err("native_policy_snapshot_consumer_version_unsupported".to_owned()),
        }
    }

    /// Materialize only at non-hook boundaries that need the durable wire value.
    pub(crate) fn authenticated(&self) -> AuthenticatedPolicySnapshot {
        match self {
            Self::V3(value) => AuthenticatedPolicySnapshot::V3(value.snapshot().clone()),
            Self::V4(value) => AuthenticatedPolicySnapshot::V4(value.snapshot().clone()),
        }
    }

    pub(super) fn encode_ack(
        &self,
        idempotent: bool,
        resident_generation: u64,
    ) -> Result<Vec<u8>, String> {
        self.authenticated()
            .encode_ack(idempotent, resident_generation)
    }

    pub(super) fn matches_reference(
        &self,
        value: &Value,
        expected_runtime: &str,
        canonical: &[u8],
    ) -> Result<bool, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
        let compact_len = if self.source_input_digest().is_some() {
            4
        } else {
            3
        };
        if object.len() == compact_len
            && ["generation", "policy_digest", "runtime_identity"]
                .iter()
                .all(|key| object.contains_key(*key))
        {
            return Ok(object.get("generation").and_then(Value::as_u64)
                == Some(*self.generation())
                && object.get("policy_digest").and_then(Value::as_str)
                    == Some(self.policy_digest())
                && object.get("runtime_identity").and_then(Value::as_str)
                    == Some(expected_runtime)
                && object.get("source_input_digest").and_then(Value::as_str)
                    == self.source_input_digest());
        }
        let candidate: AuthenticatedPolicySnapshot = serde_json::from_value(value.clone())
            .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
        Ok(candidate.bytes()? == canonical)
    }
}

impl Serialize for AdmittedVersionedPolicySnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::V3(value) => value.snapshot().serialize(serializer),
            Self::V4(value) => value.snapshot().serialize(serializer),
        }
    }
}
