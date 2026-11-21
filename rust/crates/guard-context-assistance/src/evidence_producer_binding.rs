//! Historical data provenance, not release qualification or startup authority.
use super::*;

/// Untagged keeps the stored record wire shape: the binding object itself.
/// Records written by the retired downloaded engine stay readable as opaque
/// history so saved generations and erasure scopes keep working; nothing can
/// create a new one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub(crate) enum EvidenceProducerBinding {
    Builtin(Box<BuiltinEvidenceBinding>),
    Retired(Box<serde_json::Value>),
}
/// Data written by the engine compiled into Guard. The engine release and
/// protocols are the whole producer identity; there are no files to bind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuiltinEvidenceBinding {
    pub schema: String,
    pub core_version: String,
    pub worker_protocol: String,
    pub broker_protocol: String,
    pub platform: String,
    pub worker_sha256: String,
}
impl BuiltinEvidenceBinding {
    pub(crate) const SCHEMA: &'static str = "guard-cigar-builtin-evidence-producer.v1";
    fn validate(&self) -> Result<(), RuntimeError> {
        let label = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-:".contains(&b))
        };
        if self.schema != Self::SCHEMA
            || ![
                &self.core_version,
                &self.worker_protocol,
                &self.broker_protocol,
                &self.platform,
            ]
            .iter()
            .all(|value| label(value))
            || !valid_key(&self.worker_sha256)
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(())
    }
}
impl EvidenceProducerBinding {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        match self {
            Self::Builtin(binding) => binding.validate(),
            Self::Retired(value) if is_retired_shape(value) => Ok(()),
            Self::Retired(_) => Err(RuntimeError::StorageRepairRequired),
        }
    }
    /// The engine executable hash a binding names, when it names one. Retired
    /// downloaded-engine records kept it under `approval`.
    pub(crate) fn worker_sha256(&self) -> Option<&str> {
        match self {
            Self::Builtin(binding) => Some(&binding.worker_sha256),
            Self::Retired(value) => value
                .get("approval")
                .and_then(|approval| approval.get("worker_sha256"))
                .and_then(serde_json::Value::as_str),
        }
    }
}

/// Only the two record shapes the retired engine wrote: a catalog release
/// binding (`identity`) or an enrollment record (`approval`). A record that
/// claims the built-in schema but failed its strict parse is damaged, not
/// history.
fn is_retired_shape(value: &serde_json::Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let object = |key: &str| fields.get(key).is_some_and(serde_json::Value::is_object);
    fields.len() <= 16
        && fields.get("schema").and_then(serde_json::Value::as_str)
            != Some(BuiltinEvidenceBinding::SCHEMA)
        && (object("identity") || object("approval"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(value: serde_json::Value) -> EvidenceProducerBinding {
        serde_json::from_value(value).expect("binding parses")
    }

    #[test]
    fn damaged_builtin_binding_is_not_accepted_as_history() {
        let damaged = binding(serde_json::json!({
            "schema": BuiltinEvidenceBinding::SCHEMA,
            "core_version": "0.14.2",
            "worker_protocol": "w1",
            "broker_protocol": "b1",
            "platform": "macos-arm64",
        }));
        assert!(matches!(damaged, EvidenceProducerBinding::Retired(_)));
        assert!(matches!(
            damaged.validate(),
            Err(RuntimeError::StorageRepairRequired)
        ));
        assert!(matches!(
            binding(serde_json::json!({"unrelated": true})).validate(),
            Err(RuntimeError::StorageRepairRequired)
        ));
    }

    #[test]
    fn retired_engine_records_stay_readable() {
        let enrolled = binding(serde_json::json!({
            "schema": "guard-cigar-enrolled-evidence-producer.v1",
            "approval": {"worker_sha256": "a".repeat(64)},
        }));
        assert!(enrolled.validate().is_ok());
        assert_eq!(enrolled.worker_sha256(), Some("a".repeat(64).as_str()));
        let catalog = binding(serde_json::json!({
            "identity": {"sdk_version": "0.14.1"},
            "profile_id": "p",
        }));
        assert!(catalog.validate().is_ok());
    }
}
