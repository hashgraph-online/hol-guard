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
            Self::Retired(value) => match value.as_object() {
                Some(fields) if !fields.is_empty() && fields.len() <= 16 => Ok(()),
                _ => Err(RuntimeError::StorageRepairRequired),
            },
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
