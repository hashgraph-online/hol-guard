//! Metadata-only secret audit records.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    pub(crate) schema: &'static str,
    pub(crate) event: &'static str,
    pub(crate) provider_id: String,
    pub(crate) reference_digest: String,
    pub(crate) binding_digest: String,
    pub(crate) outcome: String,
    pub(crate) lease_digest: Option<String>,
}

impl Event {
    pub(crate) fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_is_metadata_only() {
        let value = Event {
            schema: "guard.secret-audit.v1",
            event: "delivery",
            provider_id: "provider.examplevault".to_owned(),
            reference_digest: "a".repeat(64),
            binding_digest: "b".repeat(64),
            outcome: "delivered".to_owned(),
            lease_digest: None,
        }
        .to_value();
        assert!(value.get("value").is_none());
        assert!(!value.to_string().contains("fixture-value-7"));
    }
}
