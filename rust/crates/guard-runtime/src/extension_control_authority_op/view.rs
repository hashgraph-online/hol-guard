//! `ExtensionControlAuthorityView` as the resident carries it.

use guard_command::extension_control::ExtensionControlLayer;
use serde_json::{json, Value};

use super::layers::{layers_from_values, layers_to_values};
use super::records::{exact_int, tampered, Res};

/// `ExtensionControlAuthorityView`. `health` is carried as its wire name so a
/// view the caller sends back keeps its acknowledged or unacknowledged
/// degraded state.
#[derive(Debug, Clone)]
pub(super) struct View {
    pub(super) health: String,
    pub(super) revision: i64,
    pub(super) catalog_digest: String,
    pub(super) layers: Vec<ExtensionControlLayer>,
    pub(super) managed_revision: i64,
}

impl View {
    pub(super) fn bare(health: &str, revision: i64, catalog_digest: &str) -> Self {
        Self {
            health: health.to_owned(),
            revision,
            catalog_digest: catalog_digest.to_owned(),
            layers: Vec::new(),
            managed_revision: 0,
        }
    }

    pub(super) fn to_value(&self) -> Value {
        json!({
            "health": self.health,
            "revision": self.revision,
            "catalog_digest": self.catalog_digest,
            "layers": layers_to_values(&self.layers),
            "managed_revision": self.managed_revision,
        })
    }

    pub(super) fn from_value(value: Option<&Value>) -> Res<Self> {
        let invalid = || tampered("invalid extension control authority view");
        let Some(Value::Object(view)) = value else {
            return Err(invalid());
        };
        let int = |name: &str| view.get(name).and_then(exact_int).ok_or_else(invalid);
        Ok(Self {
            health: view
                .get("health")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .to_owned(),
            revision: int("revision")?,
            catalog_digest: view
                .get("catalog_digest")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .to_owned(),
            layers: layers_from_values(view.get("layers").unwrap_or(&Value::Null))?,
            managed_revision: int("managed_revision")?,
        })
    }
}
