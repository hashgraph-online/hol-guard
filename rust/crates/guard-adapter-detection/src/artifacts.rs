//! Artifact DTOs shared by the detection leaves and the runtime inventory:
//! the harness/scope pair every wire artifact names and the optional fields a
//! config entry carries.

use std::path::Path;

use serde_json::{json, Map, Value};

pub struct Scope<'a> {
    pub harness: &'a str,
    pub scope: &'a str,
}

#[derive(Default)]
pub struct Fields<'a> {
    pub command: Option<&'a str>,
    pub args: Vec<String>,
    pub url: Option<&'a str>,
    pub transport: Option<&'a str>,
    pub publisher: Option<&'a str>,
}

impl Scope<'_> {
    pub fn wire(
        &self,
        artifact_id: String,
        name: &str,
        artifact_type: &str,
        config_path: &Path,
        fields: Fields<'_>,
        metadata: Map<String, Value>,
    ) -> Value {
        json!({
            "artifact_id": artifact_id,
            "name": name,
            "harness": self.harness,
            "artifact_type": artifact_type,
            "source_scope": self.scope,
            "config_path": config_path.to_string_lossy(),
            "command": fields.command,
            "args": fields.args,
            "url": fields.url,
            "transport": fields.transport,
            "publisher": fields.publisher,
            "metadata": metadata,
        })
    }
}
