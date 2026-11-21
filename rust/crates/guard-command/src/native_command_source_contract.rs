//! Source metadata and editor schema share one Rust field declaration.

use super::matcher::SourceMatcher;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(super) const SOURCE_SCHEMA: &str = "guard.command-extension-source.v1";

trait FieldSchema {
    fn schema() -> Value;
    fn required() -> bool {
        true
    }
}
impl FieldSchema for String {
    fn schema() -> Value {
        json!({"type":"string", "maxLength":4096})
    }
}
impl FieldSchema for bool {
    fn schema() -> Value {
        json!({"type":"boolean"})
    }
}
impl<T: FieldSchema> FieldSchema for Vec<T> {
    fn schema() -> Value {
        json!({"type":"array", "maxItems":4096, "items":T::schema()})
    }
}
impl<T: FieldSchema> FieldSchema for Option<T> {
    fn schema() -> Value {
        json!({"anyOf":[T::schema(), {"type":"null"}]})
    }
    fn required() -> bool {
        false
    }
}
impl FieldSchema for SourceMatcher {
    fn schema() -> Value {
        json!({"$ref":"#/$defs/matcher"})
    }
}

macro_rules! record {
    ($name:ident { $($field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Debug, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(super) struct $name { $(pub(super) $field: $kind),* }
        impl FieldSchema for $name {
            fn schema() -> Value {
                let mut properties = serde_json::Map::new();
                let mut required = Vec::new();
                $(properties.insert(stringify!($field).to_owned(), <$kind>::schema());
                  if <$kind>::required() { required.push(stringify!($field)); })*
                json!({"type":"object", "additionalProperties":false,
                       "properties":properties, "required":required})
            }
        }
    };
}

record!(SourceDocument {
    schema: String,
    extension: SourceExtension,
});

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum SourceIcon {
    None {},
    ReactIcon { name: String, background: String },
}

impl SourceIcon {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::None {} => true,
            Self::ReactIcon { name, background } => {
                matches!(
                    name.as_str(),
                    "HiMiniBolt"
                        | "HiMiniCommandLine"
                        | "HiMiniCube"
                        | "HiMiniFolder"
                        | "HiMiniGlobeAlt"
                        | "HiMiniCloud"
                ) && background.len() == 7
                    && background.starts_with('#')
                    && background.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
            }
        }
    }
}

impl FieldSchema for SourceIcon {
    fn schema() -> Value {
        json!({"oneOf":[
            {"type":"object","additionalProperties":false,"required":["kind"],
             "properties":{"kind":{"const":"none"}}},
            {"type":"object","additionalProperties":false,"required":["kind","name","background"],
             "properties":{"kind":{"const":"react-icon"},"name":{"type":"string"},
                 "background":{"type":"string","pattern":"^#[0-9a-fA-F]{6}$"}}}
        ]})
    }
}

record!(SourceExtension {
    extension_id: String,
    version: String,
    name: String,
    description: String,
    icon: Option<SourceIcon>,
    publisher: Option<SourcePublisher>,
    homepage: Option<String>,
    license: Option<String>,
    action_classes: Vec<String>,
    risk_classes: Vec<String>,
    safer_alternatives: Vec<String>,
    reference_urls: Vec<String>,
    required: bool,
    source: String,
    aliases: Vec<String>,
    dependencies: Vec<String>,
    conflicts: Vec<String>,
    delegated_protection: Option<String>,
    ecosystem_ids: Vec<String>,
    executables: Vec<String>,
    project_markers: Vec<String>,
    permissions: Vec<SourcePermission>,
    rules: Vec<SourceRule>,
});

record!(SourcePublisher {
    id: String,
    display_name: String,
    url: Option<String>,
});

impl SourcePublisher {
    pub(super) fn projection(&self) -> Value {
        let mut result = json!({"id":self.id,"displayName":self.display_name});
        if let Some(url) = &self.url {
            result["url"] = json!(url);
        }
        result
    }
}

record!(SourcePermission {
    permission_id: String,
    implementation_version: String,
    label: String,
    description: String,
    risk_tier: String,
    baseline_floor: String,
    default_enabled: bool,
    configurable: bool,
    fixed_reason: Option<String>,
    typed_capabilities: Vec<String>,
    action_classes: Vec<String>,
    dependencies: Vec<String>,
    conflicts: Vec<String>,
    implied_permissions: Vec<String>,
    introduced_version: String,
    deprecated: bool,
    replacement_permission_id: Option<String>,
    safer_guidance: Vec<String>,
    example_command: Option<String>,
    family: Option<String>,
});

record!(SourceRule {
    rule_id: String,
    rule_version: String,
    permission_id: String,
    title: String,
    description: String,
    severity: String,
    risk_classes: Vec<String>,
    action_classes: Vec<String>,
    safer_alternatives: Vec<String>,
    family: Option<String>,
    default_mode: String,
    matcher: Option<SourceMatcher>,
    native_capability: Option<String>,
    safe_variants: Vec<SourceVariant>,
});

record!(SourceVariant {
    variant_id: String,
    title: String,
    matcher: SourceMatcher,
});

/// Structural editor contract. Native semantic validation remains mandatory.
pub fn source_schema() -> Value {
    let mut result = SourceDocument::schema();
    result["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    result["$id"] = json!(SOURCE_SCHEMA);
    result["properties"]["schema"] = json!({"const":SOURCE_SCHEMA});
    result["$defs"] = json!({"matcher":super::matcher::source_matcher_schema()});
    result
}

/// Generated descriptor v2 has a native source binding and no Python detector.
pub fn descriptor_schema() -> Value {
    let source = SourceExtension::schema();
    let fields = &source["properties"];
    let mut properties = serde_json::Map::new();
    for (output, input) in [
        ("id", "extension_id"),
        ("version", "version"),
        ("name", "name"),
        ("description", "description"),
        ("icon", "icon"),
        ("homepage", "homepage"),
        ("license", "license"),
        ("executables", "executables"),
        ("riskClasses", "risk_classes"),
        ("actionClasses", "action_classes"),
        ("ecosystemIds", "ecosystem_ids"),
        ("referenceUrls", "reference_urls"),
        ("saferAlternatives", "safer_alternatives"),
    ] {
        properties.insert(output.to_owned(), fields[input].clone());
    }
    properties.insert(
        "schemaVersion".to_owned(),
        json!({"const":"guard.extension-contribution.v2"}),
    );
    properties.insert("generated".to_owned(), json!({"const":true}));
    let mut publisher = SourcePublisher::schema();
    let display_name = publisher["properties"]
        .as_object_mut()
        .unwrap()
        .remove("display_name")
        .unwrap();
    publisher["properties"]["displayName"] = display_name;
    publisher["required"] = json!(["id", "displayName"]);
    properties.insert("publisher".to_owned(), publisher);
    properties.insert(
        "trustClass".to_owned(),
        json!({"enum":["first-party","trusted-library","external"]}),
    );
    properties.insert(
        "activation".to_owned(),
        json!({"enum":["default-on","opt-in"]}),
    );
    properties.insert("nativeSource".to_owned(), json!({"type":"object","additionalProperties":false,
        "required":["schemaVersion","path","digest"],"properties":{
            "schemaVersion":{"const":SOURCE_SCHEMA},
            "path":{"type":"string","pattern":"^contributions/command-sources/command\\.[a-z0-9.-]+\\.json$"},
            "digest":{"type":"string","pattern":"^[0-9a-f]{64}$"}
        }}));
    let required: Vec<_> = properties.keys().cloned().collect();
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "$id":"guard.extension-contribution.v2", "type":"object", "additionalProperties":false,
        "properties":properties,"required":required})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_owns_metadata_once_and_cannot_claim_trust_or_indexes() {
        let schema = source_schema();
        let properties = &schema["properties"]["extension"]["properties"];
        for forbidden in [
            "trust_class",
            "activation",
            "program_digest",
            "catalog_digest",
        ] {
            assert!(properties.get(forbidden).is_none());
        }
        let permission = &properties["permissions"]["items"]["properties"];
        assert!(permission.get("rule_ids").is_none());
        assert!(permission.get("extension_id").is_none());
    }
}
