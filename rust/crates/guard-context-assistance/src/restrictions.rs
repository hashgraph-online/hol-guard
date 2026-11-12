use serde::Deserialize;
use serde_json::Value;

use crate::{ConfigError, ContextAssistanceConfig, StorageMode};

// Restriction documents deliberately have no runtime_id or source_set_id.
// Those references belong to the user's explicit local selection only.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Restrictions {
    schema_version: Option<u32>,
    enabled: Option<bool>,
    features: Option<FeatureRestrictions>,
    sources: Option<SourceRestrictions>,
    storage: Option<StorageRestrictions>,
    limits: Option<LimitRestrictions>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FeatureRestrictions {
    review_briefs: Option<bool>,
    agent_context: Option<bool>,
    shared_agents: Option<bool>,
    execution_context: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SourceRestrictions {
    native_policy_facts: Option<bool>,
    sanitized_receipt_facts: Option<bool>,
    workspace_documents: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StorageRestrictions {
    mode: Option<StorageMode>,
    retention_hours: Option<u32>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LimitRestrictions {
    context_tokens: Option<u32>,
    reserve_tokens: Option<u32>,
    max_active_workspaces: Option<u32>,
    idle_shutdown_seconds: Option<u32>,
}

fn narrow(flag: &mut bool, restriction: Option<bool>) {
    if restriction == Some(false) {
        *flag = false;
    }
}

fn cap(value: &mut u32, restriction: Option<u32>) {
    if let Some(maximum) = restriction {
        *value = (*value).min(maximum);
    }
}

/// Intersect host consent with a sparse workspace or managed-policy restriction.
/// A true permission never creates consent; malformed restrictions return an
/// error which the caller must treat as unavailable, never as an ignored policy.
pub fn restrict_config(
    local: &ContextAssistanceConfig,
    restriction: &Value,
) -> Result<ContextAssistanceConfig, ConfigError> {
    fn contains_null(value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::Object(fields) => fields.values().any(contains_null),
            Value::Array(items) => items.iter().any(contains_null),
            _ => false,
        }
    }
    if contains_null(restriction) {
        return Err(ConfigError("context_assistance_restriction_invalid"));
    }
    let restriction: Restrictions = serde_json::from_value(restriction.clone())
        .map_err(|_| ConfigError("context_assistance_restriction_invalid"))?;
    if restriction
        .schema_version
        .is_some_and(|version| version != 1)
    {
        return Err(ConfigError("context_assistance_schema_unsupported"));
    }
    let mut effective = local.clone();
    narrow(&mut effective.enabled, restriction.enabled);
    if let Some(features) = restriction.features {
        narrow(
            &mut effective.features.review_briefs,
            features.review_briefs,
        );
        narrow(
            &mut effective.features.agent_context,
            features.agent_context,
        );
        narrow(
            &mut effective.features.shared_agents,
            features.shared_agents,
        );
        effective.features.shared_agents &= effective.features.agent_context;
        narrow(
            &mut effective.features.execution_context,
            features.execution_context,
        );
    }
    if let Some(sources) = restriction.sources {
        narrow(
            &mut effective.sources.native_policy_facts,
            sources.native_policy_facts,
        );
        narrow(
            &mut effective.sources.sanitized_receipt_facts,
            sources.sanitized_receipt_facts,
        );
        narrow(
            &mut effective.sources.workspace_documents,
            sources.workspace_documents,
        );
    }
    if let Some(storage) = restriction.storage {
        if storage.mode == Some(StorageMode::Memory) {
            effective.storage.mode = StorageMode::Memory;
        }
        cap(
            &mut effective.storage.retention_hours,
            storage.retention_hours,
        );
    }
    if let Some(limits) = restriction.limits {
        cap(&mut effective.limits.context_tokens, limits.context_tokens);
        cap(
            &mut effective.limits.max_active_workspaces,
            limits.max_active_workspaces,
        );
        cap(
            &mut effective.limits.idle_shutdown_seconds,
            limits.idle_shutdown_seconds,
        );
        if let Some(minimum) = limits.reserve_tokens {
            effective.limits.reserve_tokens = effective.limits.reserve_tokens.max(minimum);
        }
    }
    effective.validate()?;
    Ok(effective)
}

/// Config composition transports invalid restrictions as an invalid value so
/// the ordinary loader produces disabled defaults and a content-free diagnostic.
pub fn restrict_value(local: Option<&Value>, restriction: &Value) -> Value {
    let (local, diagnostic) = ContextAssistanceConfig::load(local);
    if diagnostic.is_some() {
        return Value::Null;
    }
    restrict_config(&local, restriction)
        .ok()
        .and_then(|config| serde_json::to_value(config).ok())
        .unwrap_or(Value::Null)
}
