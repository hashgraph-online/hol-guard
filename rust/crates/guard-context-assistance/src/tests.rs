use super::*;
use serde_json::json;

#[test]
fn absent_configuration_is_off_without_selecting_a_runtime_or_sources() {
    let (config, diagnostic) = ContextAssistanceConfig::load(None);
    assert!(!config.enabled);
    assert!(config.runtime_id.is_empty());
    assert!(!config.sources.workspace_documents);
    assert!(!config.features.agent_context);
    assert!(!config.features.shared_agents);
    assert!(!config.features.execution_context);
    assert_eq!(config.storage.mode, StorageMode::Memory);
    assert!(diagnostic.is_none());
    config.validate().unwrap();
}

#[test]
fn malformed_persisted_enablement_fails_off_instead_of_coercing_truthiness() {
    for value in [
        json!(null),
        json!({"enabled":"true","runtime_id":"runtime-1"}),
        json!({"enabled":1,"runtime_id":"runtime-1"}),
        json!({"enabled":true,"runtime_id":"runtime-1","worker_override":"/tmp/worker"}),
        json!({"schema_version":2,"enabled":true,"runtime_id":"runtime-1"}),
        json!({"enabled":true}),
    ] {
        let (config, diagnostic) = ContextAssistanceConfig::load(Some(&value));
        assert!(!config.enabled);
        assert!(config.runtime_id.is_empty());
        assert!(diagnostic.is_some());
    }
}

#[test]
fn selected_ids_are_bounded_opaque_references_instead_of_paths_or_urls() {
    for id in [
        "/tmp/python",
        "../python",
        "https://host",
        "runtime\nforged",
        "🐍",
    ] {
        assert!(ContextAssistanceConfig::parse(json!({"runtime_id":id})).is_err());
        assert!(ContextAssistanceConfig::parse(json!({"sources":{"source_set_id":id}})).is_err());
    }
    assert!(ContextAssistanceConfig::parse(json!({"runtime_id":"a".repeat(129)})).is_err());
    let config = ContextAssistanceConfig::parse(json!({
        "enabled":true,"runtime_id":"python:verified-314",
        "sources":{"workspace_documents":true,"source_set_id":"sources-1"}
    }))
    .unwrap();
    assert!(config.enabled);
    assert!(config.sources.workspace_documents);
}

#[test]
fn extra_documents_and_shared_agents_require_their_own_prerequisites() {
    assert!(
        ContextAssistanceConfig::parse(json!({"sources":{"workspace_documents":true}})).is_err()
    );
    assert!(ContextAssistanceConfig::parse(json!({"features":{"shared_agents":true}})).is_err());
    assert!(ContextAssistanceConfig::parse(json!({
        "features":{"shared_agents":true,"agent_context":true}
    }))
    .is_ok());
}

#[test]
fn budgets_cannot_be_negative_unbounded_or_reserve_the_whole_context() {
    for limits in [
        json!({"context_tokens":-1}),
        json!({"context_tokens":true}),
        json!({"context_tokens":63}),
        json!({"context_tokens":16385}),
        json!({"context_tokens":512,"reserve_tokens":512}),
        json!({"max_active_workspaces":0}),
        json!({"max_active_workspaces":9}),
        json!({"idle_shutdown_seconds":0}),
        json!({"idle_shutdown_seconds":3601}),
    ] {
        assert!(ContextAssistanceConfig::parse(json!({"limits":limits})).is_err());
    }
    for retention in [0, 721] {
        assert!(
            ContextAssistanceConfig::parse(json!({"storage":{"retention_hours":retention}}))
                .is_err()
        );
    }
}

#[test]
fn configuration_roundtrips_without_adding_effective_authority_fields() {
    let original = ContextAssistanceConfig::parse(json!({
        "runtime_id":"runtime-1","resource_profile":"low_memory",
        "features":{"agent_context":true},"storage":{"mode":"sqlite","retention_hours":48}
    }))
    .unwrap();
    let wire = serde_json::to_value(&original).unwrap();
    assert!(wire.get("effective_enabled").is_none());
    assert!(wire.get("secret").is_none());
    assert_eq!(ContextAssistanceConfig::parse(wire).unwrap(), original);
    assert!(ContextAssistanceConfig::parse(json!({"effective_enabled":true})).is_err());
}
