use crate::*;
use serde_json::json;

#[test]
fn an_overlay_cannot_enable_any_permission_that_local_consent_did_not_grant() {
    let local = ContextAssistanceConfig::default();
    let effective = restrict_config(
        &local,
        &json!({
            "enabled":true,
            "features":{"review_briefs":true,"agent_context":true,"shared_agents":true,"execution_context":true},
            "sources":{"workspace_documents":true},
            "storage":{"mode":"sqlite","retention_hours":720},
            "limits":{"context_tokens":16384,"max_active_workspaces":8}
        }),
    )
    .unwrap();
    assert_eq!(effective, local);
}

#[test]
fn execution_preference_is_independent_but_managed_policy_can_only_narrow_it() {
    let local = ContextAssistanceConfig::parse(json!({
        "features":{"execution_context":true}
    }))
    .unwrap();
    assert!(!local.enabled && !local.features.agent_context && !local.features.shared_agents);
    assert!(local.features.execution_context);
    let restricted =
        restrict_config(&local, &json!({"features":{"execution_context":false}})).unwrap();
    assert!(!restricted.features.execution_context);
    assert!(
        !restrict_config(&restricted, &json!({"features":{"execution_context":true}}))
            .unwrap()
            .features
            .execution_context
    );
    for malformed in [json!(null), json!(1), json!("true")] {
        assert!(ContextAssistanceConfig::parse(
            json!({"features":{"execution_context":malformed}})
        )
        .is_err());
        assert!(
            restrict_config(&local, &json!({"features":{"execution_context":malformed}})).is_err()
        );
    }
}

#[test]
fn restrictive_composition_preserves_only_locally_selected_runtime_and_sources() {
    let local = ContextAssistanceConfig::parse(json!({
        "enabled":true,"runtime_id":"runtime-1",
        "features":{"agent_context":true,"shared_agents":true},
        "sources":{"workspace_documents":true,"source_set_id":"sources-1"},
        "storage":{"mode":"sqlite","retention_hours":72}
    }))
    .unwrap();
    let effective = restrict_config(
        &local,
        &json!({
            "features":{"agent_context":false},
            "sources":{"workspace_documents":false},
            "storage":{"mode":"memory","retention_hours":24},
            "limits":{"context_tokens":1024,"max_active_workspaces":1}
        }),
    )
    .unwrap();
    assert!(effective.enabled);
    assert!(!effective.features.agent_context);
    assert!(!effective.features.shared_agents);
    assert!(!effective.sources.workspace_documents);
    assert_eq!(effective.runtime_id, "runtime-1");
    assert_eq!(effective.sources.source_set_id, "sources-1");
    assert_eq!(effective.storage.mode, StorageMode::Memory);
    assert_eq!(effective.storage.retention_hours, 24);
    assert_eq!(effective.limits.context_tokens, 1024);
    assert_eq!(effective.limits.max_active_workspaces, 1);
}

#[test]
fn restrictions_cannot_select_a_new_runtime_or_source_set() {
    for restriction in [
        json!({"runtime_id":"different-runtime"}),
        json!({"sources":{"source_set_id":"different-source"}}),
        json!({"worker_path":"/tmp/replacement"}),
        json!({"enabled":"true"}),
        json!({"enabled":null}),
        json!({"features":{"agent_context":null}}),
        json!({"schema_version":2}),
    ] {
        assert!(restrict_config(&ContextAssistanceConfig::default(), &restriction).is_err());
    }
}

#[test]
fn impossible_restricted_budgets_are_refused_without_silently_reducing_reserves() {
    let local = ContextAssistanceConfig::default();
    assert!(restrict_config(&local, &json!({"limits":{"context_tokens":128}})).is_err());
    assert!(restrict_config(&local, &json!({"limits":{"max_active_workspaces":0}})).is_err());
    assert!(restrict_config(&local, &json!({"storage":{"retention_hours":0}})).is_err());
    let effective = restrict_config(&local, &json!({"limits":{"reserve_tokens":512}})).unwrap();
    assert_eq!(effective.limits.reserve_tokens, 512);
    assert_eq!(local.limits.reserve_tokens, 256);
}

#[test]
fn portable_preferences_cannot_reactivate_machine_local_access() {
    let local = ContextAssistanceConfig::parse(json!({
        "enabled":true,"runtime_id":"private-runtime",
        "sources":{"workspace_documents":true,"source_set_id":"private-sources"},
        "limits":{"context_tokens":1024}
    }))
    .unwrap();
    let portable = local.for_export();
    portable.validate().unwrap();
    assert!(!portable.enabled);
    assert!(portable.runtime_id.is_empty());
    assert!(!portable.sources.workspace_documents);
    assert!(portable.sources.source_set_id.is_empty());
    assert_eq!(portable.limits.context_tokens, 1024);
    assert!(local.enabled);
}
