use super::*;

#[test]
fn first_enable_write_is_refused_without_a_native_enrolled_314_installation() {
    let root = tempfile::tempdir().unwrap();
    let request = json!({"schema":"guard-config-update.v1", "guard_home":root.path(), "kind":"settings",
        "value_text":json!({"context_assistance":{"enabled":true,"runtime_id":"not-enrolled"}}).to_string()});
    let result: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(result["ok"], false);
    assert!(result["invalid"].as_str().unwrap().contains("CPython 3.14"));
    assert!(!root.path().join("config.toml").exists());
    assert!(!root.path().join("context-assistance").exists());
}

fn settings(
    stored: Option<&str>,
    payload: Value,
    managed: Option<ManagedInput>,
) -> Result<Computed, Failure> {
    let payload = pyjson::parse(&payload.to_string()).unwrap();
    compute(
        "settings",
        stored,
        &payload,
        managed.as_ref(),
        false,
        "2026-10-23T00:00:00+00:00",
    )
}

#[test]
fn context_settings_roundtrip_through_the_native_writer_and_loader() {
    let result = settings(
        None,
        json!({"context_assistance":{
            "enabled":true,"runtime_id":"selected-runtime","limits":{"context_tokens":1024}
        }}),
        None,
    )
    .unwrap();
    let table: toml::Table = result.text.parse().unwrap();
    let map = serde_json::to_value(table)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let loaded = current_config(&map, None);
    assert_eq!(loaded["context_assistance"]["enabled"], true);
    assert_eq!(
        loaded["context_assistance"]["runtime_id"],
        "selected-runtime"
    );
    assert_eq!(
        loaded["context_assistance"]["limits"]["context_tokens"],
        1024
    );
    assert_eq!(loaded["context_assistance_export"]["enabled"], false);
    assert_eq!(loaded["context_assistance_export"]["runtime_id"], "");
    assert_eq!(loaded["mode"], "prompt");
}

#[test]
fn malformed_context_settings_never_produce_a_write() {
    for value in [
        json!({"enabled":"true"}),
        json!({"enabled":true}),
        json!({"runtime_id":"/tmp/python"}),
        json!({"worker_path":"/tmp/worker"}),
        json!({"limits":{"max_active_workspaces":0}}),
    ] {
        assert!(matches!(
            settings(None, json!({"context_assistance":value}), None),
            Err(Failure::Invalid(_))
        ));
    }
}

#[test]
fn managed_locked_assistance_cannot_be_enabled_by_settings_write() {
    let policy = serde_json::from_value(json!({
        "settings":{"context_assistance":{"enabled":false}},
        "locked_settings":["context_assistance.enabled"]
    }))
    .unwrap();
    assert!(matches!(
        settings(
            None,
            json!({"context_assistance":{
                "enabled":true,"runtime_id":"selected-runtime"
            }}),
            Some(policy)
        ),
        Err(Failure::Invalid(_))
    ));
}

#[test]
fn clearing_and_resetting_context_preferences_does_not_change_base_guard_settings() {
    let stored =
        "mode = 'enforce'\n[context_assistance]\nenabled = true\nruntime_id = 'selected-runtime'\n";
    let cleared = settings(Some(stored), json!({"context_assistance":null}), None).unwrap();
    let table: toml::Table = cleared.text.parse().unwrap();
    assert_eq!(table["mode"].as_str(), Some("enforce"));
    assert_eq!(
        table["context_assistance"]["enabled"].as_bool(),
        Some(false)
    );
    let reset = compute(
        "reset",
        Some(stored),
        &PyVal::Null,
        None,
        false,
        "2026-10-23T00:00:00+00:00",
    )
    .unwrap();
    assert!(!reset.text.contains("context_assistance"));
}
