use super::*;
use crate::managed_policy_load::ManagedPolicySource;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

/// A guard home with its own managed-policy root, so no machine policy is read.
fn home(tag: &str) -> (PathBuf, ManagedPolicySource) {
    let home = std::env::temp_dir().join(format!(
        "mcp-relay-session-config-{tag}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir_all(&home).unwrap();
    let mut source = ManagedPolicySource::native();
    source.machine_root = Some(home.join("machine-root"));
    fs::create_dir_all(source.machine_root.as_ref().unwrap()).unwrap();
    (home, source)
}

fn binding(mode: Option<&str>, level: Option<&str>) -> Arc<DirectLaneBinding> {
    let mut bound = json!({"config": {"mode": "enforce"}, "hash_config": {}});
    if let Some(level) = level {
        bound["receipt_redaction_level"] = json!(level);
    }
    let mut binding = DirectLaneBinding::empty_for_tests();
    binding.mcp_relay = Some(json!({
        "schema": "guard-mcp-relay-view.v2",
        "harnesses": {"codex": bound},
        "extension_layers": [],
    }));
    binding.review.blocked_request_mode = mode.map(str::to_owned);
    Arc::new(binding)
}

fn settings(
    binding: &Arc<DirectLaneBinding>,
    home: &Path,
    source: &ManagedPolicySource,
) -> SessionSettings {
    session_settings_under(binding, "codex", home.to_str().unwrap(), None, source)
}

#[test]
fn a_binding_that_disagrees_on_both_settings_takes_the_session_configs() {
    let (home, source) = home("both");
    fs::write(
        home.join("config.toml"),
        "blocked_request_mode = \"ask\"\nreceipt_redaction_level = \"partial\"\n",
    )
    .unwrap();
    let session = settings(&binding(None, None), &home, &source);
    assert_eq!(session.blocked_request_mode(None), Some("ask"));
    assert_eq!(session.redaction_level(None), Some("partial"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn a_session_config_without_the_settings_takes_the_loader_defaults() {
    let (home, source) = home("defaults");
    let session = settings(&binding(None, None), &home, &source);
    assert_eq!(session.blocked_request_mode(None), Some("safe-alternative"));
    assert_eq!(session.redaction_level(None), Some("full"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn either_unbound_setting_reads_the_config_and_a_bound_one_still_wins() {
    let (home, source) = home("one");
    fs::write(
        home.join("config.toml"),
        "blocked_request_mode = \"ask\"\nreceipt_redaction_level = \"none\"\n",
    )
    .unwrap();
    let mode_only = binding(None, Some("full"));
    let session = settings(&mode_only, &home, &source);
    assert_eq!(session.blocked_request_mode(None), Some("ask"));
    assert_eq!(session.redaction_level(Some("full")), Some("full"));
    let level_only = binding(Some("safe-alternative"), None);
    let session = settings(&level_only, &home, &source);
    assert_eq!(
        session.blocked_request_mode(Some("safe-alternative")),
        Some("safe-alternative")
    );
    assert_eq!(session.redaction_level(None), Some("none"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn a_binding_that_carries_both_settings_never_reads_the_config() {
    let (home, source) = home("bound");
    // A config the loader would refuse: reading it would leave both unbound.
    fs::write(home.join("config.toml"), "blocked_request_mode = [\n").unwrap();
    let session = settings(&binding(Some("ask"), Some("partial")), &home, &source);
    assert_eq!(session, SessionSettings::default());
    let _ = fs::remove_dir_all(home);
}

#[test]
fn a_config_the_loader_cannot_compose_leaves_the_call_unbound() {
    let (home, source) = home("malformed");
    fs::write(home.join("config.toml"), "blocked_request_mode = [\n").unwrap();
    let session = settings(&binding(None, None), &home, &source);
    assert_eq!(session.blocked_request_mode(None), None);
    assert_eq!(session.redaction_level(None), None);
    let _ = fs::remove_dir_all(home);
}

#[test]
fn a_harness_the_view_does_not_bind_reads_nothing_for_its_level() {
    let (home, source) = home("unbound-harness");
    fs::write(home.join("config.toml"), "blocked_request_mode = [\n").unwrap();
    let bound = binding(Some("ask"), Some("full"));
    let session = session_settings_under(&bound, "cursor", home.to_str().unwrap(), None, &source);
    assert_eq!(session, SessionSettings::default());
    let _ = fs::remove_dir_all(home);
}
