use super::*;
use std::io::Write;
use std::path::PathBuf;

#[path = "context_assistance_action_installed_tests.rs"]
mod actions;
#[path = "context_assistance_agent_installed_tests.rs"]
mod agents;
#[cfg(unix)]
#[path = "context_assistance_config_snapshot_tests.rs"]
mod config_snapshot;
#[path = "context_assistance_history_installed_tests.rs"]
mod history;
#[path = "context_assistance_installed_tests.rs"]
mod installed;
#[cfg(unix)]
#[path = "context_assistance_persistent_installed_tests.rs"]
mod persistent;
#[path = "context_assistance_receipts_tests.rs"]
mod receipts;
#[cfg(unix)]
#[path = "context_assistance_saved_data_tests.rs"]
mod saved_data;
#[path = "context_assistance_shared_installed_tests.rs"]
mod shared;
#[path = "context_assistance_workspace_tests.rs"]
mod workspace;

struct Fixture {
    home: PathBuf,
    store: PolicySnapshotStore,
}
impl Fixture {
    fn agent(&self, input: serde_json::Value) -> serde_json::Value {
        let frame = json!({"operation":"context_agent", "request":{"schema":"guard-context-agent-request.v1",
            "request_id":"private-agent", "query":{"kind":"agent","guard_home":self.home,"input":input}}});
        serde_json::from_slice(
            &crate::resident_protocol::evaluate_resident_bytes(
                frame.to_string().as_bytes(),
                Some(&self.store),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-cigar-control-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        let home = crate::resident_state::ensure_private_directory(&path, true).unwrap();
        let mut fixture_key =
            crate::resident_state::private_file(&home.join("policy-verifier.key"), true, &home)
                .unwrap();
        fixture_key.write_all(&[29_u8; 32]).unwrap();
        drop(fixture_key);
        let store = PolicySnapshotStore::new(&home, &"a".repeat(64)).unwrap();
        Self { home, store }
    }
    fn ask(&self, kind: &str) -> serde_json::Value {
        self.ask_input(kind, json!({}))
    }
    fn ask_input(&self, kind: &str, input: serde_json::Value) -> serde_json::Value {
        let request: Request = serde_json::from_value(
            json!({"schema":"guard-context-assistance-request.v1", "request_id":"test-control",
            "query":{"kind":kind,"guard_home":self.home,"input":input}}),
        )
        .unwrap();
        let frame = json!({"operation":"context_assistance", "request":request});
        serde_json::from_slice(
            &crate::resident_protocol::evaluate_resident_bytes(
                frame.to_string().as_bytes(),
                Some(&self.store),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn control_feature_requires_a_scoped_resident_and_has_no_oneshot_sdk_fallback() {
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|feature| feature == FEATURE));
    let frame = json!({"operation":"context_assistance", "request":{"schema":"guard-context-assistance-request.v1",
        "request_id":"oneshot", "query":{"kind":"status","guard_home":"/not-opened","input":{}}}});
    assert_eq!(
        crate::resident_protocol::evaluate_resident_bytes(frame.to_string().as_bytes(), None)
            .unwrap_err(),
        "native_context_assistance_resident_required"
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.home).unwrap();
    }
}

#[test]
fn status_is_bound_off_and_activation_cannot_bypass_local_consent() {
    let fixture = Fixture::new();
    let status = fixture.ask("status");
    assert_eq!(status["status"], "ok");
    assert_eq!(status["payload"]["state"]["effective_enabled"], false);
    assert!(status["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        fixture.ask("activate")["code"],
        "native_context_assistance_disabled"
    );
    assert!(!fixture.home.join("context-assistance").exists());
}

#[test]
fn foreign_home_and_caller_supplied_runtime_authority_are_refused() {
    let fixture = Fixture::new();
    let request: Request = serde_json::from_value(
        json!({"schema":"guard-context-assistance-request.v1", "request_id":"foreign",
        "query":{"kind":"status","guard_home":"/foreign/home","input":{}}}),
    )
    .unwrap();
    let answer: serde_json::Value =
        serde_json::from_slice(&evaluate(&request, &fixture.store).unwrap()).unwrap();
    assert_eq!(answer["code"], "native_guard_home_mismatch");
    for authority in [
        json!({"implementation":"cpython","version":[3,14,7]}),
        json!({"worker_sha256":"0".repeat(64)}),
    ] {
        assert!(serde_json::from_value::<Request>(
            json!({"schema":"guard-context-assistance-request.v1", "request_id":"injected",
            "query":{"kind":"activate","guard_home":fixture.home,"input":{},"authority":authority}})
        )
        .is_err());
        let request: Request = serde_json::from_value(
            json!({"schema":"guard-context-assistance-request.v1", "request_id":"injected-body",
            "query":{"kind":"activate","guard_home":fixture.home,"input":{"authority":authority}}}),
        )
        .unwrap();
        let reply: serde_json::Value =
            serde_json::from_slice(&evaluate(&request, &fixture.store).unwrap()).unwrap();
        assert_eq!(
            reply["code"],
            "native_context_assistance_control_input_invalid"
        );
    }
}

#[test]
fn stop_persists_opt_out_without_erasing_other_preferences_or_guard_mode() {
    let fixture = Fixture::new();
    std::fs::write(fixture.home.join("config.toml"), "mode='enforce'\n[context_assistance]\nenabled=true\nruntime_id='retained-runtime'\n[context_assistance.limits]\ncontext_tokens=1024\n").unwrap();
    let answer = fixture.ask("stop");
    assert_eq!(answer["status"], "ok");
    let table: toml::Table = std::fs::read_to_string(fixture.home.join("config.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(table["mode"].as_str(), Some("enforce"));
    assert_eq!(
        table["context_assistance"]["enabled"].as_bool(),
        Some(false)
    );
    assert_eq!(
        table["context_assistance"]["runtime_id"].as_str(),
        Some("retained-runtime")
    );
    assert_eq!(
        table["context_assistance"]["limits"]["context_tokens"].as_integer(),
        Some(1024)
    );
    assert!(answer["payload"]["state"]["runtime"].is_null());
}
