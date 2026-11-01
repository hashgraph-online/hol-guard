use super::*;
use serde_json::json;

fn interpreter() -> InterpreterFacts {
    InterpreterFacts {
        schema: "guard-cigar-interpreter.v1".into(),
        implementation: "cpython".into(),
        version: [3, 14, 7],
        release_level: "final".into(),
        free_threaded: false,
        debug_build: false,
        abi: "cpython-314-darwin".into(),
        platform: "darwin-arm64".into(),
    }
}

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

#[test]
fn only_final_cpython_314_passes_version_eligibility() {
    let mut facts = interpreter();
    assert_eq!(check_interpreter(&facts), Ok(()));
    for version in [
        [3, 10, 0],
        [3, 11, 0],
        [3, 12, 0],
        [3, 13, 9],
        [3, 15, 0],
        [4, 14, 0],
    ] {
        facts.version = version;
        assert_eq!(
            check_interpreter(&facts),
            Err(UnavailableReason::PythonVersionUnsupported)
        );
    }
    facts = interpreter();
    for release in ["alpha", "beta", "candidate", "FINAL", ""] {
        facts.release_level = release.into();
        assert_eq!(
            check_interpreter(&facts),
            Err(UnavailableReason::PythonVersionUnsupported)
        );
    }
    facts = interpreter();
    facts.implementation = "pypy".into();
    assert_eq!(
        check_interpreter(&facts),
        Err(UnavailableReason::PythonImplementationUnsupported)
    );
}

#[test]
fn unqualified_builds_and_unknown_platforms_are_unavailable() {
    let mut facts = interpreter();
    facts.free_threaded = true;
    assert_eq!(
        check_interpreter(&facts),
        Err(UnavailableReason::PythonBuildUnqualified)
    );
    facts = interpreter();
    facts.debug_build = true;
    assert_eq!(
        check_interpreter(&facts),
        Err(UnavailableReason::PythonBuildUnqualified)
    );
    facts = interpreter();
    facts.abi = "cpython-313-darwin".into();
    assert_eq!(
        check_interpreter(&facts),
        Err(UnavailableReason::PythonBuildUnqualified)
    );
    facts = interpreter();
    for platform in [
        "win32-arm64",
        "linux-x64-unknown",
        "unknown-x64",
        "darwin-*",
        "",
    ] {
        facts.platform = platform.into();
        assert_eq!(
            check_interpreter(&facts),
            Err(UnavailableReason::PlatformUnsupported)
        );
    }
}

#[test]
fn malformed_probe_records_are_not_tolerated() {
    let mut facts = interpreter();
    facts.schema = "caller-supplied.v1".into();
    assert_eq!(
        check_interpreter(&facts),
        Err(UnavailableReason::PythonReportInvalid)
    );
    let mut wire = serde_json::to_value(interpreter()).unwrap();
    wire["trusted"] = json!(true);
    assert!(serde_json::from_value::<InterpreterFacts>(wire).is_err());
}

#[test]
fn platform_and_abi_must_describe_the_same_supported_process() {
    for (platform, abi) in [
        ("darwin-arm64", "cpython-314-darwin"),
        ("darwin-x64", "cpython-314-darwin"),
        ("linux-arm64-gnu", "cpython-314-aarch64-linux-gnu"),
        ("linux-x64-gnu", "cpython-314-x86_64-linux-gnu"),
        ("linux-arm64-musl", "cpython-314-aarch64-linux-musl"),
        ("linux-x64-musl", "cpython-314-x86_64-linux-musl"),
        ("win32-x64", "cp314-win_amd64"),
    ] {
        let mut facts = interpreter();
        facts.platform = platform.into();
        facts.abi = abi.into();
        assert_eq!(check_interpreter(&facts), Ok(()));
        facts.abi = "cpython-314-forged".into();
        assert_eq!(
            check_interpreter(&facts),
            Err(UnavailableReason::PythonBuildUnqualified)
        );
    }
    let mut facts = interpreter();
    facts.abi = "cp314-win_amd64".into();
    assert_eq!(
        check_interpreter(&facts),
        Err(UnavailableReason::PythonBuildUnqualified)
    );
}
