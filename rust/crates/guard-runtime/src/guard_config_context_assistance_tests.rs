use super::*;
use std::fs;

fn load_case(home: &str, files: &[(&str, &str)], managed: Option<Value>) -> Value {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("home")).unwrap();
    fs::create_dir(root.path().join("workspace")).unwrap();
    fs::write(root.path().join("home/config.toml"), home).unwrap();
    for (name, contents) in files {
        fs::write(root.path().join("workspace").join(name), contents).unwrap();
    }
    let request = json!({
        "schema":"guard-config-load.v1",
        "guard_home":root.path().join("home"),
        "workspace":root.path().join("workspace"),
        "managed":managed,
    });
    let response: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    assert_eq!(response["ok"], true, "{response}");
    response["config"].clone()
}

const CONSENT: &str = "[context_assistance]\nenabled=true\nruntime_id='selected-runtime'\n";

#[test]
fn control_configuration_reads_native_machine_restrictions_and_invalid_authority_disables_assistance(
) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("config.toml"), CONSENT).unwrap();
    let profile = root.path().join("managed.json");
    fs::write(&profile, json!({"schemaVersion":"hol-guard-mdm-policy.v1", "settings":{"context_assistance":{"enabled":false}}}).to_string()).unwrap();
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.policy_path = Some(profile.clone());
    source.write_cache = false;
    let settings = context_assistance_from_source(&home, &source).unwrap();
    assert!(settings.requested.enabled);
    assert!(!settings.effective.enabled);
    assert_eq!(settings.restriction, Some("managed_policy"));
    assert!(!settings.verification_permitted);
    let service = crate::context_assistance_service::Service::default();
    service.configure(settings).unwrap();
    let restricted = service.status().unwrap();
    assert_eq!(restricted["requested_enabled"], true);
    assert_eq!(restricted["effective_enabled"], false);
    println!("GUARD_CIGAR_RESTRICTION_VERIFICATION={restricted}");
    fs::write(&profile, "not valid policy").unwrap();
    let settings = context_assistance_from_source(&home, &source).unwrap();
    assert!(settings.requested.enabled);
    assert!(!settings.effective.enabled);
    assert_eq!(
        settings.diagnostic.as_deref(),
        Some("managed_policy_unavailable")
    );
}

#[test]
fn absence_has_no_assistance_state_or_runtime_selection() {
    let config = load_case("", &[], None);
    assert!(config["context_assistance"].is_null());
    assert!(config["context_assistance_requested"].is_null());
    assert!(config["context_assistance_export"].is_null());
    assert!(config["context_assistance_diagnostic"].is_null());
    assert_eq!(config["mode"], "prompt");
}

#[test]
fn only_home_configuration_can_record_runtime_selection_and_opt_in() {
    let config = load_case(CONSENT, &[], None);
    assert_eq!(config["context_assistance"]["enabled"], true);
    assert_eq!(
        config["context_assistance"]["runtime_id"],
        "selected-runtime"
    );
    assert!(config["context_assistance_diagnostic"].is_null());
    let workspace = load_case(
        "",
        &[(".hol-guard.toml", "[context_assistance]\nenabled=true\n")],
        None,
    );
    assert_eq!(workspace["context_assistance"]["enabled"], false);
    assert_eq!(workspace["context_assistance"]["runtime_id"], "");
}

#[test]
fn both_workspace_files_are_intersected_instead_of_last_writer_winning() {
    let config = load_case(
        CONSENT,
        &[
            (
                ".ai-plugin-scanner-guard.toml",
                "[context_assistance]\nenabled=false\n",
            ),
            (".hol-guard.toml", "[context_assistance]\nenabled=true\n"),
        ],
        None,
    );
    assert_eq!(config["context_assistance"]["enabled"], false);
    assert_eq!(config["context_assistance_requested"]["enabled"], true);
    assert_eq!(
        config["context_assistance"]["runtime_id"],
        "selected-runtime"
    );
}

#[test]
fn workspace_permission_and_resource_expansion_does_not_create_consent() {
    let config = load_case(
        CONSENT,
        &[(
            ".hol-guard.toml",
            "\
[context_assistance.features]\nagent_context=true\nshared_agents=true\n\
[context_assistance.sources]\nworkspace_documents=true\n\
[context_assistance.limits]\ncontext_tokens=16384\nmax_active_workspaces=8\n",
        )],
        None,
    );
    let context = &config["context_assistance"];
    assert_eq!(context["enabled"], true);
    assert_eq!(context["features"]["agent_context"], false);
    assert_eq!(context["features"]["shared_agents"], false);
    assert_eq!(context["sources"]["workspace_documents"], false);
    assert_eq!(context["limits"]["context_tokens"], 2048);
    assert_eq!(context["limits"]["max_active_workspaces"], 2);
}

#[test]
fn malformed_or_runtime_selecting_workspace_restrictions_disable_only_assistance() {
    for restriction in ["enabled='yes'", "runtime_id='workspace-python'"] {
        let config = load_case(
            CONSENT,
            &[(
                ".hol-guard.toml",
                &format!("[context_assistance]\n{restriction}\n"),
            )],
            None,
        );
        assert_eq!(config["context_assistance"]["enabled"], false);
        assert_eq!(
            config["context_assistance_diagnostic"],
            "context_assistance_schema_invalid"
        );
        assert_eq!(config["mode"], "prompt");
    }
}

#[test]
fn malformed_stored_enablement_is_disabled_with_a_content_free_diagnostic() {
    let config = load_case(
        "[context_assistance]\nenabled='private-secret-value'\n",
        &[],
        None,
    );
    assert_eq!(config["context_assistance"]["enabled"], false);
    assert_eq!(
        config["context_assistance_diagnostic"],
        "context_assistance_schema_invalid"
    );
    assert!(!config.to_string().contains("private-secret-value"));
}

#[test]
fn managed_true_and_locked_true_never_enable_absent_local_consent() {
    for locks in [
        json!([]),
        json!(["context_assistance.enabled"]),
        json!(["context_assistance"]),
    ] {
        let config = load_case(
            "",
            &[],
            Some(json!({
                "settings":{"context_assistance":{"enabled":true}},"locked_settings":locks
            })),
        );
        assert_eq!(config["context_assistance"]["enabled"], false);
        assert_eq!(config["context_assistance"]["runtime_id"], "");
    }
}

#[test]
fn managed_restrictions_lower_caps_and_disable_permissions_without_reselecting_runtime() {
    let config = load_case(
        CONSENT,
        &[],
        Some(json!({
            "settings":{"context_assistance":{"enabled":false,"limits":{"context_tokens":1024}}},
            "locked_settings":["context_assistance.enabled"]
        })),
    );
    assert_eq!(config["context_assistance"]["enabled"], false);
    assert_eq!(
        config["context_assistance"]["limits"]["context_tokens"],
        1024
    );
    assert_eq!(
        config["context_assistance"]["runtime_id"],
        "selected-runtime"
    );
}

#[test]
fn export_projection_has_preferences_without_local_activation_or_source_references() {
    let home=format!("{CONSENT}[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='private-source-set'\n");
    let config = load_case(&home, &[], None);
    let portable = &config["context_assistance_export"];
    assert_eq!(portable["enabled"], false);
    assert_eq!(portable["runtime_id"], "");
    assert_eq!(portable["sources"]["workspace_documents"], false);
    assert_eq!(portable["sources"]["source_set_id"], "");
    assert!(!portable.to_string().contains("selected-runtime"));
    assert!(!portable.to_string().contains("private-source-set"));
    assert_eq!(config["context_assistance"]["enabled"], true);
}
