use super::*;

fn triggers(level: &str, overrides: &[(&str, &str)]) -> ReviewTriggers {
    let risk_actions = (!overrides.is_empty()).then(|| {
        overrides
            .iter()
            .map(|(key, action)| ((*key).to_string(), (*action).to_string()))
            .collect()
    });
    ReviewTriggers::from_config(GuardConfig {
        security_level: level.to_string(),
        risk_actions,
        ..GuardConfig::default()
    })
}

fn reason(code: &str) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code.to_string()));
    reason.insert(
        "message".to_string(),
        Value::String(format!("{code} pauses")),
    );
    reason.insert("severity".to_string(), Value::String("medium".to_string()));
    reason
}

fn package(decision: &str, codes: &[&str]) -> Map<String, Value> {
    let mut package = Map::new();
    package.insert("name".to_string(), Value::String("left-pad".to_string()));
    package.insert("decision".to_string(), Value::String(decision.to_string()));
    package.insert(
        "reasons".to_string(),
        Value::Array(
            codes
                .iter()
                .map(|code| Value::Object(reason(code)))
                .collect(),
        ),
    );
    package
}

fn result_with(packages: Vec<Map<String, Value>>) -> PackageEvalResult {
    PackageEvalResult {
        decision: "ask".to_string(),
        packages,
        ..PackageEvalResult::default()
    }
}

#[test]
fn balanced_records_signals_that_only_mean_guard_cannot_vouch() {
    let balanced = triggers("balanced", &[]);
    for key in [
        PACKAGE_UNKNOWN,
        PACKAGE_LOCKFILE_DRIFT,
        PACKAGE_DIRECT_SOURCE,
        PACKAGE_CUSTOM_REGISTRY,
        PACKAGE_INSTALL,
    ] {
        assert_eq!(balanced.decision(key), "monitor", "{key}");
    }
}

#[test]
fn strict_keeps_unknown_packages_blocked_and_reviews_drift_and_direct_sources() {
    let strict = triggers("strict", &[]);
    assert_eq!(strict.decision(PACKAGE_UNKNOWN), "block");
    assert_eq!(strict.decision(PACKAGE_LOCKFILE_DRIFT), "ask");
    assert_eq!(strict.decision(PACKAGE_DIRECT_SOURCE), "ask");
    assert_eq!(strict.decision(PACKAGE_INSTALL), "monitor");
}

#[test]
fn paranoid_blocks_every_install_and_custom_registry() {
    let paranoid = triggers("paranoid", &[]);
    assert_eq!(paranoid.decision(PACKAGE_INSTALL), "block");
    assert_eq!(paranoid.decision(PACKAGE_CUSTOM_REGISTRY), "block");
}

#[test]
fn a_user_risk_action_overrides_the_level_default() {
    let opted_in = triggers(
        "balanced",
        &[(PACKAGE_LOCKFILE_DRIFT, "require-reapproval")],
    );
    assert_eq!(opted_in.decision(PACKAGE_LOCKFILE_DRIFT), "ask");
    assert_eq!(opted_in.decision(PACKAGE_UNKNOWN), "monitor");
}

#[test]
fn a_tunable_review_is_recorded_quietly_under_balanced() {
    let mut result = result_with(vec![package(
        "ask",
        &["no_cached_match", "unidentified_package"],
    )]);
    assert!(resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        false
    ));
    let package = &result.packages[0];
    assert_eq!(decision_of(package), "monitor");
    let codes: Vec<String> = package_reasons(package)
        .iter()
        .filter_map(|reason| optional_string(reason.get("code")))
        .collect();
    assert_eq!(codes, vec!["no_cached_match".to_string()]);
    let message = optional_string(package_reasons(package)[0].get("message")).unwrap();
    assert!(
        !message.to_ascii_lowercase().contains("review"),
        "{message}"
    );
}

#[test]
fn a_review_with_any_non_tunable_reason_is_kept() {
    let mut result = result_with(vec![package(
        "ask",
        &["no_cached_match", "install_script_risk"],
    )]);
    assert!(!resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        false
    ));
    assert_eq!(decision_of(&result.packages[0]), "ask");
}

#[test]
fn cloud_fallback_annotations_do_not_hold_a_tunable_review() {
    let mut result = result_with(vec![package(
        "ask",
        &["manifest_lockfile_unsynced", "cloud_timeout"],
    )]);
    assert!(resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        false
    ));
    assert_eq!(decision_of(&result.packages[0]), "monitor");
}

#[test]
fn guard_own_release_review_is_never_relaxed() {
    let mut own = package("ask", &["no_cached_match", "unidentified_package"]);
    own.insert(OWN_PACKAGE_RELEASE_FIELD.to_string(), Value::Bool(true));
    let mut result = result_with(vec![own]);
    assert!(!resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        false
    ));
    let package = &result.packages[0];
    assert_eq!(decision_of(package), "ask");
    assert!(package.get(OWN_PACKAGE_RELEASE_FIELD).is_none());
}

#[test]
fn guard_distribution_from_a_direct_source_keeps_its_review() {
    let mut own = package("ask", &["git_dependency_source"]);
    own.insert("name".to_string(), Value::String("HOL_Guard".to_string()));
    own.insert("ecosystem".to_string(), Value::String("pypi".to_string()));
    let mut other = own.clone();
    other.insert("ecosystem".to_string(), Value::String("npm".to_string()));
    let mut result = result_with(vec![own, other]);
    assert!(resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        false
    ));
    assert_eq!(decision_of(&result.packages[0]), "ask");
    assert_eq!(decision_of(&result.packages[1]), "monitor");
}

#[test]
fn guard_distribution_into_a_guard_free_environment_follows_settings() {
    // A local wheel of Guard installed into a separate environment that holds
    // no Guard cannot replace the running one, so the user's settings decide
    // it: a direct source is recorded quietly, as for any other package.
    let mut direct = package("ask", &["local_path_dependency_source"]);
    direct.insert("name".to_string(), Value::String("hol_guard".to_string()));
    direct.insert("ecosystem".to_string(), Value::String("pypi".to_string()));
    let mut unpublished = package("ask", &["no_cached_match", "unidentified_package"]);
    unpublished.insert(OWN_PACKAGE_RELEASE_FIELD.to_string(), Value::Bool(true));
    let mut result = result_with(vec![direct, unpublished]);
    assert!(resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        true
    ));
    assert_eq!(decision_of(&result.packages[0]), "monitor");
    assert_eq!(decision_of(&result.packages[1]), "monitor");
    assert!(result.packages[1].get(OWN_PACKAGE_RELEASE_FIELD).is_none());
}

fn install_artifact(redacted_command: &str, cwd: Option<&Path>) -> GuardArtifact {
    GuardArtifact {
        artifact_id: "pypi:hol-guard".into(),
        name: "hol-guard".into(),
        harness: "shell".into(),
        artifact_type: "package-request".into(),
        source_scope: "local".into(),
        config_path: String::new(),
        command: None,
        args: vec![],
        url: None,
        transport: None,
        publisher: None,
        metadata: serde_json::json!({
            "redacted_command": redacted_command,
            "effective_cwd": cwd.map(|cwd| cwd.display().to_string()),
        }),
        runtime_private_metadata: Value::Object(Map::new()),
    }
}

#[test]
fn guard_free_target_reads_the_redacted_command_and_its_working_directory() {
    // The artifact carries the shell-quoted command and the directory it ran
    // in; a path with a space must survive the quoting round trip.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("release candidate");
    let python = project.join(".venv/bin/python");
    std::fs::create_dir_all(python.parent().unwrap()).unwrap();
    std::fs::write(&python, b"").unwrap();
    let tokens = |interpreter: &str| {
        [
            "uv",
            "pip",
            "install",
            "--python",
            interpreter,
            "--no-deps",
            "./dist/hol_guard-3.61.0-py3-none-any.whl",
        ]
        .map(str::to_string)
    };
    let absolute =
        crate::package_intent_common::redacted_command(&tokens(&python.display().to_string()));
    assert!(installs_into_guard_free_environment(
        &install_artifact(&absolute, None),
        None
    ));
    let relative = crate::package_intent_common::redacted_command(&tokens(".venv/bin/python"));
    assert!(installs_into_guard_free_environment(
        &install_artifact(&relative, Some(&project)),
        None
    ));
    assert!(installs_into_guard_free_environment(
        &install_artifact(&relative, None),
        Some(&project)
    ));
    assert!(!installs_into_guard_free_environment(
        &install_artifact(&relative, None),
        None
    ));

    // Guard already installed there keeps the review.
    std::fs::write(project.join(".venv/bin/hol-guard"), b"").unwrap();
    assert!(!installs_into_guard_free_environment(
        &install_artifact(&absolute, None),
        None
    ));
}

#[test]
fn guard_distribution_into_a_guard_free_environment_keeps_risk_reviews() {
    // A separate environment relaxes only the replace-Guard floor. A setting
    // that reviews direct sources, and every non-tunable risk, still holds.
    let mut direct = package("ask", &["local_path_dependency_source"]);
    direct.insert("name".to_string(), Value::String("hol-guard".to_string()));
    direct.insert("ecosystem".to_string(), Value::String("pypi".to_string()));
    let mut advisory = direct.clone();
    advisory.insert(
        "reasons".to_string(),
        Value::Array(vec![Value::Object(reason("runtime_known_vulnerable"))]),
    );
    let mut result = result_with(vec![direct, advisory]);
    let review_direct = triggers("balanced", &[(PACKAGE_DIRECT_SOURCE, "review")]);
    assert!(!resolve_packages(&review_direct, &mut result, true));
    assert_eq!(decision_of(&result.packages[0]), "ask");
    assert_eq!(decision_of(&result.packages[1]), "ask");
}

#[test]
fn guard_distribution_from_the_registry_follows_settings() {
    let mut own = package("ask", &["no_cached_match"]);
    own.insert("name".to_string(), Value::String("hol-guard".to_string()));
    own.insert("ecosystem".to_string(), Value::String("pypi".to_string()));
    let mut custom_index = own.clone();
    custom_index.insert(
        "reasons".to_string(),
        Value::Array(vec![Value::Object(reason(PACKAGE_CUSTOM_REGISTRY_CODE))]),
    );
    let mut result = result_with(vec![own, custom_index]);
    assert!(resolve_packages(
        &triggers("balanced", &[]),
        &mut result,
        false
    ));
    assert_eq!(decision_of(&result.packages[0]), "monitor");
    assert_eq!(decision_of(&result.packages[1]), "ask");
}

#[test]
fn a_package_script_review_holds_an_install_that_could_run_package_code() {
    let codes = ["no_cached_match", LIFECYCLE_SCRIPTS_ENABLED_CODE];
    let mut balanced = result_with(vec![package("ask", &codes)]);
    assert!(resolve_packages(
        &triggers("balanced", &[]),
        &mut balanced,
        false
    ));
    assert_eq!(decision_of(&balanced.packages[0]), "monitor");
    let ask_lifecycle = triggers("balanced", &[(PACKAGE_SCRIPT, "require-reapproval")]);
    let mut opted_in = result_with(vec![package("ask", &codes)]);
    assert!(!resolve_packages(&ask_lifecycle, &mut opted_in, false));
    assert_eq!(decision_of(&opted_in.packages[0]), "ask");
}

#[test]
fn strict_raises_a_tunable_review_to_its_configured_action() {
    let mut result = result_with(vec![package("ask", &["no_cached_match"])]);
    assert!(resolve_packages(
        &triggers("strict", &[]),
        &mut result,
        false
    ));
    assert_eq!(decision_of(&result.packages[0]), "block");
}

#[test]
fn an_opt_in_trigger_raises_every_quieter_package() {
    let mut result = result_with(vec![package("monitor", &["no_cached_match"])]);
    assert!(raise_packages(
        &mut result,
        "ask",
        PACKAGE_INSTALL_CODE,
        "Your settings review every package install or update.",
    ));
    let package = &result.packages[0];
    assert_eq!(decision_of(package), "ask");
    assert!(
        package_reasons(package)
            .iter()
            .any(|reason| optional_string(reason.get("code")).as_deref()
                == Some(PACKAGE_INSTALL_CODE))
    );
}
