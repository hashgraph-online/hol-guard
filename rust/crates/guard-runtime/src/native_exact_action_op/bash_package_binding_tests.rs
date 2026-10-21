use super::*;
use guard_contracts::NativeScriptPackageStateV1 as State;

fn fixture() -> (tempfile::TempDir, NativeBashCaptureV1, PathBuf) {
    let (root, request) = tests::fixture();
    let package = Path::new(&request.cwd).join("node_modules/captured-dep");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("package.json"),
        r#"{"name":"captured-dep","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(package.join("library.sh"), "VALUE='reviewed'\n").unwrap();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "source './node_modules/captured-dep/library.sh'; printf '%s' \"$VALUE\"",
    )
    .unwrap();
    (root, request, package)
}

fn captured(request: &NativeBashCaptureV1) -> CapturedBash {
    capture_for_launch(request, &tests::admitted("allow")).unwrap()
}

#[test]
fn bash_package_binding_tracks_the_captured_members_and_declared_version() {
    let (_root, request, _package) = fixture();
    let value = captured(&request);
    let packages = &value.subject.package_bindings;
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].state, State::Declared);
    assert_eq!(packages[0].name.as_deref(), Some("captured-dep"));
    assert_eq!(packages[0].version.as_deref(), Some("1.0.0"));
    assert_eq!(packages[0].code_input_indices.len(), 1);
    let input = &value.subject.code_inputs[usize::from(packages[0].code_input_indices[0])];
    assert!(input
        .resolved_path
        .ends_with("/node_modules/captured-dep/library.sh"));
    assert_ne!(input.kind, NativeScriptInputKindV1::Interpreter);
    let policy = value.policy.unwrap();
    assert!(
        policy.allows_without_consent(),
        "{:?}",
        policy
            .decisions
            .iter()
            .map(|decision| (
                &decision.decision,
                &decision.minimum_action,
                &decision.reason_code
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn bash_package_binding_semantic_metadata_change_invalidates_but_description_does_not() {
    let (_root, request, package) = fixture();
    let original = captured(&request).subject.identity_sha256().unwrap();
    let original_times = std::fs::metadata(package.join("package.json")).unwrap();
    std::fs::write(package.join("package.json"),
        "{\n\"description\":\"ordinary package documentation\",\"version\":\"1.0.0\",\"name\":\"captured-dep\"\n}").unwrap();
    assert_eq!(
        original,
        captured(&request).subject.identity_sha256().unwrap()
    );
    std::fs::write(
        package.join("package.json"),
        r#"{"name":"captured-dep","version":"1.0.1"}"#,
    )
    .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(package.join("package.json"))
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(original_times.accessed().unwrap())
                .set_modified(original_times.modified().unwrap()),
        )
        .unwrap();
    assert_ne!(
        original,
        captured(&request).subject.identity_sha256().unwrap()
    );
}

#[test]
fn bash_package_binding_unknown_missing_and_oversized_metadata_never_becomes_declared() {
    let (_root, request, package) = fixture();
    let manifest = package.join("package.json");
    let original = captured(&request).subject.identity_sha256().unwrap();
    std::fs::write(&manifest, r#"{"name":"captured-dep","version":"^1"}"#).unwrap();
    let invalid = captured(&request);
    assert_eq!(
        invalid.subject.package_bindings[0].state,
        State::MetadataInvalid
    );
    assert_ne!(original, invalid.subject.identity_sha256().unwrap());
    std::fs::remove_file(&manifest).unwrap();
    let missing = captured(&request);
    assert_eq!(
        missing.subject.package_bindings[0].state,
        State::MetadataUnavailable
    );
    assert!(missing.subject.package_bindings[0].name.is_none());
    assert!(missing.policy.unwrap().allows_without_consent());
    std::fs::write(&manifest, "x".repeat(128 * 1024 + 1)).unwrap();
    let oversized = captured(&request);
    assert_eq!(
        oversized.subject.package_bindings[0].state,
        State::MetadataBudgetExceeded
    );
    assert!(oversized.policy.unwrap().allows_without_consent());
}

#[test]
fn bash_package_binding_does_not_follow_a_manifest_symlink() {
    let (_root, request, package) = fixture();
    let target = Path::new(&request.home_dir).join("private-metadata.json");
    std::fs::write(&target, r#"{"name":"private-material","version":"1.0.0"}"#).unwrap();
    let manifest = package.join("package.json");
    std::fs::remove_file(&manifest).unwrap();
    std::os::unix::fs::symlink(&target, &manifest).unwrap();
    let before = captured(&request).subject;
    assert_eq!(before.package_bindings[0].state, State::MetadataUnavailable);
    std::fs::write(
        &target,
        r#"{"name":"different-material","version":"2.0.0"}"#,
    )
    .unwrap();
    let after = captured(&request).subject;
    assert_eq!(before.identity_sha256(), after.identity_sha256());
}

#[test]
fn bash_package_binding_keeps_source_mutation_separate_from_manifest_attribution() {
    let (_root, request, package) = fixture();
    let original = captured(&request).subject;
    std::fs::write(package.join("library.sh"), "VALUE='changed!'\n").unwrap();
    let changed = captured(&request).subject;
    assert_eq!(original.package_bindings, changed.package_bindings);
    assert_ne!(original.identity_sha256(), changed.identity_sha256());
}

#[test]
fn bash_package_binding_uses_the_nearest_physical_scoped_package() {
    let (_root, request, package) = fixture();
    let nested = package.join("node_modules/@captured/nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        nested.join("package.json"),
        r#"{"name":"@captured/nested","version":"2.0.0"}"#,
    )
    .unwrap();
    std::fs::write(nested.join("library.sh"), "VALUE='nested'\n").unwrap();
    std::fs::write(Path::new(&request.cwd).join("maintenance.sh"),
        "source './node_modules/captured-dep/node_modules/@captured/nested/library.sh'; printf '%s' \"$VALUE\"").unwrap();
    let value = captured(&request);
    assert_eq!(value.subject.package_bindings.len(), 1);
    assert_eq!(
        value.subject.package_bindings[0].name.as_deref(),
        Some("@captured/nested")
    );
}

#[test]
fn bash_package_binding_preserves_current_review_and_nested_extension_denial() {
    use guard_contracts::NativeCommandControlBindingV1;
    use serde_json::json;
    let (_root, request, package) = fixture();
    let reviewed = capture_for_launch(&request, &tests::admitted("review")).unwrap();
    assert!(!reviewed.policy.unwrap().allows_without_consent());
    let cwd = Path::new(&request.cwd);
    std::fs::write(
        cwd.join("aws"),
        "#!/bin/bash\nprintf 'local fixture only\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(cwd.join("aws"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(package.join("library.sh"), "aws s3 ls\nVALUE='reviewed'\n").unwrap();
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1", "program_digest":program.program_digest,
        "catalog_digest":program.catalog_digest, "trust_digest":program.trust_digest,
        "health":"protected", "revision":1, "managed_revision":0, "effective_digest":"",
        "layers":[{"schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":[{"target_kind":"permission",
                "target_id":"command.storage.aws-s3.permission.ls", "state":"disabled"}]}]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let mut changed = crate::policy_enforcement::tests::snapshot(
        crate::policy_enforcement::tests::policy("allow"),
    );
    changed.command_extensions = Some(binding);
    let changed = crate::policy_enforcement::AdmittedPolicySnapshot::new(changed).unwrap();
    assert_eq!(
        capture_for_launch(&request, &changed).err().as_deref(),
        Some("bash_current_policy_denied")
    );
}

#[test]
fn bash_package_binding_artifact_excludes_private_paths_and_is_bound_to_actual_code() {
    let (_root, request, package) = fixture();
    let subject = captured(&request).subject;
    let artifact = super::super::super::bash_dependency_artifact::build(&subject, "omp")
        .unwrap()
        .unwrap();
    let serialized = serde_json::to_string(&artifact).unwrap();
    for private in [
        &request.cwd,
        &request.home_dir,
        &request.guard_home,
        "maintenance.sh",
        "library.sh",
        "VALUE",
        "reviewed",
    ] {
        assert!(!serialized.contains(private));
    }
    assert_eq!(artifact["metadata"]["assessment_only"], true);
    assert_eq!(artifact["metadata"]["intent_kind"], "execute");
    assert_eq!(
        artifact["metadata"]["captured_subject_sha256"],
        subject.identity_sha256().unwrap()
    );
    assert_eq!(
        artifact["metadata"]["targets"][0]["package_name"],
        "captured-dep"
    );
    let index = usize::from(subject.package_bindings[0].code_input_indices[0]);
    assert_eq!(
        artifact["metadata"]["captured_code_sha256"][0],
        subject.code_inputs[index].content_sha256
    );
    std::fs::write(package.join("library.sh"), "VALUE='changed!'\n").unwrap();
    let changed = captured(&request).subject;
    let changed_artifact = super::super::super::bash_dependency_artifact::build(&changed, "omp")
        .unwrap()
        .unwrap();
    assert_ne!(artifact["artifact_id"], changed_artifact["artifact_id"]);
    assert!(super::super::super::bash_dependency_artifact::build(&changed, "pi").is_err());
    std::fs::remove_file(package.join("package.json")).unwrap();
    let unknown = captured(&request).subject;
    assert!(
        super::super::super::bash_dependency_artifact::build(&unknown, "omp")
            .unwrap()
            .is_none()
    );
}

#[test]
fn bash_package_binding_artifact_reaches_the_existing_native_intelligence_evaluator() {
    use guard_contracts::{SupplyChainEvalRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
    use serde_json::{json, Value};
    let (_root, request, package) = fixture();
    std::fs::write(
        package.join("package.json"),
        r#"{"name":"minimist","version":"1.2.8"}"#,
    )
    .unwrap();
    let subject = captured(&request).subject;
    let artifact = super::super::super::bash_dependency_artifact::build(&subject, "omp")
        .unwrap()
        .unwrap();
    let vectors: Value =
        serde_json::from_str(crate::supply_chain_cloud_vectors_tests::VECTORS).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "offline_bundle_block")
        .unwrap();
    let store = Path::new(&request.guard_home).join("guard.db");
    crate::supply_chain_cloud_vectors_tests::seed_store(&store, &vectors, case);
    let mut evaluation = SupplyChainEvalRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "captured-package-intelligence".into(),
        store_path: text(&store).unwrap(),
        guard_home: request.guard_home.clone(),
        artifact,
        workspace_dir: Some(request.workspace.clone()),
        now: vectors["now"].as_str().map(str::to_owned),
        external_archive_network_authorized: false,
        retain_external_archive_blob: false,
        runtime_private_metadata: None,
        sync_auth_context_override: None,
        package_entitlement_override: None,
        registry_metadata_override: None,
        saved_policy_probe: None,
        egress_supplied: None,
        egress_spool_dir: None,
    };
    let result = crate::supply_chain_cloud_vectors_tests::drive(
        &mut evaluation,
        Some("fixture Cloud is offline"),
    )
    .unwrap();
    assert_eq!(result.code, "ok");
    let payload = result.payload.unwrap();
    assert_eq!(
        payload["package_intent_hash"],
        subject.identity_sha256().unwrap()
    );
    assert_eq!(payload["decision"], "block");
    assert!(payload["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == json!("known_malware_or_kev")));
}

#[test]
fn bash_package_binding_immutable_launch_uses_the_captured_dependency_body() {
    struct Gate;
    impl guard_contained_process::SourceLaunchGate for Gate {
        fn prepare_effects(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        fn commit(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        fn released(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_root, request, package) = fixture();
    let frozen = captured(&request);
    let sentinel = Path::new(&request.home_dir).join("package-sentinel");
    std::fs::write(&sentinel, "protected").unwrap();
    std::fs::write(
        package.join("library.sh"),
        "VALUE='replaced'; : > \"$HOME/package-sentinel\"\n",
    )
    .unwrap();
    let result = super::super::super::bash_launch::execute(
        frozen,
        Instant::now() + Duration::from_secs(10),
        &std::sync::atomic::AtomicBool::new(false),
        &mut Gate,
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"reviewed");
    assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "protected");
}

#[test]
fn bash_package_binding_omp_preview_uses_the_hosts_tool_directory() {
    use crate::policy_enforcement::{
        tests::{policy, snapshot},
        AdmittedPolicySnapshot,
    };
    use guard_contracts::{GuardHookEnvelopeV2, GuardHookSourceMetadataV2};
    use serde_json::json;
    let (_root, mut request, package) = fixture();
    let session = request.cwd.clone();
    let child = Path::new(&session).join("subproject");
    std::fs::create_dir(&child).unwrap();
    std::fs::rename(package.parent().unwrap(), child.join("node_modules")).unwrap();
    std::fs::rename(
        Path::new(&session).join("maintenance.sh"),
        child.join("maintenance.sh"),
    )
    .unwrap();
    request.command = format!("/bin/bash '{}' dry", child.join("maintenance.sh").display());
    request.cwd = text(&child).unwrap();
    let mut current = snapshot(policy("allow"));
    current.command_extensions = Some(super::policy_tests::protected_controls());
    let current = AdmittedPolicySnapshot::new(current).unwrap();
    let captured = capture_for_launch(&request, &current).unwrap();
    let decision = captured.policy.unwrap().decisions.remove(0);
    assert!(decision.command_extensions.is_some());
    let mut envelope = GuardHookEnvelopeV2 {
        schema: guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: None,
        harness: "omp".into(),
        event: "PreToolUse".into(),
        recording_only: false,
        deadline_budget_ms: Some(1000),
        policy_generation: 0,
        policy_snapshot: json!({}),
        raw_payload: json!({"tool_name":"bash","tool_input":{"command":request.command,"cwd":"subproject"},
            "guard_bound_bash_host":{"schema":"guard-native-bash-host-delivery.v3","host":"omp-input-rewrite-v1",
                "owner_pid":std::process::id(),"environment":request.environment,"file_creation_mask":0o022}}),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(session),
            home_dir: request.home_dir,
            guard_home: request.guard_home,
            source_ref_external_allowed: false,
            execution_environment: Some(request.execution_environment),
        },
    };
    let result = super::super::super::bash_delivery::require_owner(
        &envelope,
        Some(&current),
        decision.clone(),
    );
    assert_eq!(
        result.reason_code,
        guard_contracts::NATIVE_BASH_DELIVERY_REASON,
        "{}",
        result.reason
    );
    assert_eq!(result.minimum_action, "sandbox-required");
    for invalid in [json!("missing-directory"), json!({"path":"subproject"})] {
        envelope.raw_payload["tool_input"]["cwd"] = invalid;
        let refused = super::super::super::bash_delivery::require_owner(
            &envelope,
            Some(&current),
            decision.clone(),
        );
        assert_eq!(refused.minimum_action, "block");
        assert!(refused
            .reason
            .contains("bash_working_directory_unavailable"));
    }
    let mut deny = decision;
    deny.minimum_action = "block".into();
    deny.reason_code = "current_extension_denied".into();
    let refused =
        super::super::super::bash_delivery::require_owner(&envelope, Some(&current), deny);
    assert_eq!(refused.reason_code, "current_extension_denied");
}
