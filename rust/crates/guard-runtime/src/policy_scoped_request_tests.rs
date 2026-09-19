use super::*;
use guard_policy_snapshot::scoped_authority::NativePolicyAuthority;
use serde_json::json;

fn envelope(payload: Value) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "harness":"codex", "event":"PreToolUse",
        "raw_payload":payload, "policy_generation":1, "policy_snapshot":{},
        "source":{"cwd":std::env::temp_dir(),"home_dir":std::env::temp_dir(),"guard_home":std::env::temp_dir()}
    })).unwrap()
}

fn authority(harness: &str, artifact: &str, digest: &str) -> NativePolicyAuthority {
    NativePolicyAuthority::from_slice(&serde_json::to_vec(&json!({
        "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1", "rows":[{
            "decision_id":1, "harness":harness, "scope":"artifact", "action":"allow",
            "source_kind":"signed-memory", "updated_at_us":1,
            "artifact_id":artifact, "artifact_hash":null, "workspace":null, "publisher":null,
            "expires_at_ms":null, "exact_command_sha256":digest, "requires_exact_context":false
        }],"managed":null
    })).unwrap()).unwrap()
}

#[test]
fn matches_shared_actual_python_artifact_producer_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("policy_scoped_request_fixture.json")).unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 29);
    for case in fixture["cases"].as_array().unwrap() {
        let mut source = envelope(case["payload"].clone());
        source.harness = case["harness"].as_str().unwrap().to_owned();
        let policy = authority(
            &source.harness,
            case["artifactId"].as_str().unwrap(),
            case["sha256"].as_str().unwrap(),
        );
        let request = derive_scoped_policy_request(&source, &source.harness).unwrap();
        assert!(
            policy.select_generic(&request, 1).unwrap().is_some(),
            "case {}",
            case["name"]
        );
    }
}

#[test]
fn matches_shared_actual_non_shell_hook_producer_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("policy_scoped_tool_fixture.json")).unwrap();
    let workspace =
        std::env::temp_dir().join(format!("guard-scoped-tool-vectors-{}", std::process::id()));
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("guide.md"), "Synthetic local guide.\n").unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 24);
    for case in fixture["cases"].as_array().unwrap() {
        let mut source = envelope(case["payload"].clone());
        source.harness = case["harness"].as_str().unwrap().to_owned();
        source.source.cwd = Some(workspace.to_string_lossy().into_owned());
        let request = derive_scoped_policy_request(&source, &source.harness)
            .unwrap_or_else(|reason| panic!("{}: {reason}", case["name"]));
        assert_eq!(request.artifact_id(), case["artifactId"].as_str());
    }
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn non_shell_identity_refuses_ambiguous_sensitive_and_unmodeled_sources() {
    for payload in [
        json!({"tool_name":"Read","tool_input":{"path":"../guide.md"}}),
        json!({"tool_name":"Read","tool_input":{"path":"private_key.txt"}}),
        json!({"tool_name":"Read","tool_input":{"path":"guide.md","command":"printf synthetic"}}),
        json!({"tool_name":"Read","tool_input":{"path":"guide.md"},"arguments":{"path":"guide.md"}}),
        json!({"tool_name":"mcp__synthetic__inspect","toolName":"mcp__synthetic__ping","tool_input":{}}),
        json!({"tool_name":"mcp__synthetic__inspect","tool_input":{"command":"printf synthetic"}}),
        json!({"tool_name":"mcp__synthetic__inspect","tool_input":{"nested":{"path":"guide.md"}}}),
        json!({"tool_name":"mcp__synthetic__inspect","tool_input":{},"source_scope":"user"}),
        json!({"tool_name":"npm","tool_input":{}}),
    ] {
        assert!(derive_scoped_policy_request(&envelope(payload), "codex").is_err());
    }
    // The dedicated producer does not relax the generic read classifier.
    assert!(tool_request::generic_tool_artifact(
        &envelope(json!({"tool_name":"Read","tool_input":{"path":".env"}})),
        "codex",
    )
    .is_none());
    let mut forged = envelope(json!({"tool_name":"mcp__synthetic__inspect","tool_input":{}}));
    forged.raw_payload["exact_command_sha256"] = json!("a".repeat(64));
    let policy = authority(
        "codex",
        "codex:project:mcp__synthetic__inspect",
        &"a".repeat(64),
    );
    assert!(policy
        .select_generic(&derive_scoped_policy_request(&forged, "codex").unwrap(), 1)
        .unwrap()
        .is_none());
}

#[test]
fn missing_execution_context_cannot_be_labeled_as_a_generic_artifact() {
    let payload = json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"}});
    for cwd in [
        None,
        Some("/synthetic/missing-scoped-identity-directory".to_owned()),
    ] {
        let mut source = envelope(payload.clone());
        source.source.cwd = cwd;
        assert!(derive_scoped_policy_request(&source, "codex").is_err());
    }
}

#[test]
fn original_command_and_actual_artifact_are_jointly_required() {
    let raw = "\tprintf 'Synthetic  exact bytes'\r\n";
    let payload = json!({"tool_name":"Shell","tool_input":{"command":raw}});
    let original = envelope(payload.clone());
    let policy = authority(
        "codex",
        "codex:project:Shell",
        &exact_command_sha256(raw).unwrap(),
    );
    let request = derive_scoped_policy_request(&original, "codex").unwrap();
    assert!(policy.select_generic(&request, 1).unwrap().is_some());
    for changed in [
        raw.trim().to_owned(),
        raw.replace("  ", " "),
        raw.replace("Synthetic", "synthetic"),
    ] {
        let candidate = envelope(json!({"tool_name":"Shell","tool_input":{"command":changed}}));
        let request = derive_scoped_policy_request(&candidate, "codex").unwrap();
        assert!(policy.select_generic(&request, 1).unwrap().is_none());
    }
    let mut changed = original.clone();
    changed.raw_payload["artifact_id"] = json!("synthetic:other");
    assert!(policy
        .select_generic(&derive_scoped_policy_request(&changed, "codex").unwrap(), 1)
        .unwrap()
        .is_none());
}

#[test]
fn caller_digests_and_ambiguous_or_runtime_sources_cannot_create_authority() {
    let original = json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"}});
    for payload in [
        json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"},"arguments":{"command":"printf synthetic"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic","cmd":"printf synthetic"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic","nested":{"command":"ssh synthetic"}}}),
        json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic; printf more"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"ssh synthetic true"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"ssh -F synthetic.conf synthetic"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"cat ~/.ssh/id_rsa"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"sh -c 'printf synthetic'"}}),
        json!({"tool_name":"Shell","exact_command_sha256":"a".repeat(64)}),
    ] {
        assert!(derive_scoped_policy_request(&envelope(payload), "codex").is_err());
    }
    let mut forged = envelope(original);
    forged.raw_payload["exact_command_sha256"] = json!("a".repeat(64));
    let policy = authority("codex", "codex:project:Shell", &"a".repeat(64));
    assert!(policy
        .select_generic(&derive_scoped_policy_request(&forged, "codex").unwrap(), 1)
        .unwrap()
        .is_none());
}

#[test]
fn raw_compatibility_aliases_match_actual_python_identity_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("policy_scoped_alias_fixture.json")).unwrap();
    let workspace =
        std::env::temp_dir().join(format!("guard-scoped-aliases-{}", std::process::id()));
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("guide.md"), "Synthetic guide.\n").unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let mut source = envelope(case["payload"].clone());
        source.harness = case["harness"].as_str().unwrap().to_owned();
        source.source.cwd = Some(workspace.to_string_lossy().into_owned());
        let actual = derive_scoped_policy_request(&source, &source.harness).unwrap();
        assert_eq!(actual.artifact_id(), case["artifactId"].as_str());
    }
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn aliases_cannot_invent_project_identity_or_choose_a_conflicting_selector() {
    let sources = [
        json!({"tool_name":"Bash","tool_input":{"command":"printf synthetic"}}),
        json!({"tool_name":"mcp__synthetic__inspect","tool_input":{}}),
    ];
    for payload in sources {
        for changes in [
            json!({"sourceScope":"user"}),
            json!({"source_scope":"project","sourceScope":"project"}),
            json!({"source_scope":"project","sourceScope":"user"}),
            json!({"artifact_id":"first","artifactId":"second"}),
            json!({"artifact_id":"same","artifactId":"same"}),
            json!({"artifactId":false}),
            json!({"sourceScope":false}),
        ] {
            let mut source = envelope(payload.clone());
            source
                .raw_payload
                .as_object_mut()
                .unwrap()
                .extend(changes.as_object().unwrap().clone());
            assert!(derive_scoped_policy_request(&source, "codex").is_err());
        }
        for key in [
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
        ] {
            let mut source = envelope(payload.clone());
            source.raw_payload[key] = json!("PostToolUse");
            assert!(derive_scoped_policy_request(&source, "codex").is_err());
        }
    }
}
