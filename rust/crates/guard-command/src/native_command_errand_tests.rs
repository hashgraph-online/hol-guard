use super::*;

#[test]
fn errand_native_rules_require_opt_in_and_enforce_both_permissions() {
    let enabled = binding(&[("extension", "command.errand", "enabled")], false);
    for (command, rule, permission) in [
        (
            "errand -- make test",
            "command.errand.run",
            "command.errand.permission.run",
        ),
        (
            "errand fetch --apply linux/job",
            "command.errand.fetch-apply",
            "command.errand.permission.fetch-apply",
        ),
    ] {
        let result = decision(command, &enabled);
        assert!(
            matches!(result.minimum_action.as_str(), "review" | "block"),
            "{command}"
        );
        let observations = result.command_extensions.unwrap();
        assert!(observations.evaluation_error.is_none(), "{command}");
        let matched = observations
            .observations
            .iter()
            .find(|item| item.rule_id == rule)
            .unwrap();
        assert_eq!(matched.effective_segment_indexes, [0], "{command}");
        assert!(matched.uncertainty_reasons.is_empty(), "{command}");
        let disabled = binding(
            &[
                ("extension", "command.errand", "enabled"),
                ("permission", permission, "disabled"),
            ],
            false,
        );
        assert_eq!(
            decision(command, &disabled).minimum_action,
            "block",
            "{command}"
        );
        for inactive in [
            binding(&[], false),
            binding(&[("extension", "command.errand", "disabled")], false),
        ] {
            assert!(decision(command, &inactive)
                .command_extensions
                .unwrap()
                .observations
                .iter()
                .all(|item| item.extension_id != "command.errand"));
        }
    }
    for command in [
        "errand ps",
        "errand fetch linux/job",
        "errand fetch --apply=false linux/job",
    ] {
        let observations = decision(command, &enabled).command_extensions.unwrap();
        assert!(observations.evaluation_error.is_none(), "{command}");
        assert!(
            observations
                .observations
                .iter()
                .all(|item| item.extension_id != "command.errand"),
            "{command}"
        );
    }
}

#[test]
fn unsupported_native_wrapper_parsing_stays_fail_closed() {
    // The native shell parser currently rejects nested executors before
    // matcher evaluation. The Python-model oracle separately qualifies the
    // Errand matcher's wrapper semantics without broadening parser support.
    let enabled = binding(&[("extension", "command.errand", "enabled")], false);
    for command in [
        "xargs errand",
        "xargs errand fetch",
        "exec errand -- make test",
    ] {
        let result = decision(command, &enabled);
        assert_eq!(result.minimum_action, "block", "{command}");
        assert_eq!(
            result
                .command_extensions
                .unwrap()
                .evaluation_error
                .as_deref(),
            Some("native_command_evaluation_failed"),
            "{command}"
        );
    }
}

#[test]
fn errand_admission_rejects_unknown_operations_and_expansion_profiles() {
    let value: Value = serde_json::from_slice(EMBEDDED_PROGRAM).unwrap();
    let config = value["nodes"]
        .as_object()
        .unwrap()
        .values()
        .find(|node| node["op"] == "errand-command.v1")
        .unwrap()["config"]
        .clone();
    for (field, invalid) in [
        ("operation", serde_json::json!("unknown")),
        ("expansion_markers", serde_json::json!([])),
    ] {
        let mut config = config.clone();
        config[field] = invalid;
        assert!(compile_node(
            RawNode {
                op: "errand-command.v1".into(),
                config,
                children: BTreeMap::new()
            },
            &BTreeMap::new()
        )
        .is_err());
    }
}
