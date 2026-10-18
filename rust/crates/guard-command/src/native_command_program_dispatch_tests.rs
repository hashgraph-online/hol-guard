use super::*;

#[test]
fn active_dispatch_matches_exhaustive_observations_for_every_fixture_and_control_set() {
    let program = packaged_command_program().unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/native-command-observations-v1.json"
    ))
    .unwrap();
    let sets = [
        BTreeSet::new(),
        program
            .extensions
            .iter()
            .filter(|extension| extension.trust_class != "external")
            .map(|extension| extension.extension_id.clone())
            .collect(),
        program
            .extensions
            .iter()
            .map(|extension| extension.extension_id.clone())
            .collect(),
    ];
    for active in sets {
        let dispatch = CommandCandidateIndex::for_active(&program, &active);
        for case in fixture["cases"].as_array().unwrap() {
            let command: CanonicalCommandV1 =
                serde_json::from_value(case["model"].clone()).unwrap();
            let expected = program
                .observe_declarative_selected(&command, &active, None, 0..program.rules.len())
                .unwrap();
            let actual = program
                .observe_declarative_memo(
                    &command,
                    &active,
                    None,
                    dispatch.candidates(&command),
                    Some(Arc::clone(&dispatch.memo_layout)),
                )
                .unwrap();
            assert_eq!(actual, expected, "active={active:?} model={command:?}");
        }
    }
}

#[test]
fn disabled_rules_never_enter_the_bound_dispatch_or_matcher_memo() {
    let program = packaged_command_program().unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/native-command-observations-v1.json"
    ))
    .unwrap();
    let active = BTreeSet::new();
    let dispatch = CommandCandidateIndex::for_active(&program, &active);
    assert!(dispatch.extension_indices().is_empty());
    assert!(
        dispatch.executables.is_empty()
            && dispatch.keywords.is_empty()
            && dispatch.unindexed.is_empty()
    );
    for case in fixture["cases"].as_array().unwrap() {
        let command: CanonicalCommandV1 = serde_json::from_value(case["model"].clone()).unwrap();
        let mut state = Evaluation {
            program: &program,
            command: &command,
            deadline: None,
            memo: NodeMemo::new(Some(Arc::clone(&dispatch.memo_layout))),
        };
        for index in dispatch.candidates(&command) {
            if let Some(matcher) = program.rules[index].matcher {
                state.evaluate(matcher).unwrap();
            }
        }
        assert_eq!(dispatch.memo_layout.active_node_count(), 0);
    }
}

#[test]
fn owner_and_default_floor_indexes_preserve_the_admitted_program() {
    let program = packaged_command_program().unwrap();
    for (index, extension) in program.extensions.iter().enumerate() {
        let expected: Vec<_> = program
            .rules
            .iter()
            .filter(|rule| rule.extension_index == index)
            .map(|rule| rule.rule_id.as_str())
            .collect();
        assert_eq!(
            program
                .extension_rules(index)
                .map(|rule| rule.rule_id.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        for permission in &extension.permissions {
            assert_eq!(
                program.permission_baseline_allows(&permission.permission_id),
                permission.default_enabled && permission.baseline_floor == "allow"
            );
        }
    }
    assert!(!program.permission_baseline_allows("unknown.permission"));
}
