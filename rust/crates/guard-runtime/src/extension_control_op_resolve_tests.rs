use super::*;

#[test]
fn a_disabled_extension_permission_dependency_and_implication_each_block() {
    let cases: [(NativeExtensionControlV1, ExtensionControlItemV1, &str); 6] = [
        (
            disabled_extension(ALPHA),
            item(&[ALPHA], &[]),
            "control.disabled-extension",
        ),
        (
            disabled_permission(ALPHA_READ),
            item(&[], &[ALPHA_READ]),
            "control.disabled-permission",
        ),
        // gamma depends on alpha.
        (
            disabled_extension(ALPHA),
            item(&[GAMMA], &[]),
            "control.disabled-extension",
        ),
        // deploy depends on alpha's write permission.
        (
            disabled_permission(ALPHA_WRITE),
            item(&[], &[GAMMA_DEPLOY]),
            "control.disabled-permission",
        ),
        // deploy implies beta's run permission.
        (
            disabled_permission(BETA_RUN),
            item(&[], &[GAMMA_DEPLOY]),
            "control.disabled-permission",
        ),
        // A permission carries its owner: disabling the owner blocks it.
        (
            disabled_extension(ALPHA),
            item(&[], &[ALPHA_READ]),
            "control.disabled-extension",
        ),
    ];

    for (disabled, asked, reason) in cases {
        let answer = resolve_one(vec![local(vec![disabled.clone()])], asked);
        assert!(answer.blocked, "{disabled:?}");
        assert_eq!(answer.factor_reason_codes, vec![reason], "{disabled:?}");
        assert!(answer.failures.is_empty());
    }
}

#[test]
fn an_unrestricted_item_is_allowed_and_names_what_was_explicitly_enabled() {
    let answer = resolve_one(
        vec![local(vec![
            enabled_permission(ALPHA_WRITE),
            enabled_permission(ALPHA_READ),
        ])],
        item(&[ALPHA], &[ALPHA_WRITE, ALPHA_READ, BETA_RUN]),
    );

    assert!(!answer.blocked);
    assert!(answer.factor_reason_codes.is_empty());
    assert!(answer.failures.is_empty());
    assert_eq!(
        answer.explicitly_enabled_permission_ids,
        vec![ALPHA_READ.to_owned(), ALPHA_WRITE.to_owned()]
    );
    assert_eq!(answer.active, None);
}

#[test]
fn restrictions_never_reduce_the_resolved_action() {
    let subjects = [disabled_extension(ALPHA), disabled_permission(ALPHA_READ)];
    let mut blocked_by_subset = Vec::new();
    for mask in 0..(1 << subjects.len()) {
        let controls: Vec<NativeExtensionControlV1> = subjects
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, control)| control.clone())
            .collect();
        let answer = resolve_one(vec![local(controls)], item(&[ALPHA], &[ALPHA_READ]));
        blocked_by_subset.push((mask, answer.blocked));
    }

    assert!(blocked_by_subset
        .iter()
        .all(|(mask, blocked)| *blocked == (*mask != 0)));
}

#[test]
fn global_lockdown_blocks_commands_and_allows_only_typed_local_recovery() {
    let locked = vec![layer("local-admin", true, Vec::new())];
    let mut recovery = scenario(locked.clone(), vec![item(&[], &[])]);
    recovery.surface = "trusted-local-recovery".to_owned();
    let mut proof = scenario(locked.clone(), vec![item(&[], &[])]);
    proof.surface = "trusted-local-proof".to_owned();
    let command = scenario(locked, vec![item(&[ALPHA], &[ALPHA_READ])]);

    let answers = resolved(vec![command, recovery, proof]);

    assert!(answers.iter().all(|answer| answer.global_lockdown));
    assert!(answers[0].results[0].blocked);
    assert_eq!(
        answers[0].results[0].factor_reason_codes,
        vec!["control.global-lockdown"]
    );
    for answer in &answers[1..] {
        assert!(!answer.results[0].blocked);
        assert!(answer.results[0].factor_reason_codes.is_empty());
    }
}

#[test]
fn one_request_resolves_every_scenario_against_its_own_layers() {
    let answers = resolved(vec![
        scenario(Vec::new(), vec![item(&[ALPHA], &[]), item(&[BETA], &[])]),
        scenario(
            vec![local(vec![disabled_extension(BETA)])],
            vec![item(&[ALPHA], &[]), item(&[BETA], &[])],
        ),
        scenario(Vec::new(), Vec::new()),
    ]);

    let blocked: Vec<Vec<bool>> = answers
        .iter()
        .map(|answer| answer.results.iter().map(|item| item.blocked).collect())
        .collect();
    assert_eq!(
        blocked,
        vec![vec![false, false], vec![false, true], Vec::new()]
    );
}

#[test]
fn resolver_failures_are_typed_and_sorted_by_string_value() {
    // A digest mismatch and a duplicate layer kind sort the other way round
    // in the resolver's own declaration order.
    let mut stale = local(Vec::new());
    stale.catalog_digest = "b".repeat(64);
    let answer = resolve_one(vec![stale, local(Vec::new())], item(&[ALPHA], &[]));

    assert!(answer.blocked);
    assert_eq!(answer.factor_reason_codes, vec!["control.resolver-failure"]);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![
            (
                "catalog-digest-mismatch".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "duplicate-layer-kind".to_owned(),
                Some("local-admin".to_owned())
            ),
        ]
    );
}

#[test]
fn an_unknown_target_is_a_typed_failure_that_never_echoes_the_input() {
    let answer = resolve_one(Vec::new(), item(&["command.private-unknown-input"], &[]));

    assert!(answer.blocked);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![("unknown-extension-target".to_owned(), None)]
    );
    assert!(!format!("{answer:?}").contains("private-unknown-input"));
    let unknown_permission = resolve_one(
        Vec::new(),
        item(&[], &["command.private-unknown-input.permission.x"]),
    );
    assert_eq!(
        failure_codes(&unknown_permission.failures),
        vec!["unknown-permission-target"]
    );
}

#[test]
fn a_layer_built_for_another_catalog_blocks_every_item() {
    let mut other = local(vec![disabled_extension(ALPHA)]);
    other.catalog_digest = "0".repeat(64);
    let answer = resolve_one(vec![other], item(&[ALPHA], &[]));

    assert!(answer.blocked);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![(
            "catalog-digest-mismatch".to_owned(),
            Some("local-admin".to_owned())
        )]
    );
}

#[test]
fn a_duplicate_target_in_a_layer_fails_closed() {
    let answer = resolve_one(
        vec![local(vec![
            disabled_extension(ALPHA),
            disabled_extension(ALPHA),
        ])],
        item(&[ALPHA], &[]),
    );

    assert!(answer.blocked);
    assert_eq!(
        failure_codes(&answer.failures),
        vec!["duplicate-target-in-layer"]
    );
}

#[test]
fn a_control_aimed_at_an_alias_is_non_canonical_not_a_missing_disabled_control() {
    let answer = resolve_one(
        vec![local(vec![disabled_extension(BETA_ALIAS)])],
        item(&[BETA], &[]),
    );

    assert!(answer.blocked);
    assert_eq!(
        failure_pairs(&answer.failures),
        vec![(
            "non-canonical-target".to_owned(),
            Some("local-admin".to_owned())
        )]
    );
}

#[test]
fn a_control_for_a_target_the_registry_lacks_is_a_typed_failure() {
    let answer = resolve_one(
        vec![local(vec![
            disabled_extension("command.missing"),
            disabled_permission("command.missing.permission.x"),
        ])],
        item(&[ALPHA], &[]),
    );

    assert_eq!(
        failure_pairs(&answer.failures),
        vec![
            (
                "unknown-extension-target".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "unknown-permission-target".to_owned(),
                Some("local-admin".to_owned())
            ),
        ]
    );
}

#[test]
fn lookups_follow_the_catalog_normalization() {
    // Extensions resolve through a trimmed, lowercased id or a listed alias;
    // permissions through a trimmed, lowercased id.
    for asked in [
        item(&["  COMMAND.BETA  "], &[]),
        item(&[BETA_ALIAS], &[]),
        item(&[], &[" COMMAND.BETA.PERMISSION.RUN "]),
    ] {
        let answer = resolve_one(vec![local(vec![disabled_extension(BETA)])], asked.clone());
        assert!(answer.blocked, "{asked:?}");
        assert_eq!(
            answer.factor_reason_codes,
            vec!["control.disabled-extension"]
        );
    }
}

#[test]
fn an_alias_is_matched_as_listed_and_a_later_listing_wins_a_shared_alias() {
    let blocked_asking = |registry: ExtensionControlRegistryV1, layers, asked: &str| {
        let result = run(&request(ExtensionControlQueryV1::Resolve {
            registry,
            scenarios: vec![scenario(layers, vec![item(&[asked], &[])])],
        }));
        let Some(ExtensionControlPayloadV1::Resolve { scenarios }) = result.payload else {
            panic!("expected resolve payload: {}", result.code);
        };
        scenarios[0].results[0].clone()
    };

    // The queried id is normalized, the listed alias is not, so an alias that
    // is not already lowercase is never reached.
    let mut mixed = registry();
    mixed.extensions[1].aliases = vec!["command.Mixed-Alias".to_owned()];
    for asked in ["command.Mixed-Alias", "command.mixed-alias"] {
        let answer = blocked_asking(mixed.clone(), Vec::new(), asked);
        assert!(answer.blocked, "{asked}");
        assert_eq!(
            failure_codes(&answer.failures),
            vec!["unknown-extension-target"]
        );
    }

    // Two extensions listing one alias: the later one owns it.
    let mut shared = registry();
    shared.extensions[0].aliases = vec!["command.shared".to_owned()];
    shared.extensions[1].aliases = vec!["command.shared".to_owned()];
    let beta_disabled = vec![local(vec![disabled_extension(BETA)])];
    let alpha_disabled = vec![local(vec![disabled_extension(ALPHA)])];
    assert!(blocked_asking(shared.clone(), beta_disabled, "command.shared").blocked);
    assert!(!blocked_asking(shared, alpha_disabled, "command.shared").blocked);
}
