use super::*;

#[test]
fn input_limits_fail_closed_at_their_boundaries() {
    let boundary = |ids: usize| {
        let asked: Vec<String> = (0..ids).map(|_| ALPHA.to_owned()).collect();
        resolve_one(
            Vec::new(),
            ExtensionControlItemV1 {
                extension_ids: asked,
                permission_ids: Vec::new(),
                active_extension_id: None,
            },
        )
    };
    assert!(!boundary(1024).blocked);
    let over = boundary(1025);
    assert!(over.blocked);
    assert_eq!(failure_codes(&over.failures), vec!["input-limit-exceeded"]);

    let long = "command.".to_owned() + &"a".repeat(248);
    assert_eq!(long.len(), 256);
    assert!(!resolve_one(Vec::new(), item(&[long.as_str()], &[]))
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
    let longer = format!("{long}a");
    assert_eq!(
        failure_codes(&resolve_one(Vec::new(), item(&[longer.as_str()], &[])).failures),
        vec!["input-limit-exceeded"]
    );

    let controls = |count: usize| -> Vec<NativeExtensionControlV1> {
        (0..count)
            .map(|index| {
                control(
                    "extension",
                    &format!("command.generated-{index}"),
                    "enabled",
                )
            })
            .collect()
    };
    let at_limit = resolve_one(vec![local(controls(512))], item(&[ALPHA], &[]));
    assert!(!at_limit
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
    let over_limit = resolve_one(vec![local(controls(513))], item(&[ALPHA], &[]));
    assert!(over_limit.blocked);
    assert!(over_limit
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
    // More layers than layer kinds is an input-limit failure, not a rejection.
    let layers = resolve_one(
        vec![local(Vec::new()), cloud(Vec::new()), local(Vec::new())],
        item(&[ALPHA], &[]),
    );
    assert!(layers.blocked);
    assert!(layers
        .failures
        .iter()
        .any(|failure| failure.code == "input-limit-exceeded"));
}

#[test]
fn an_authority_failure_blocks_commands_but_not_the_trusted_proof() {
    let mut command = scenario(Vec::new(), vec![item(&[ALPHA], &[])]);
    command.authority_failure = Some("authority-tampered".to_owned());
    let mut proof = command.clone();
    proof.surface = "trusted-local-proof".to_owned();
    let mut recovery = command.clone();
    recovery.surface = "trusted-local-recovery".to_owned();

    let answers = resolved(vec![command, proof, recovery]);

    assert!(answers[0].results[0].blocked);
    assert_eq!(
        failure_pairs(&answers[0].results[0].failures),
        vec![("authority-tampered".to_owned(), None)]
    );
    assert!(!answers[1].results[0].blocked);
    assert!(answers[1].results[0].failures.is_empty());
    assert!(answers[2].results[0].blocked);
}

#[test]
fn a_surface_or_authority_failure_the_op_does_not_know_is_a_bound_error() {
    let mut surface = scenario(Vec::new(), vec![item(&[ALPHA], &[])]);
    surface.surface = "recovery/by-path".to_owned();
    assert_eq!(
        error_code(&resolve_request(vec![surface])),
        "native_extension_control_surface_invalid"
    );
    let mut failure = scenario(Vec::new(), vec![item(&[ALPHA], &[])]);
    failure.authority_failure = Some("authority-fine".to_owned());
    assert_eq!(
        error_code(&resolve_request(vec![failure])),
        "native_extension_control_authority_failure_invalid"
    );
}

#[test]
fn an_extension_is_active_by_trust_class_and_local_admin_enablement() {
    let activity = |layers: Vec<NativeExtensionControlLayerV1>, extension_id: &str| {
        resolve_one(layers, active_item(extension_id)).active
    };

    // Required and non-external extensions are always active.
    assert_eq!(
        activity(vec![local(vec![disabled_extension(GAMMA)])], GAMMA),
        Some(true)
    );
    assert_eq!(activity(Vec::new(), ALPHA), Some(true));
    // An external one needs an explicit local-admin enable.
    assert_eq!(activity(Vec::new(), BETA), Some(false));
    assert_eq!(
        activity(vec![local(vec![enabled_extension(BETA)])], BETA),
        Some(true)
    );
    assert_eq!(
        activity(vec![cloud(vec![enabled_extension(BETA)])], BETA),
        Some(false)
    );
    // Disable dominates the explicit enable, from either layer.
    assert_eq!(
        activity(
            vec![
                local(vec![enabled_extension(BETA)]),
                cloud(vec![disabled_extension(BETA)])
            ],
            BETA
        ),
        Some(false)
    );
    // An owner the registry does not know is never active.
    assert_eq!(activity(Vec::new(), "command.unlisted"), Some(false));
}

#[test]
fn an_extension_asked_about_by_alias_is_judged_by_its_canonical_id() {
    // The controls name canonical ids, so the alias or a differently cased id
    // reaches the same verdict as the canonical one.
    for asked in [BETA, BETA_ALIAS, "  COMMAND.BETA  "] {
        let activity = |layers: Vec<NativeExtensionControlLayerV1>| {
            resolve_one(layers, active_item(asked)).active
        };

        assert_eq!(
            activity(vec![local(vec![enabled_extension(BETA)])]),
            Some(true),
            "{asked}"
        );
        assert_eq!(activity(Vec::new()), Some(false), "{asked}");
        assert_eq!(
            activity(vec![
                local(vec![enabled_extension(BETA)]),
                cloud(vec![disabled_extension(BETA)]),
            ]),
            Some(false),
            "{asked}"
        );
    }
}

#[test]
fn activity_and_blocking_are_answered_together_for_one_item() {
    let answer = resolve_one(
        vec![local(vec![enabled_extension(BETA)])],
        ExtensionControlItemV1 {
            extension_ids: vec![BETA.to_owned()],
            permission_ids: Vec::new(),
            active_extension_id: Some(BETA.to_owned()),
        },
    );

    assert!(!answer.blocked);
    assert_eq!(answer.active, Some(true));
}

#[test]
fn an_active_question_about_an_extension_without_a_trust_class_is_a_bound_error() {
    let mut classless = registry();
    classless.extensions[1].trust_class = None;

    // Resolving without an activity question never needs the class.
    let answered = run(&request(ExtensionControlQueryV1::Resolve {
        registry: classless.clone(),
        scenarios: vec![scenario(Vec::new(), vec![item(&[BETA], &[])])],
    }));
    assert_eq!(answered.status, "ok", "{}", answered.code);

    assert_eq!(
        error_code(&request(ExtensionControlQueryV1::Resolve {
            registry: classless,
            scenarios: vec![scenario(Vec::new(), vec![active_item(BETA)])],
        })),
        "native_extension_control_trust_class_missing"
    );
}

#[test]
fn a_registry_the_op_cannot_index_is_a_bound_error() {
    let mut duplicate_extension = registry();
    duplicate_extension
        .extensions
        .push(extension(ALPHA, &[], &[], false, "first-party"));
    let mut duplicate_permission = registry();
    duplicate_permission
        .permissions
        .push(permission(ALPHA_READ, ALPHA, &[], &[]));
    let mut unknown_class = registry();
    unknown_class.extensions[0].trust_class = Some("trusted".to_owned());

    for broken in [duplicate_extension, duplicate_permission, unknown_class] {
        assert_eq!(
            error_code(&request(ExtensionControlQueryV1::Resolve {
                registry: broken,
                scenarios: vec![scenario(Vec::new(), vec![item(&[ALPHA], &[])])],
            })),
            "native_extension_control_registry_invalid"
        );
    }
}

#[test]
fn a_request_over_the_scenario_or_item_limit_is_a_bound_error() {
    let scenarios: Vec<ExtensionControlScenarioV1> =
        (0..65).map(|_| scenario(Vec::new(), Vec::new())).collect();
    assert_eq!(
        error_code(&resolve_request(scenarios)),
        "native_extension_control_too_many_items"
    );
    let items: Vec<ExtensionControlItemV1> = (0..4097).map(|_| item(&[ALPHA], &[])).collect();
    assert_eq!(
        error_code(&resolve_request(vec![scenario(Vec::new(), items)])),
        "native_extension_control_too_many_items"
    );
    let at_limit: Vec<ExtensionControlItemV1> = (0..4096).map(|_| item(&[ALPHA], &[])).collect();
    assert_eq!(
        resolved(vec![scenario(Vec::new(), at_limit)])[0]
            .results
            .len(),
        4096
    );
}

#[test]
fn a_request_over_the_byte_limit_has_no_digest_to_bind() {
    let mut padded = registry();
    padded.extensions[0].aliases = vec!["a".repeat(EXTENSION_CONTROL_MAX_BYTES + 1)];
    let outcome = evaluate_extension_control_request(&request(ExtensionControlQueryV1::Resolve {
        registry: padded,
        scenarios: Vec::new(),
    }));

    assert_eq!(
        outcome,
        Err("native_extension_control_too_large".to_owned())
    );
}

#[test]
fn a_request_for_another_schema_is_a_bound_error() {
    let mut other = request(ExtensionControlQueryV1::Compose { layers: Vec::new() });
    other.schema = "guard-extension-control-request.v0".to_owned();

    assert_eq!(
        error_code(&other),
        "native_extension_control_schema_mismatch"
    );
}

#[test]
fn every_reply_is_bound_to_its_request_by_id_and_digest() {
    let asked = request(ExtensionControlQueryV1::Compose { layers: Vec::new() });
    let result = run(&asked);

    assert_eq!(result.schema, EXTENSION_CONTROL_RESULT_SCHEMA);
    assert_eq!(result.request_id, "extension-control-1");
    assert_eq!(
        result.request_sha256,
        request_digest_with_limit(&asked, EXTENSION_CONTROL_MAX_BYTES).unwrap()
    );
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let mut other = asked;
    other.request_id = "extension-control-2".to_owned();
    assert_ne!(run(&other).request_sha256, result.request_sha256);
}

#[test]
fn failures_with_and_without_a_layer_kind_order_by_string_with_none_first() {
    let ordered = failures_wire(&[
        ControlResolverFailure::new(
            ResolverFailureCode::UnknownExtensionTarget,
            Some(ControlLayerKind::SignedCloud),
        ),
        ControlResolverFailure::new(
            ResolverFailureCode::UnknownExtensionTarget,
            Some(ControlLayerKind::LocalAdmin),
        ),
        ControlResolverFailure::new(ResolverFailureCode::UnknownExtensionTarget, None),
        ControlResolverFailure::new(ResolverFailureCode::UnsupportedControlSchema, None),
        ControlResolverFailure::new(
            ResolverFailureCode::CatalogDigestMismatch,
            Some(ControlLayerKind::LocalAdmin),
        ),
    ]);

    assert_eq!(
        failure_pairs(&ordered),
        vec![
            (
                "catalog-digest-mismatch".to_owned(),
                Some("local-admin".to_owned())
            ),
            ("unknown-extension-target".to_owned(), None),
            (
                "unknown-extension-target".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "unknown-extension-target".to_owned(),
                Some("signed-cloud".to_owned())
            ),
            ("unsupported-control-schema".to_owned(), None),
        ]
    );
}

#[test]
fn the_registry_projection_denies_unknown_fields_and_defaults_nothing() {
    let mut value = serde_json::to_value(request(ExtensionControlQueryV1::Resolve {
        registry: registry(),
        scenarios: Vec::new(),
    }))
    .unwrap();
    assert!(serde_json::from_value::<ExtensionControlRequestV1>(value.clone()).is_ok());
    value["query"]["registry"]["extensions"][0]["unlisted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExtensionControlRequestV1>(value.clone()).is_err());
    value["query"]["registry"]["extensions"][0]
        .as_object_mut()
        .unwrap()
        .remove("unlisted");
    value["query"]["registry"]["extensions"][0]
        .as_object_mut()
        .unwrap()
        .remove("aliases");
    assert!(serde_json::from_value::<ExtensionControlRequestV1>(value).is_err());
}
