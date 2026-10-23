use super::*;
use guard_command::extension_control::CONTROL_SCHEMA_VERSION;
use guard_contracts::{
    NativeExtensionControlLayerV1, NativeExtensionControlV1,
    APPROVAL_EXTENSION_RECOMMENDATION_FEATURE,
};
use serde_json::{json, Value};

const GIT_ADD: &str = "command.git.permission.add";
const HARD_RESET: &str = "command.git.permission.hard-reset";
const COMMIT: &str = "command.git.permission.commit";

/// One control: target kind, target id, state.
type Control = (&'static str, &'static str, &'static str);
const GIT_ADD_ON: Control = ("permission", GIT_ADD, "enabled");

fn catalog() -> Arc<CommandCatalog> {
    packaged_command_catalog().unwrap()
}

fn hint(catalog: &CommandCatalog, permission_ids: &[&str]) -> ExtensionAllowHintV1 {
    let permissions: Vec<&CatalogPermission> = permission_ids
        .iter()
        .map(|id| catalog.permission(id).expect("a packaged permission"))
        .collect();
    let mut extension_ids: Vec<String> = permissions
        .iter()
        .map(|permission| permission.extension_id.clone())
        .collect();
    extension_ids.sort();
    extension_ids.dedup();
    ExtensionAllowHintV1 {
        schema: EXTENSION_ALLOW_HINT_SCHEMA.into(),
        permission_ids: permission_ids.iter().map(|id| (*id).into()).collect(),
        rule_ids: permissions
            .iter()
            .map(|permission| permission.rule_ids[0].clone())
            .collect(),
        extension_ids,
        relied_permission_ids: Vec::new(),
        catalog_digest: catalog.catalog_digest.clone(),
    }
}

fn layer(
    catalog: &CommandCatalog,
    kind: &str,
    global_lockdown: bool,
    controls: &[Control],
) -> NativeExtensionControlLayerV1 {
    NativeExtensionControlLayerV1 {
        schema_version: CONTROL_SCHEMA_VERSION.into(),
        kind: kind.into(),
        catalog_digest: catalog.catalog_digest.clone(),
        global_lockdown,
        controls: controls
            .iter()
            .map(|(target_kind, target_id, state)| NativeExtensionControlV1 {
                target_kind: (*target_kind).into(),
                target_id: (*target_id).into(),
                state: (*state).into(),
            })
            .collect(),
    }
}

fn snapshot(
    catalog: &CommandCatalog,
    health: &str,
    local: &[Control],
    managed: &[Control],
) -> ApprovalExtensionRecommendationSnapshotV1 {
    let mut layers = vec![layer(catalog, "local-admin", false, local)];
    if !managed.is_empty() {
        layers.push(layer(catalog, "signed-cloud", false, managed));
    }
    ApprovalExtensionRecommendationSnapshotV1 {
        health: health.into(),
        revision: 7,
        catalog_digest: catalog.catalog_digest.clone(),
        layers,
    }
}

fn request(
    query: ApprovalExtensionRecommendationQueryV1,
) -> ApprovalExtensionRecommendationRequestV1 {
    ApprovalExtensionRecommendationRequestV1 {
        schema: APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA.into(),
        request_id: "recommendation-test".into(),
        query,
    }
}

fn recommend_request(
    catalog: &CommandCatalog,
    hint: ExtensionAllowHintV1,
    snapshot: ApprovalExtensionRecommendationSnapshotV1,
) -> ApprovalExtensionRecommendationRequestV1 {
    request(ApprovalExtensionRecommendationQueryV1::Recommend {
        hint: Box::new(hint),
        registry_catalog_digest: catalog.catalog_digest.clone(),
        snapshot,
    })
}

fn answer(
    request: &ApprovalExtensionRecommendationRequestV1,
) -> ApprovalExtensionRecommendationResultV1 {
    let bytes = evaluate_with_catalog(request, Some(&catalog())).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn recommendation(
    hint: ExtensionAllowHintV1,
    snapshot: ApprovalExtensionRecommendationSnapshotV1,
) -> Option<ApprovalExtensionRecommendationV1> {
    let result = answer(&recommend_request(&catalog(), hint, snapshot));
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload.expect("an ok answer carries a payload") {
        ApprovalExtensionRecommendationPayloadV1::Recommend { recommendation } => recommendation,
        other => panic!("unexpected payload {other:?}"),
    }
}

fn error_code(request: &ApprovalExtensionRecommendationRequestV1) -> String {
    let result = answer(request);
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());
    result.code
}

#[test]
fn available_recommendation_for_git_add() {
    let catalog = catalog();
    let recommendation = recommendation(
        hint(&catalog, &[GIT_ADD]),
        snapshot(&catalog, "protected", &[], &[]),
    )
    .expect("an applicable hint is recommended");
    assert_eq!(
        recommendation.schema,
        APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA
    );
    assert_eq!(recommendation.status, "available");
    assert!(!recommendation.caution);
    assert_eq!(recommendation.revision, 7);
    assert_eq!(recommendation.catalog_digest, catalog.catalog_digest);
    let [permission] = recommendation.permissions.as_slice() else {
        panic!("one permission is recommended");
    };
    assert_eq!(permission.permission_id, GIT_ADD);
    assert_eq!(permission.extension_id, "command.git");
    assert_eq!(permission.rule_id.as_deref(), Some("command.git.add"));
    assert!(permission.label.is_some());
    assert!(!permission.caution);
    assert!(permission.caution_reason.is_none() && permission.caution_detail.is_none());
    assert_eq!(
        permission.cli_command,
        format!("hol-guard command controls set {GIT_ADD} --state allow")
    );
    assert!(!serde_json::to_string(&recommendation)
        .unwrap()
        .contains("src/app.py"));
}

#[test]
fn destructive_permission_carries_caution() {
    let catalog = catalog();
    let recommendation = recommendation(
        hint(&catalog, &[HARD_RESET]),
        snapshot(&catalog, "protected", &[], &[]),
    )
    .expect("a destructive permission is still recommended");
    assert!(recommendation.caution);
    let permission = &recommendation.permissions[0];
    assert!(permission.caution);
    assert!(["critical", "destructive", "sensitive"]
        .contains(&permission.caution_reason.as_deref().unwrap()));
    assert!(permission.caution_detail.is_some());
}

#[test]
fn no_recommendation_when_not_applicable() {
    let catalog = catalog();
    let hint = hint(&catalog, &[GIT_ADD]);
    let healthy = |local: &[Control], managed: &[Control]| {
        recommendation(
            hint.clone(),
            snapshot(&catalog, "protected", local, managed),
        )
    };
    assert!(healthy(&[], &[]).is_some());
    // Already allowed locally, or switched off by the managed layer.
    assert!(healthy(&[GIT_ADD_ON], &[]).is_none());
    assert!(healthy(&[], &[("permission", GIT_ADD, "disabled")]).is_none());
    // The owning extension is switched off locally or by the managed layer.
    assert!(healthy(&[("extension", "command.git", "disabled")], &[]).is_none());
    assert!(healthy(&[], &[("extension", "command.git", "disabled")]).is_none());
    // A hint recorded under another catalog is stale.
    let mut stale = hint.clone();
    stale.catalog_digest = "0".repeat(64);
    assert!(recommendation(stale, snapshot(&catalog, "protected", &[], &[])).is_none());
    // A permission the catalog does not know.
    let mut unknown = hint.clone();
    unknown.permission_ids = vec!["command.git.permission.no-such-permission".into()];
    assert!(recommendation(unknown, snapshot(&catalog, "protected", &[], &[])).is_none());
    // A global lockdown withholds every recommendation.
    let mut locked = snapshot(&catalog, "protected", &[], &[]);
    locked.layers[0].global_lockdown = true;
    assert!(recommendation(hint.clone(), locked).is_none());
}

#[test]
fn a_later_control_replaces_an_earlier_one_for_the_same_target() {
    let catalog = catalog();
    let hint = hint(&catalog, &[GIT_ADD]);
    let mut layers = snapshot(&catalog, "protected", &[], &[]);
    layers.layers.push(layer(
        &catalog,
        "local-admin",
        false,
        &[("permission", GIT_ADD, "enabled")],
    ));
    // The last local-admin layer wins, so the permission is already allowed.
    assert!(recommendation(hint.clone(), layers.clone()).is_none());
    layers.layers.push(layer(
        &catalog,
        "local-admin",
        false,
        &[("permission", GIT_ADD, "disabled")],
    ));
    assert!(recommendation(hint, layers).is_some());
}

#[test]
fn relied_permission_must_still_be_enabled() {
    let catalog = catalog();
    assert!(catalog.permission(COMMIT).is_some());
    let mut relied = hint(&catalog, &[GIT_ADD]);
    relied.relied_permission_ids = vec![COMMIT.into()];
    let build = |local: &[Control], managed: &[Control]| {
        recommendation(
            relied.clone(),
            snapshot(&catalog, "protected", local, managed),
        )
    };
    let on: [Control; 1] = [("permission", COMMIT, "enabled")];
    let off: [Control; 1] = [("permission", COMMIT, "disabled")];
    assert!(build(&on, &[]).is_some());
    assert!(build(&[], &on).is_some());
    assert!(build(&[], &[]).is_none());
    assert!(build(&on, &off).is_none());
    // A hint queued before relied permissions were recorded has none to check.
    assert!(recommendation(
        hint(&catalog, &[GIT_ADD]),
        snapshot(&catalog, "protected", &[], &[])
    )
    .is_some());
}

#[test]
fn unhealthy_authority_reports_unavailable() {
    let catalog = catalog();
    for health in [
        "unenrolled",
        "degraded-unacknowledged",
        "degraded-acknowledged",
        "tampered",
        "recovery-required",
    ] {
        let recommendation = recommendation(
            hint(&catalog, &[GIT_ADD]),
            snapshot(&catalog, health, &[], &[]),
        )
        .expect("an advisory recommendation is still shown");
        assert_eq!(recommendation.status, "authority_unavailable", "{health}");
    }
}

#[test]
fn malformed_inputs_are_refused_with_their_own_code() {
    let catalog = catalog();
    let good_hint = hint(&catalog, &[GIT_ADD]);
    let good_snapshot = snapshot(&catalog, "protected", &[], &[]);

    let mut unknown_health = good_snapshot.clone();
    unknown_health.health = "healthy".into();
    assert_eq!(
        error_code(&recommend_request(
            &catalog,
            good_hint.clone(),
            unknown_health
        )),
        SNAPSHOT_INVALID
    );

    let mut bad_layer = good_snapshot.clone();
    bad_layer.layers[0].kind = "bogus".into();
    assert_eq!(
        error_code(&recommend_request(&catalog, good_hint.clone(), bad_layer)),
        SNAPSHOT_INVALID
    );

    let mut foreign_hint = good_hint.clone();
    foreign_hint.schema = "bogus".into();
    assert_eq!(
        error_code(&recommend_request(
            &catalog,
            foreign_hint,
            good_snapshot.clone()
        )),
        HINT_INVALID
    );

    let mut wide_hint = good_hint.clone();
    wide_hint.permission_ids =
        vec![GIT_ADD.into(); APPROVAL_EXTENSION_RECOMMENDATION_MAX_HINT_IDS + 1];
    assert_eq!(
        error_code(&recommend_request(
            &catalog,
            wide_hint,
            good_snapshot.clone()
        )),
        HINT_INVALID
    );

    let mut foreign = request(ApprovalExtensionRecommendationQueryV1::CautionRiskClasses {
        risk_classes: Vec::new(),
    });
    foreign.schema = "bogus".into();
    assert_eq!(error_code(&foreign), SCHEMA_MISMATCH);
}

#[test]
fn a_registry_the_resident_has_not_admitted_is_refused() {
    let catalog = catalog();
    let mut other = hint(&catalog, &[GIT_ADD]);
    other.catalog_digest = "1".repeat(64);
    let query = ApprovalExtensionRecommendationQueryV1::Recommend {
        hint: Box::new(other),
        registry_catalog_digest: "1".repeat(64),
        snapshot: snapshot(&catalog, "protected", &[], &[]),
    };
    assert_eq!(error_code(&request(query.clone())), CATALOG_MISMATCH);
    let bytes = evaluate_with_catalog(&request(query), None).unwrap();
    let result: ApprovalExtensionRecommendationResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.code, CATALOG_UNAVAILABLE);
}

#[test]
fn caution_risk_classes_are_the_sensitive_set() {
    let ask = |classes: &[&str]| {
        let result = answer(&request(
            ApprovalExtensionRecommendationQueryV1::CautionRiskClasses {
                risk_classes: classes.iter().map(|class| (*class).into()).collect(),
            },
        ));
        assert_eq!(result.status, "ok", "{}", result.code);
        match result.payload.expect("an ok answer carries a payload") {
            ApprovalExtensionRecommendationPayloadV1::CautionRiskClasses { risk_classes } => {
                risk_classes
            }
            other => panic!("unexpected payload {other:?}"),
        }
    };
    assert_eq!(
        ask(&[
            "policy_bypass",
            "benign",
            "destructive",
            "local_secret_read",
            "destructive",
        ]),
        ["destructive", "local_secret_read", "policy_bypass"]
    );
    assert!(ask(&[]).is_empty());
    assert!(ask(&["Destructive", "network"]).is_empty());
    for class in CAUTION_RISK_CLASSES {
        assert_eq!(ask(&[class]), [class]);
    }
    let too_many = request(ApprovalExtensionRecommendationQueryV1::CautionRiskClasses {
        risk_classes: vec![
            "destructive".into();
            APPROVAL_EXTENSION_RECOMMENDATION_MAX_RISK_CLASSES + 1
        ],
    });
    assert_eq!(error_code(&too_many), TOO_MANY_RISK_CLASSES);
}

#[test]
fn display_text_is_collapsed_like_python_split_join() {
    assert_eq!(
        bounded("a \t b\u{1c}c\u{a0}d\n", 240).as_deref(),
        Some("a b c d")
    );
    assert_eq!(bounded("  \u{1f}\u{85}  ", 10), None);
    assert_eq!(bounded("", 10), None);
    assert_eq!(bounded("abcdef", 3).as_deref(), Some("abc"));
    // The cut counts characters, never splits one.
    assert_eq!(
        bounded("\u{e9}\u{e9}\u{e9}\u{e9}", 2).as_deref(),
        Some("\u{e9}\u{e9}")
    );
}

#[test]
fn an_oversized_request_is_refused_before_any_work() {
    let request = request(ApprovalExtensionRecommendationQueryV1::CautionRiskClasses {
        risk_classes: vec!["x".repeat(APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES)],
    });
    assert_eq!(
        evaluate_with_catalog(&request, None).unwrap_err(),
        TOO_LARGE
    );
}

#[test]
fn a_snapshot_the_store_will_not_admit_is_a_bound_error_not_a_transport_failure() {
    let catalog = catalog();
    let request = recommend_request(
        &catalog,
        hint(&catalog, &[GIT_ADD]),
        snapshot(&catalog, "protected", &[], &[]),
    );
    for refusal in [
        "native_policy_snapshot_expired",
        "native_policy_snapshot_invalid",
        "native_policy_snapshot_context_mismatch",
    ] {
        let bytes = evaluate_with_snapshot(&request, || Some(Err(refusal.to_owned()))).unwrap();
        let result: ApprovalExtensionRecommendationResultV1 =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.status, "error", "{refusal}");
        assert_eq!(result.code, CATALOG_UNAVAILABLE, "{refusal}");
        assert!(result.payload.is_none());
        assert_eq!(result.request_id, "recommendation-test");
        assert!(result.request_sha256.starts_with("sha256:"));
    }
}

#[test]
fn no_snapshot_falls_back_to_the_packaged_catalog_and_a_caution_query_reads_none() {
    let catalog = catalog();
    let request = recommend_request(
        &catalog,
        hint(&catalog, &[GIT_ADD]),
        snapshot(&catalog, "protected", &[], &[]),
    );
    for read in [None, Some(Err("native_policy_snapshot_missing".to_owned()))] {
        let bytes = evaluate_with_snapshot(&request, || read).unwrap();
        let result: ApprovalExtensionRecommendationResultV1 =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.status, "ok", "{}", result.code);
    }
    let caution = request_for_caution(&["destructive"]);
    let bytes = evaluate_with_snapshot(&caution, || {
        unreachable!("a caution query reads no snapshot")
    })
    .unwrap();
    let result: ApprovalExtensionRecommendationResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
}

fn request_for_caution(risk_classes: &[&str]) -> ApprovalExtensionRecommendationRequestV1 {
    request(ApprovalExtensionRecommendationQueryV1::CautionRiskClasses {
        risk_classes: risk_classes.iter().map(|class| (*class).into()).collect(),
    })
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&APPROVAL_EXTENSION_RECOMMENDATION_FEATURE));
}

#[test]
fn resident_transport_binds_replies_and_rejects_unknown_fields() {
    let catalog = catalog();
    let envelope = |request: Value| {
        json!({"operation": "approval_extension_recommendation", "request": request}).to_string()
    };
    let recommend = serde_json::to_value(recommend_request(
        &catalog,
        hint(&catalog, &[GIT_ADD]),
        snapshot(&catalog, "protected", &[], &[]),
    ))
    .unwrap();
    let out = crate::resident_protocol::evaluate_resident_bytes(
        envelope(recommend.clone()).as_bytes(),
        None,
    )
    .expect("a recommend query is answered");
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        reply["schema"],
        APPROVAL_EXTENSION_RECOMMENDATION_RESULT_SCHEMA
    );
    assert_eq!(reply["request_id"], "recommendation-test");
    assert_eq!(reply["status"], "ok");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["kind"], "recommend");
    assert_eq!(reply["payload"]["recommendation"]["status"], "available");
    assert_eq!(
        reply["payload"]["recommendation"]["permissions"][0]["permission_id"],
        GIT_ADD
    );

    let mut stale = recommend.clone();
    stale["query"]["hint"]["catalog_digest"] = json!("0".repeat(64));
    let out = crate::resident_protocol::evaluate_resident_bytes(envelope(stale).as_bytes(), None)
        .expect("a stale hint is a bound reply");
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(
        reply["payload"],
        json!({"kind": "recommend", "recommendation": null})
    );

    let mut foreign = recommend.clone();
    foreign["schema"] = json!("bogus");
    let out = crate::resident_protocol::evaluate_resident_bytes(envelope(foreign).as_bytes(), None)
        .expect("a foreign schema is a bound reply");
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], SCHEMA_MISMATCH);

    let mut surprise = recommend;
    surprise["query"]["surprise"] = json!(true);
    assert!(
        crate::resident_protocol::evaluate_resident_bytes(envelope(surprise).as_bytes(), None)
            .is_err()
    );
}
