//! Golden business policy cases. Each role overlay only adds rules to the
//! managed-team baseline, so a role can tighten but never loosen a floor.

use super::*;
use guard_contracts::{BusinessActionClassV1, BusinessOperationV1};
use guard_policy_snapshot::business_policy::BUSINESS_POLICY_BINDING_SCHEMA;
use serde_json::{json, Value};

const GMAIL: &str = "google_gmail";
const DRIVE: &str = "google_drive";
const CALENDAR: &str = "google_calendar";

fn rule(id: &str, action: &str, services: &[&str], operations: &[&str], extra: Value) -> Value {
    let mut selector = json!({"schema":"guard.business-policy-match.v1","version":1,
        "services":services,"operations":operations});
    for (key, value) in extra.as_object().unwrap() {
        selector[key] = value.clone();
    }
    json!({"id":id,"action":action,"match":selector})
}

// Managed-team baseline: reads, drafts, edits and small exports run; sends and
// shares need review; public shares and mailbox administration are blocked.
fn baseline() -> Vec<Value> {
    vec![
        rule(
            "read.allow",
            "allow",
            &[GMAIL, DRIVE, CALENDAR],
            &["mail_read", "drive_read", "calendar_read"],
            json!({}),
        ),
        rule("draft.allow", "allow", &[GMAIL], &["mail_draft"], json!({})),
        rule(
            "draft.sensitive",
            "review",
            &[GMAIL],
            &["mail_draft"],
            json!({"sensitivityLabels":["confidential","secret"]}),
        ),
        rule(
            "send.review",
            "review",
            &[GMAIL, CALENDAR],
            &["mail_send", "calendar_invite"],
            json!({}),
        ),
        rule(
            "update.allow",
            "allow",
            &[GMAIL, DRIVE],
            &["mail_label", "drive_edit"],
            json!({}),
        ),
        rule(
            "share.review",
            "review",
            &[DRIVE],
            &["drive_share"],
            json!({}),
        ),
        rule(
            "share.public",
            "block",
            &[DRIVE],
            &["drive_share"],
            json!({"audienceKinds":["public"]}),
        ),
        rule(
            "export.allow",
            "allow",
            &[DRIVE],
            &["drive_export"],
            json!({}),
        ),
        rule(
            "export.volume",
            "review",
            &[DRIVE],
            &["drive_export"],
            json!({"minRecordCount":100}),
        ),
        rule(
            "admin.block",
            "block",
            &[GMAIL],
            &["mail_settings", "mail_permanent_delete"],
            json!({}),
        ),
    ]
}

fn roles() -> Vec<(&'static str, Vec<Value>)> {
    vec![
        ("baseline", vec![]),
        (
            "sales",
            vec![rule(
                "sales.secret_send",
                "block",
                &[GMAIL],
                &["mail_send"],
                json!({"sensitivityLabels":["secret"]}),
            )],
        ),
        (
            "marketing",
            vec![
                rule(
                    "marketing.share",
                    "block",
                    &[DRIVE],
                    &["drive_share"],
                    json!({}),
                ),
                rule(
                    "marketing.list_export",
                    "review",
                    &[DRIVE],
                    &["drive_export"],
                    json!({"minRecordCount":1}),
                ),
            ],
        ),
        (
            "bd",
            vec![rule(
                "bd.external_share",
                "review",
                &[DRIVE],
                &["drive_share"],
                json!({"audienceKinds":["named"]}),
            )],
        ),
        (
            "operations",
            vec![rule(
                "operations.bulk_edit",
                "review",
                &[DRIVE],
                &["drive_edit"],
                json!({"minRecordCount":50}),
            )],
        ),
    ]
}

fn policy(extra: &[Value]) -> CompiledBusinessPolicy {
    let mut rules = baseline();
    rules.extend_from_slice(extra);
    let binding: BusinessPolicyBindingV1 = serde_json::from_value(json!({
        "schema": BUSINESS_POLICY_BINDING_SCHEMA, "version": 1,
        "defaultAction": "review", "rules": rules}))
    .unwrap();
    CompiledBusinessPolicy::new(&binding).unwrap()
}

fn service(operation: &str) -> &'static str {
    match operation.split('_').next().unwrap() {
        "mail" => GMAIL,
        "drive" => DRIVE,
        _ => CALENDAR,
    }
}

fn facts(operation: &str, audience: &str, records: u64, label: &str) -> BusinessActionV1 {
    let kind = match service(operation) {
        GMAIL => "to",
        DRIVE => "collaborator",
        _ => "calendar_attendee",
    };
    let recipients = if audience == "named" {
        json!([{"identity_binding":"e".repeat(64),"domain":"partner.test","kind":kind}])
    } else {
        json!([])
    };
    let count = u64::from(audience == "named");
    BusinessActionV1::from_bounded_json(
        &serde_json::to_vec(&json!({
            "schema":"guard.business-action.v1","version":1,
            "provider":{"service":service(operation),"account_binding":"a".repeat(64),
            "tenant_binding":"b".repeat(64),"identity_state":"known",
            "tool_identity_digest":"c".repeat(64),"tool_schema_digest":"d".repeat(64)},
            "operation":operation,"audience":{"kind":audience,"expansion_state":"known",
            "recipients":recipients},
            "content":{"snapshot_digest":"1".repeat(64),"attachment_digests":[],
            "inspection_state":"known","inspected_bytes":64,"sensitivity_labels":[label]},
            "target":{"resource_binding":"3".repeat(64),"revision_binding":"4".repeat(64),
            "field_diff_digest":"5".repeat(64),"batch_manifest_digest":"6".repeat(64)},
            "volume":{"recipient_count":count,"record_count":records,"byte_count":64},
            "completeness":"known"
        }))
        .unwrap(),
    )
    .unwrap()
}

fn class(operation: &str) -> BusinessActionClassV1 {
    serde_json::from_value::<BusinessOperationV1>(json!(operation))
        .unwrap()
        .action_class()
}

// One representative complete action for every operation.
fn every_operation() -> Vec<BusinessActionV1> {
    [
        ("mail_read", "private"),
        ("mail_draft", "named"),
        ("mail_send", "named"),
        ("mail_label", "private"),
        ("mail_permanent_delete", "private"),
        ("mail_settings", "private"),
        ("drive_read", "private"),
        ("drive_edit", "private"),
        ("drive_share", "named"),
        ("drive_share", "public"),
        ("drive_export", "private"),
        ("calendar_read", "private"),
        ("calendar_invite", "named"),
    ]
    .into_iter()
    .map(|(operation, audience)| facts(operation, audience, 1, "public"))
    .collect()
}

#[test]
fn baseline_distinguishes_draft_send_share_export_and_admin() {
    let policy = policy(&[]);
    let cases = [
        (
            "mail_draft",
            "named",
            1,
            "public",
            ActionFloor::Allow,
            vec!["draft.allow"],
        ),
        (
            "mail_draft",
            "named",
            1,
            "confidential",
            ActionFloor::Review,
            vec!["draft.allow", "draft.sensitive"],
        ),
        (
            "mail_send",
            "named",
            1,
            "public",
            ActionFloor::Review,
            vec!["send.review"],
        ),
        (
            "drive_share",
            "named",
            1,
            "public",
            ActionFloor::Review,
            vec!["share.review"],
        ),
        (
            "drive_share",
            "public",
            1,
            "public",
            ActionFloor::Block,
            vec!["share.public", "share.review"],
        ),
        (
            "drive_export",
            "private",
            10,
            "public",
            ActionFloor::Allow,
            vec!["export.allow"],
        ),
        (
            "drive_export",
            "private",
            100,
            "public",
            ActionFloor::Review,
            vec!["export.allow", "export.volume"],
        ),
        (
            "mail_settings",
            "private",
            1,
            "public",
            ActionFloor::Block,
            vec!["admin.block"],
        ),
    ];
    for (operation, audience, records, label, action, rules) in cases {
        let output = policy.floor(
            ActionFloor::Allow,
            Some(&facts(operation, audience, records, label)),
        );
        assert_eq!(
            output.action, action,
            "{operation} {audience} {records} {label}"
        );
        assert_eq!(
            output.matched_rule_ids, rules,
            "{operation} {audience} {records} {label}"
        );
    }
    let classes: Vec<_> = [
        "mail_draft",
        "mail_send",
        "drive_share",
        "drive_export",
        "mail_settings",
    ]
    .into_iter()
    .map(class)
    .collect();
    assert_eq!(
        classes,
        [
            BusinessActionClassV1::Draft,
            BusinessActionClassV1::Send,
            BusinessActionClassV1::Share,
            BusinessActionClassV1::Export,
            BusinessActionClassV1::Admin,
        ]
    );
}

#[test]
fn role_overlays_only_tighten_the_baseline() {
    let baseline = policy(&[]);
    for (role, extra) in roles() {
        let policy = policy(&extra);
        for action in every_operation() {
            for records in [1, 100] {
                let mut action = action.clone();
                action.volume.record_count = records;
                let base = baseline.floor(ActionFloor::Allow, Some(&action));
                let output = policy.floor(ActionFloor::Allow, Some(&action));
                assert!(
                    output.action >= base.action,
                    "{role} {:?}",
                    action.operation
                );
                assert!(
                    base.matched_rule_ids
                        .iter()
                        .all(|id| output.matched_rule_ids.contains(id)),
                    "{role} {:?}",
                    action.operation
                );
            }
        }
    }
}

#[test]
fn role_specific_golden_outcomes() {
    let cases = [
        (
            "sales",
            "mail_send",
            "named",
            1,
            "secret",
            ActionFloor::Block,
            vec!["sales.secret_send", "send.review"],
        ),
        (
            "sales",
            "mail_send",
            "named",
            1,
            "public",
            ActionFloor::Review,
            vec!["send.review"],
        ),
        (
            "marketing",
            "drive_share",
            "named",
            1,
            "public",
            ActionFloor::Block,
            vec!["marketing.share", "share.review"],
        ),
        (
            "marketing",
            "drive_export",
            "private",
            1,
            "public",
            ActionFloor::Review,
            vec!["export.allow", "marketing.list_export"],
        ),
        (
            "bd",
            "drive_share",
            "named",
            1,
            "public",
            ActionFloor::Review,
            vec!["bd.external_share", "share.review"],
        ),
        (
            "bd",
            "drive_export",
            "private",
            1,
            "public",
            ActionFloor::Allow,
            vec!["export.allow"],
        ),
        (
            "operations",
            "drive_edit",
            "private",
            49,
            "public",
            ActionFloor::Allow,
            vec!["update.allow"],
        ),
        (
            "operations",
            "drive_edit",
            "private",
            50,
            "public",
            ActionFloor::Review,
            vec!["operations.bulk_edit", "update.allow"],
        ),
    ];
    let roles = roles();
    for (role, operation, audience, records, label, action, rules) in cases {
        let extra = &roles.iter().find(|(name, _)| *name == role).unwrap().1;
        let output = policy(extra).floor(
            ActionFloor::Allow,
            Some(&facts(operation, audience, records, label)),
        );
        // Rule IDs catch an overlay whose outcome the baseline already gives.
        assert_eq!(
            output.action, action,
            "{role} {operation} {records} {label}"
        );
        assert_eq!(
            output.matched_rule_ids, rules,
            "{role} {operation} {records} {label}"
        );
    }
}

#[test]
fn every_role_preserves_intrinsic_blocks_and_stops_without_identity() {
    for (role, extra) in roles() {
        let policy = policy(&extra);
        // Secret, filesystem and supply-chain findings arrive as an intrinsic
        // block; no business rule or default can lower it.
        for action in every_operation() {
            for intrinsic in [ActionFloor::Block, ActionFloor::SandboxRequired] {
                assert!(
                    policy.floor(intrinsic, Some(&action)).action >= intrinsic,
                    "{role} {:?}",
                    action.operation
                );
            }
            let mut unknown = action.clone();
            unknown.provider.account_binding = None;
            unknown.provider.tenant_binding = None;
            unknown.provider.identity_state = serde_json::from_value(json!("unknown")).unwrap();
            assert_eq!(
                policy.floor(ActionFloor::Allow, Some(&unknown)).action,
                ActionFloor::Block,
                "{role} {:?}",
                action.operation
            );
        }
        assert_eq!(
            policy.floor(ActionFloor::Allow, None).action,
            ActionFloor::Block
        );
    }
}
