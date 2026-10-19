use super::*;
use crate::hook_direct::saved_decision::tests::{
    integrity_state, local_store, sign_decision, KEY, KEY_ID, SIGNED_AT,
};
use guard_contracts::{
    ClaimEvidenceBindingV1, PolicyDecisionLookupRequestV1, POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
};
use rusqlite::params;
use serde_json::json;

const ARTIFACT: &str = "npm:lodash";
const TOKEN: &str = "sha256:abc";
const PORTABLE: &str = "git-project:v1:0000000000000000";
const LOCAL: &str = "/workspace/clone";

fn key_b64() -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(&KEY)
}

fn request(store: &std::path::Path, workspace: Option<&str>) -> PolicyDecisionLookupRequestV1 {
    PolicyDecisionLookupRequestV1 {
        schema: POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
        request_id: "req-portable".to_owned(),
        store_path: store.to_string_lossy().into_owned(),
        guard_home: "/tmp/gh".to_owned(),
        harness: "claude-code".to_owned(),
        artifact_id: Some(ARTIFACT.to_owned()),
        artifact_hash: Some(TOKEN.to_owned()),
        workspace: workspace.map(str::to_owned),
        publisher: None,
        now: "2030-01-01T00:00:00+00:00".to_owned(),
        runtime_exact_match_context: None,
        consume_one_shot: false,
        local_once_only: false,
        integrity_state: Some(serde_json::to_value(integrity_state()).unwrap()),
        integrity_key_b64: Some(key_b64()),
        integrity_key_id: Some(KEY_ID.to_owned()),
        local_once_integrity_key_b64: Some(key_b64()),
        local_once_integrity_key_id: Some(KEY_ID.to_owned()),
        policy_bundle_decision_identities: None,
        probe_groups: None,
        portable_workspace: Some(PORTABLE.to_owned()),
        evidence_binding: None,
    }
}

/// A signed workspace-scoped decision for the artifact.
fn decide(connection: &Connection, workspace: &str, action: &str) {
    connection
        .execute(
            "insert into policy_decisions (harness, scope, artifact_id, action, artifact_hash,
               workspace, source, created_at, updated_at)
             values ('claude-code', 'workspace', ?1, ?2, ?3, ?4, 'approval-gate', ?5, ?5)",
            params![ARTIFACT, action, TOKEN, workspace, SIGNED_AT],
        )
        .unwrap();
    sign_decision(connection, connection.last_insert_rowid());
}

fn action_of(lookup: &Value) -> Option<String> {
    Some(
        lookup
            .get("decision")?
            .as_object()?
            .get("action")?
            .as_str()?
            .to_owned(),
    )
}

#[test]
fn the_preview_only_authority_revision_is_removed_from_an_enforcement_result() {
    let carried = json!({"decision": {"action": "review", "_approval_authority_revision": 5}});
    let stripped = without_authority_revision(carried);
    assert_eq!(stripped, json!({"decision": {"action": "review"}}));

    let plain = json!({"decision": {"action": "review"}});
    assert_eq!(without_authority_revision(plain.clone()), plain);

    let empty = json!({"decision": Value::Null});
    assert_eq!(without_authority_revision(empty.clone()), empty);
}

#[test]
fn an_unclaimable_allow_is_dropped_and_a_restriction_is_kept() {
    let allow = json!({"decision": {"action": "allow", "_approval_authority_revision": 5}});
    assert_eq!(restrictive_only(allow), json!({"decision": Value::Null}));

    let warn = json!({"decision": {"action": "warn"}});
    assert_eq!(restrictive_only(warn), json!({"decision": Value::Null}));

    let review = json!({"decision": {"action": "review", "_approval_authority_revision": 5}});
    assert_eq!(
        restrictive_only(review),
        json!({"decision": {"action": "review"}})
    );

    let none = json!({"decision": Value::Null, "trust_status": {}});
    assert_eq!(restrictive_only(none.clone()), none);
}

/// The exact local-once peek reads no portable authority, so Python derives no
/// identity for it and a request carrying both is malformed.
#[test]
fn a_local_once_only_request_carries_no_portable_identity() {
    let (store, _connection) = local_store("portable-once");
    let mut request = request(&store, Some(LOCAL));
    request.local_once_only = true;
    assert_eq!(
        evaluate(&request, PORTABLE),
        Err("native_policy_decision_lookup_invalid".to_owned())
    );
}

/// The composition's own probes are plain non-consuming lookups; a probe that
/// carried the identity again would compose it twice.
#[test]
fn a_non_consuming_probe_refuses_a_portable_identity() {
    let (store, connection) = local_store("portable-probe");
    let request = request(&store, Some(LOCAL));
    assert_eq!(
        crate::policy_decision_lookup_op::evaluate_non_consuming(&request, &connection),
        Err("native_policy_decision_lookup_invalid".to_owned())
    );
}

/// A managed restriction written against the portable identity reaches this
/// clone: that is what a portable selector is for.
#[test]
fn a_portable_restriction_composes_into_the_local_lookup() {
    let (store, connection) = local_store("portable-review");
    decide(&connection, PORTABLE, "review");
    let lookup = evaluate(&request(&store, Some(LOCAL)), PORTABLE).unwrap();
    assert_eq!(action_of(&lookup).as_deref(), Some("review"));
}

/// Git metadata lives inside the workspace and can be forged by it, so a
/// permission written against the portable identity never answers for this
/// clone.
#[test]
fn a_portable_allow_grants_this_clone_nothing() {
    let (store, connection) = local_store("portable-allow");
    decide(&connection, PORTABLE, "allow");
    let lookup = evaluate(&request(&store, Some(LOCAL)), PORTABLE).unwrap();
    assert_eq!(lookup["decision"], Value::Null);
}

/// A workspace that already names the identity reads that lookup alone — and
/// it is restrictive-only there too, so the forged-identity path gains nothing
/// by naming itself.
#[test]
fn a_workspace_that_names_the_identity_elevates_no_permission() {
    let (store, connection) = local_store("portable-named");
    decide(&connection, PORTABLE, "allow");
    let lookup = evaluate(&request(&store, Some(PORTABLE)), PORTABLE).unwrap();
    assert_eq!(lookup["decision"], Value::Null);

    decide(&connection, PORTABLE, "review");
    let lookup = evaluate(&request(&store, Some(PORTABLE)), PORTABLE).unwrap();
    assert_eq!(action_of(&lookup).as_deref(), Some("review"));
}

/// An allow the claim cannot take is never served: the permission can be
/// presented again on the caller's next approval cycle, but this call enforces
/// without it.
#[test]
fn an_unclaimable_local_allow_is_not_served() {
    let (store, connection) = local_store("portable-claim");
    decide(&connection, LOCAL, "allow");
    let preview = evaluate(&request(&store, Some(LOCAL)), PORTABLE).unwrap();
    assert_eq!(action_of(&preview).as_deref(), Some("allow"));
    let mut consuming = request(&store, Some(LOCAL));
    consuming.consume_one_shot = true;
    consuming.evidence_binding = Some(ClaimEvidenceBindingV1::default());
    let lookup = evaluate(&consuming, PORTABLE).unwrap();
    assert_eq!(lookup["decision"], Value::Null);
}

/// A policy-source allow cannot be claimed at all without the binding its
/// evidence was derived against.
#[test]
fn an_unbound_claim_is_refused() {
    let (store, connection) = local_store("portable-unbound");
    decide(&connection, LOCAL, "allow");
    let mut request = request(&store, Some(LOCAL));
    request.consume_one_shot = true;
    let lookup = evaluate(&request, PORTABLE).unwrap();
    assert_eq!(lookup["decision"], Value::Null);
}

/// A restriction is enforced as it stands, without the preview-only revision
/// the claim compares.
#[test]
fn a_consuming_composition_strips_the_preview_only_revision() {
    let (store, connection) = local_store("portable-consume-review");
    decide(&connection, LOCAL, "review");
    let mut request = request(&store, Some(LOCAL));
    request.consume_one_shot = true;
    let lookup = evaluate(&request, PORTABLE).unwrap();
    assert_eq!(action_of(&lookup).as_deref(), Some("review"));
    assert_eq!(lookup["decision"].get("_approval_authority_revision"), None);
}
