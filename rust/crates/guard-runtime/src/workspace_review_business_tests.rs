use super::*;
use guard_command::business_input::business_input_snapshot_digest;
use guard_policy_snapshot::business_source_anchor::{
    sign_business_source_anchor, BusinessSourcePhase,
};
use guard_policy_snapshot::business_source_authority::{
    sign_business_source, verify_business_source,
};
use guard_policy_snapshot::{integrity_mac, policy_digest, PolicySnapshotV3};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};

#[path = "workspace_review_owned_input_tests.rs"]
pub(super) mod owned_input_tests;

#[path = "workspace_review_local_summary_tests.rs"]
mod local_summary_tests;

pub(super) fn input(primary: &[u8], attachments: &[Vec<u8>]) -> Value {
    let total = primary.len() + attachments.iter().map(Vec::len).sum::<usize>();
    json!({"schema":"guard.private-business-input.v1","version":1,
        "primary_base64":Base64::encode_string(primary),
        "attachments_base64":attachments.iter().map(|s|Base64::encode_string(s)).collect::<Vec<_>>(),
        "facts":{"schema":"guard.business-action.v1","version":1,
            "provider":{"service":"google_gmail","identity_state":"known",
                "account_binding":"a".repeat(64),"tenant_binding":"b".repeat(64),
                "tool_identity_digest":"c".repeat(64),"tool_schema_digest":"d".repeat(64)},
            "operation":"mail_send","audience":{"kind":"named","expansion_state":"known",
                "recipients":[{"identity_binding":"e".repeat(64),"domain":"example.test","kind":"to"}]},
            "content":{"snapshot_digest":business_input_snapshot_digest(primary,attachments).unwrap(),
                "attachment_digests":attachments.iter().map(|s|digest_bytes(s)).collect::<Vec<_>>(),
                "inspection_state":"known","inspected_bytes":total,"sensitivity_labels":["confidential"]},
            "target":{"resource_binding":"1".repeat(64),"revision_binding":"2".repeat(64),
                "field_diff_digest":"3".repeat(64),"batch_manifest_digest":"4".repeat(64)},
            "volume":{"recipient_count":1,"record_count":1,"byte_count":total},"completeness":"known"}})
}

fn receipt(snapshot: &PolicySnapshotV3) -> NativeHookDecisionReceiptV1 {
    serde_json::from_value(json!({"schema":"guard-native-hook-decision-receipt.v1","version":1,
        "authority":"rust","decision_id":"a".repeat(64),"request_id":"business-test",
        "request_digest":"b".repeat(64),"harness":"codex","event_name":"PreToolUse",
        "payload_kind":"inline","policy_generation":snapshot.generation,"policy_digest":snapshot.policy_digest,
        "rule_digest":snapshot.rule_digest,"runtime_identity":snapshot.runtime_identity,
        "decision":"review","model_output_action":"allow","policy_action":"review",
        "observed_policy_action":null,"reason_code":"native_pre_tool_review","workspace_bound":true,
        "source_ref_external_allowed":false,"reviewed_output_sha256":null,"observe_mode":false,
        "deadline_budget_ms":100})).unwrap()
}

pub(super) fn write(root: &Path, path: &Path, value: &Value) {
    let mut file = crate::resident_state::private_file(path, false, root).unwrap();
    file.set_len(0).unwrap();
    file.write_all(&canonical_json_bytes(value).unwrap())
        .unwrap();
}

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) store: super::super::PolicySnapshotStore,
    pub(super) snapshot: PolicySnapshotV3,
    pub(super) key: [u8; 32],
    pub(super) source_document: Option<Value>,
}
impl Fixture {
    pub(super) fn new(label: &str) -> Self {
        Self::with_effect(label, "review")
    }

    /// Installs no business source, so the store keeps an unarmed legacy policy.
    pub(super) fn without_business_policy(label: &str) -> Self {
        let root = super::super::tests::test_root(label);
        let key = super::super::tests::install_test_key(&root, 29);
        let store = super::super::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = super::super::tests::signed_snapshot(1, &key, &root);
        assert!(snapshot.business_policy.is_none());
        store
            .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
            .unwrap();
        for directory in [DIRECTORY, "workspace-review-requests"] {
            crate::resident_state::ensure_private_directory(&root.join(directory), true).unwrap();
        }
        Self {
            root,
            store,
            snapshot,
            key,
            source_document: None,
        }
    }

    pub(super) fn with_effect(label: &str, effect: &str) -> Self {
        let root = super::super::tests::test_root(label);
        Self::from_root(root, &"a".repeat(64), effect)
    }
    pub(super) fn for_core_transport(label: &str, runtime_identity: &str) -> Self {
        let home = super::super::tests::test_root(label);
        let root = home.join("native-runtime");
        crate::resident_state::ensure_private_directory(&root, true).unwrap();
        Self::from_root(root, runtime_identity, "review")
    }
    fn from_root(root: PathBuf, runtime_identity: &str, effect: &str) -> Self {
        let key = super::super::tests::install_test_key(&root, 29);
        let store = super::super::PolicySnapshotStore::new(&root, runtime_identity).unwrap();
        let mut snapshot = super::super::tests::signed_snapshot(1, &key, &root);
        snapshot.runtime_identity = runtime_identity.to_owned();
        snapshot.scope_contract.scope_digest = super::super::scope_digest_for_test(&root);
        let document = json!({"apiVersion":"guard.hashgraphonline.com/v1alpha1","kind":"GuardPolicy",
            "metadata":{"id":"policy.mail.review","name":"Review source fixture","revision":1},
            "spec":{"defaults":{"mode":"enforce","defaultAction":"block"},"rules":[{
                "id":"mail.review","enabled":true,"effect":effect,"match":{"business":{
                    "schema":"guard.business-policy-match.v1","version":1,"services":["google_gmail"],
                    "operations":["mail_send"],"recipientDomains":["example.test"]}},
                "lifetime":{"mode":"until","expiresAt":"2099-01-01T00:00:00Z"},
                "provenance":{"source":"local","createdAt":"2026-07-15T00:00:00Z"}}]}});
        let record = sign_business_source(&document, 1, &key).unwrap();
        let source = verify_business_source(&record, &key).unwrap();
        snapshot.business_policy = Some(source.compiled().binding().clone());
        let marker =
            sign_business_source_anchor(&source, BusinessSourcePhase::Committed, &key).unwrap();
        write(
            &root,
            &root.join("business-source-anchor.v1.json"),
            &serde_json::from_slice(&marker).unwrap(),
        );
        let private_root = crate::resident_state::private_root_for_state_base(&root).unwrap();
        let mut lock = crate::resident_state::private_file(
            &private_root.join("extension-control-authority.lock"),
            false,
            &private_root,
        )
        .unwrap();
        lock.write_all(b"0").unwrap();
        lock.sync_all().unwrap();
        snapshot.policy_digest = policy_digest(&snapshot).unwrap();
        snapshot.integrity.mac = integrity_mac(&snapshot, &key).unwrap();
        store
            .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
            .unwrap();
        for directory in [DIRECTORY, "workspace-review-requests"] {
            crate::resident_state::ensure_private_directory(&root.join(directory), true).unwrap();
        }
        Self {
            root,
            store,
            snapshot,
            key,
            source_document: Some(document),
        }
    }
    fn stage(&self, value: &Value) -> Value {
        let prepared = prepare(value.clone()).unwrap();
        let context = Context {
            schema: "guard.private-business-review.v1".into(),
            version: 1,
            prepared_input_binding: prepared.binding().into(),
            snapshot_digest: digest_bytes(&canonical_json_bytes(value).unwrap()),
        };
        let mut origin = receipt(&self.snapshot);
        origin.business_review_binding =
            Some(origin_binding("business-test", &context, &origin).unwrap());
        super::super::native_review_origin::authenticate(&self.store, &mut origin).unwrap();
        write(&self.root, &self.input_path(value), value);
        let state = json!({"schema":"guard-native-workspace-review-request.v1","version":1,
            "request_id":"business-test","status":"pending","action":{"action_envelope":{
                "native_origin_receipt":origin,"business_context":{"schema":context.schema,"version":context.version,
                    "prepared_input_binding":context.prepared_input_binding,"snapshot_digest":context.snapshot_digest}}},
            "intent":{"harness":"codex"},"revision":{"version":1},"policy":{"policy_action":"review"}});
        self.write_state(&state);
        state
    }
    fn write_state(&self, value: &Value) {
        write(
            &self.root,
            &self
                .root
                .join("workspace-review-requests/business-test.json"),
            value,
        );
    }
    fn input_path(&self, value: &Value) -> PathBuf {
        self.root.join(DIRECTORY).join(format!(
            "{}.json",
            digest_bytes(&canonical_json_bytes(value).unwrap())
        ))
    }
    fn load(
        &self,
    ) -> Result<super::super::workspace_review_request::TrustedWorkspaceReviewRequest, String> {
        super::super::workspace_review_request::load(&self.store, "business-test")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn legacy_decision_rpc_refuses_business_before_claiming_or_retrying() {
    let f = Fixture::new("business-no-legacy-dispatch");
    f.stage(&input(b"body", &[]));
    assert_eq!(
        super::super::workspace_review_decision::verify_and_claim_request(
            &f.store,
            "business-test",
            &json!({}),
        )
        .unwrap_err(),
        "native_workspace_review_business_dispatch_unavailable"
    );
    assert!(f.load().unwrap().business_input.is_some());
}

#[test]
fn missing_noncanonical_or_oversized_private_files_fail_closed() {
    let f = Fixture::new("business-file-boundary");
    let value = input(b"body", &[]);
    f.stage(&value);
    let path = f.input_path(&value);
    std::fs::remove_file(&path).unwrap();
    assert!(f.load().is_err());
    f.stage(&value);
    let mut file = crate::resident_state::private_file(&path, false, &f.root).unwrap();
    file.set_len(0).unwrap();
    file.write_all(&serde_json::to_vec_pretty(&value).unwrap())
        .unwrap();
    assert!(f.load().is_err());
    file.set_len(MAX_PRIVATE_BYTES + 1).unwrap();
    assert!(f.load().is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_private_input_is_rejected() {
    let f = Fixture::new("business-file-symlink");
    let value = input(b"body", &[]);
    f.stage(&value);
    let path = f.input_path(&value);
    let target = f.root.join("synthetic-target.json");
    write(&f.root, &target, &value);
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(f.load().is_err());
}

#[test]
fn authenticated_private_snapshot_owns_all_bytes_without_diagnostic_content() {
    let f = Fixture::new("business-owned");
    let original = input(
        b"private synthetic message",
        &[b"first".to_vec(), b"second".to_vec()],
    );
    f.stage(&original);
    let loaded = f.load().unwrap();
    let prepared = loaded.business_input.as_ref().unwrap();
    assert_eq!(prepared.primary_bytes(), b"private synthetic message");
    assert_eq!(
        prepared.attachments().collect::<Vec<_>>(),
        [b"first".as_slice(), b"second".as_slice()]
    );
    write(&f.root, &f.input_path(&original), &input(b"changed", &[]));
    assert_eq!(prepared.primary_bytes(), b"private synthetic message");
    assert!(f.load().is_err());
    let diagnostic = format!("{loaded:?}");
    assert!(
        !diagnostic.contains("private synthetic")
            && !diagnostic.contains("first")
            && !diagnostic.contains("base64")
    );
}

#[test]
fn changed_account_audience_tool_revision_batch_or_content_invalidates_old_bindings() {
    let f = Fixture::new("business-bindings");
    let value = input(b"body", &[b"alpha".to_vec(), b"bravo".to_vec()]);
    f.stage(&value);
    let original = f.load().unwrap();
    let mut variants = vec![
        input(b"Body", &[b"alpha".to_vec(), b"bravo".to_vec()]),
        input(b"body", &[b"bravo".to_vec(), b"alpha".to_vec()]),
    ];
    for (section, field) in [
        ("provider", "account_binding"),
        ("provider", "tenant_binding"),
        ("provider", "tool_identity_digest"),
        ("provider", "tool_schema_digest"),
        ("target", "resource_binding"),
        ("target", "revision_binding"),
        ("target", "field_diff_digest"),
        ("target", "batch_manifest_digest"),
    ] {
        let mut changed = value.clone();
        changed["facts"][section][field] = json!("9".repeat(64));
        variants.push(changed);
    }
    let mut changed = value.clone();
    changed["facts"]["audience"]["recipients"][0]["kind"] = json!("bcc");
    variants.push(changed);
    let mut changed = value.clone();
    changed["facts"]["content"]["sensitivity_labels"] = json!(["secret"]);
    variants.push(changed);
    let mut changed = value.clone();
    changed["facts"]["volume"]["record_count"] = json!(2);
    variants.push(changed);
    for changed in variants {
        f.stage(&value);
        write(&f.root, &f.input_path(&value), &changed);
        assert!(f.load().is_err());
        f.stage(&changed);
        let current = f.load().unwrap();
        assert_ne!(current.action_binding, original.action_binding);
        assert_ne!(current.retry_scope_binding, original.retry_scope_binding);
    }
}

#[test]
fn missing_null_stripped_or_copied_context_cannot_downgrade_to_generic_review() {
    let f = Fixture::new("business-downgrade");
    let state = f.stage(&input(b"body", &[]));
    for replacement in [json!({"action_envelope":{}}), json!({})] {
        let mut changed = state.clone();
        changed["action"] = replacement;
        f.write_state(&changed);
        assert!(f.load().is_err());
        assert_eq!(
            super::super::workspace_review_decision::verify_and_claim_request(
                &f.store,
                "business-test",
                &json!({}),
            )
            .unwrap_err(),
            "native_workspace_review_business_invalid"
        );
    }
    for field in ["native_origin_receipt", "business_context"] {
        let mut changed = state.clone();
        changed["action"]["action_envelope"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        f.write_state(&changed);
        assert!(f.load().is_err());
        let mut changed = state.clone();
        changed["action"]["action_envelope"][field] = Value::Null;
        f.write_state(&changed);
        assert!(f.load().is_err());
    }
    let mut changed = state.clone();
    changed["action"]["action_envelope"]["native_origin_receipt"]
        .as_object_mut()
        .unwrap()
        .remove("business_review_binding");
    f.write_state(&changed);
    assert!(f.load().is_err());
    let mut copied = state;
    copied["request_id"] = json!("business-copy");
    write(
        &f.root,
        &f.root.join("workspace-review-requests/business-copy.json"),
        &copied,
    );
    assert!(super::super::workspace_review_request::load(&f.store, "business-copy").is_err());
}

#[test]
fn intrinsic_and_business_blocks_cannot_become_human_exceptions() {
    let f = Fixture::new("business-blocks");
    let value = input(b"body", &[]);
    let mut outside = value.clone();
    outside["facts"]["audience"]["recipients"][0]["domain"] = json!("outside.test");
    f.stage(&outside);
    assert_eq!(
        f.load().unwrap_err(),
        "native_workspace_review_business_blocked"
    );
    for action in ["block", "sandbox-required"] {
        let mut state = f.stage(&value);
        let raw = &mut state["action"]["action_envelope"]["native_origin_receipt"];
        let mut origin: NativeHookDecisionReceiptV1 = serde_json::from_value(raw.clone()).unwrap();
        origin.policy_action = Some(action.into());
        super::super::native_review_origin::authenticate(&f.store, &mut origin).unwrap();
        *raw = serde_json::to_value(origin).unwrap();
        f.write_state(&state);
        assert_eq!(
            f.load().unwrap_err(),
            "native_workspace_review_business_blocked"
        );
    }
}

#[test]
fn changed_current_policy_invalidates_authenticated_business_context() {
    let f = Fixture::new("business-policy-change");
    f.stage(&input(b"body", &[]));
    f.load().unwrap();
    let mut next = f.snapshot.clone();
    next.generation += 1;
    next.policy_digest = policy_digest(&next).unwrap();
    next.integrity.mac = integrity_mac(&next, &f.key).unwrap();
    f.store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":next}))
        .unwrap();
    assert_eq!(f.load().unwrap_err(), INVALID);
}

#[test]
fn malformed_base64_counts_unknown_fields_and_limits_are_rejected() {
    let value = input(b"body", &[]);
    for encoded in ["YQ", "YQ==\n", "YR==", "%%%", ""] {
        let mut changed = value.clone();
        changed["primary_base64"] = json!(encoded);
        assert!(prepare(changed).is_err());
    }
    for field in ["provider", "audience", "content", "volume"] {
        let mut changed = value.clone();
        changed["facts"][field]["unrecognized"] = json!(true);
        assert!(prepare(changed).is_err());
    }
    let mut changed = value.clone();
    changed["attachments_base64"] = json!(vec![""; MAX_BUSINESS_ACTION_ITEMS + 1]);
    assert!(prepare(changed).is_err());
    let mut changed = value.clone();
    changed["primary_base64"] =
        json!("A".repeat((MAX_BUSINESS_INLINE_BYTES as usize).div_ceil(3) * 4 + 4));
    assert!(prepare(changed).is_err());
    let large = input(&vec![b'x'; MAX_BUSINESS_INLINE_BYTES as usize], &[]);
    assert!(prepare(large).is_ok());
    let mut changed = value.clone();
    changed["facts"]["volume"]["byte_count"] = json!(0);
    assert!(prepare(changed).is_err());
}

#[test]
fn absent_business_data_preserves_generic_review_and_explicit_null_is_rejected() {
    let f = Fixture::new("business-absent");
    let mut native_origin = receipt(&f.snapshot);
    super::super::native_review_origin::authenticate(&f.store, &mut native_origin).unwrap();
    let state = json!({"schema":"guard-native-workspace-review-request.v1","version":1,"request_id":"business-test",
        "status":"pending","action":{"action_envelope":{"native_origin_receipt":native_origin}},"intent":{},"revision":{},"policy":{}});
    f.write_state(&state);
    assert!(f.load().unwrap().business_input.is_none());
    let mut origin = serde_json::to_value(receipt(&f.snapshot)).unwrap();
    origin["business_review_binding"] = Value::Null;
    assert!(serde_json::from_value::<NativeHookDecisionReceiptV1>(origin).is_err());
}
