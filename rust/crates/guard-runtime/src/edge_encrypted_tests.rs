use super::*;
use crate::edge::tests::{envelope, evaluate_isolated};
use guard_contracts::{GuardHookEdgeResultV2, GuardHookPayloadKindV2};
use serde_json::json;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
const KEY: [u8; 32] = [0; 32];
const NONCE: [u8; 12] = [0; 12];

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) path: PathBuf,
}

impl Fixture {
    pub(super) fn new(bytes: &[u8]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-hook-payload-test-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("payload.json");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        Self { root, path }
    }

    fn encrypted(inner: &Value) -> (Self, Value) {
        let encoded = serde_json::to_string(inner).unwrap();
        Self::encoded(encoded.as_bytes(), encoded.encode_utf16().count(), inner)
    }

    fn encoded(bytes: &[u8], chars: usize, outer: &Value) -> (Self, Value) {
        let mut ciphertext = bytes.to_vec();
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(NONCE),
            Aad::empty(),
            &mut ciphertext,
        )
        .unwrap();
        let fixture = Self::new(&ciphertext);
        let mut payload = json!({"hook_event_name":"PostToolUse", "guard_payload_ref": {
            "version":1, "path": fixture.path, "sha256":hex::encode(Sha256::digest(&ciphertext)),
            "encoding":"json", "encryption":"aes-256-gcm", "key":"A".repeat(43),
            "nonce":"A".repeat(16), "serialized_chars":chars
        }});
        for name in ["tool_name", "config_path", "is_error"] {
            if let Some(value) = outer.get(name) {
                payload[name] = value.clone();
            }
        }
        (fixture, payload)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn inner() -> Value {
    json!({"hook_event_name":"PostToolUse", "tool_name":"Read", "is_error":false,
        "tool_response":"ordinary café 😀"})
}

#[test]
fn decrypts_actual_node_aes_gcm_known_answer_and_js_utf16_length() {
    // Produced by Node createCipheriv('aes-256-gcm'), key 0..31, nonce 32..43,
    // append getAuthTag(), then Buffer.toString('base64url'), matching the generator.
    let key: Vec<u8> = (0..32).collect();
    let encoded_key = crate::approval::approval_v4_crypto::encode_base64url(&key);
    assert_eq!(
        fixed_base64url::<32>(&encoded_key).unwrap().as_slice(),
        key.as_slice()
    );
    let ciphertext = hex::decode(concat!(
        "a918ce1f03f3456b6c192cba9e769594b56bd6bed7ef109a3899037e1cf93b2b59ac916be1496ab475900bb0622b4dad",
        "834ecea2b8555e3eab100d723e9030bbb94abe6ebab591f9e406b655de2e490ebbe456268dd9ed70a038ac0a797df81f",
        "ab74dec950c4bc8e71db8e027160bd89940ddbfaf63850bd"
    )).unwrap();
    let fixture = Fixture::new(&ciphertext);
    let payload = json!({"hook_event_name":"PostToolUse", "tool_name":"Read", "is_error":false,
        "guard_payload_ref":{"version":1,"path":fixture.path,
        "sha256":"23a0a2b48b4dd72e25358802a70db63d6a595e3cd252046b4c768cc5ba5809a9",
        "encoding":"json","encryption":"aes-256-gcm",
        "key":encoded_key,
        "nonce":"ICEiIyQlJicoKSor","serialized_chars":101}});
    let value = hydrate(&payload, None).unwrap();
    assert_eq!(value["tool_response"], "known café 😀");
    assert_eq!(value["hook_event_name"], "PostToolUse");
    assert_eq!(fs::read(&fixture.path).unwrap(), ciphertext);
}

#[test]
fn canonical_fixed_base64url_rejects_aliases_and_wrong_lengths() {
    assert_eq!(fixed_base64url::<32>(&"A".repeat(43)).unwrap(), KEY);
    assert_eq!(fixed_base64url::<12>(&"A".repeat(16)).unwrap(), NONCE);
    for value in [
        "A".repeat(42),
        "A".repeat(44),
        format!("{}=", "A".repeat(43)),
        format!("{}B", "A".repeat(42)),
        format!("{}+", "A".repeat(42)),
    ] {
        assert_eq!(
            fixed_base64url::<32>(&value).unwrap_err(),
            error("key_or_nonce_invalid")
        );
    }
}

#[test]
fn ciphertext_hash_and_authentication_are_independent_gates() {
    let (fixture, payload) = Fixture::encrypted(&inner());
    let mut changed = fs::read(&fixture.path).unwrap();
    changed[0] ^= 1;
    fs::write(&fixture.path, &changed).unwrap();
    assert_eq!(
        hydrate(&payload, None).unwrap_err(),
        error("digest_mismatch")
    );
    let mut rebound = payload;
    rebound["guard_payload_ref"]["sha256"] = json!(hex::encode(Sha256::digest(&changed)));
    assert_eq!(
        hydrate(&rebound, None).unwrap_err(),
        error("authentication_failed")
    );
}

#[test]
fn wrong_key_nonce_and_tag_never_produce_plaintext() {
    for name in ["key", "nonce"] {
        let (_fixture, mut payload) = Fixture::encrypted(&inner());
        let old = payload["guard_payload_ref"][name].as_str().unwrap();
        payload["guard_payload_ref"][name] = json!(format!("B{}", &old[1..]));
        assert_eq!(
            hydrate(&payload, None).unwrap_err(),
            error("authentication_failed")
        );
    }
    let (fixture, mut payload) = Fixture::encrypted(&inner());
    let mut bytes = fs::read(&fixture.path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&fixture.path, &bytes).unwrap();
    payload["guard_payload_ref"]["sha256"] = json!(hex::encode(Sha256::digest(bytes)));
    assert_eq!(
        hydrate(&payload, None).unwrap_err(),
        error("authentication_failed")
    );
}

#[test]
fn reference_schema_types_and_closed_fields_are_checked() {
    let (_fixture, payload) = Fixture::encrypted(&inner());
    for (name, value) in [
        ("version", json!(2)),
        ("version", json!(true)),
        ("encoding", json!("raw")),
        ("encryption", json!("none")),
        ("unexpected", json!(1)),
        ("path", json!(null)),
    ] {
        let mut changed = payload.clone();
        changed["guard_payload_ref"][name] = value;
        assert_eq!(
            hydrate(&changed, None).unwrap_err(),
            error("metadata_invalid")
        );
    }
    for value in [json!(0), json!(-1), json!(MAX_BYTES + 1), json!(1.5)] {
        let mut changed = payload.clone();
        changed["guard_payload_ref"]["serialized_chars"] = value;
        assert_eq!(hydrate(&changed, None).unwrap_err(), error("size_invalid"));
    }
}

#[test]
fn authenticated_json_event_length_and_outer_copies_remain_bound() {
    let (_fixture, payload) = Fixture::encrypted(&inner());
    for name in ["tool_name", "config_path", "is_error"] {
        let mut changed = payload.clone();
        changed[name] = json!("changed");
        assert_eq!(
            hydrate(&changed, None).unwrap_err(),
            error("metadata_mismatch")
        );
    }
    let mut wrong_length = payload;
    wrong_length["guard_payload_ref"]["serialized_chars"] = json!(1);
    assert_eq!(
        hydrate(&wrong_length, None).unwrap_err(),
        error("size_mismatch")
    );
    for (value, expected) in [
        (json!([]), "inner_invalid"),
        (json!({"hook_event_name":"PreToolUse"}), "event_mismatch"),
        (
            json!({"hook_event_name":"PostToolUse","guard_payload_ref":{}}),
            "inner_invalid",
        ),
    ] {
        let (_fixture, wrapped) = Fixture::encrypted(&value);
        assert_eq!(hydrate(&wrapped, None).unwrap_err(), error(expected));
    }
    let (_fixture, invalid) = Fixture::encoded(&[0xff], 1, &json!({}));
    assert_eq!(hydrate(&invalid, None).unwrap_err(), error("json_invalid"));
    let (_fixture, invalid) = Fixture::encoded(b"{", 1, &json!({}));
    assert_eq!(hydrate(&invalid, None).unwrap_err(), error("json_invalid"));
}

#[test]
fn original_expired_deadline_wins_before_reference_access() {
    assert_eq!(
        hydrate(&json!({}), Some(Instant::now() - Duration::from_millis(1))).unwrap_err(),
        "native_request_deadline_exceeded"
    );
}

fn edge_result(
    payload: Value,
    harness: &str,
    cwd: Option<&Path>,
) -> (GuardHookEdgeResultV2, String) {
    let mut request = envelope("PostToolUse", payload);
    request.harness = harness.to_owned();
    request.deadline_budget_ms = Some(1000);
    if let Some(root) = cwd {
        request.source.cwd = Some(root.to_string_lossy().into_owned());
        request.source.home_dir = root.to_string_lossy().into_owned();
    }
    let digest = crate::edge::request_identity(&request).unwrap().1;
    let bytes = evaluate_isolated(request).unwrap();
    (serde_json::from_slice(&bytes).unwrap(), digest)
}

#[test]
fn both_producer_harnesses_scan_inner_output_but_receipt_commits_outer() {
    for harness in ["pi", "omp"] {
        let original = inner();
        let (_fixture, payload) = Fixture::encrypted(&original);
        let (result, digest) = edge_result(payload.clone(), harness, None);
        assert_eq!(result.result["reason_code"], "output_scan_allow");
        assert_eq!(result.receipt.request_digest, digest);
        assert_eq!(
            result.receipt.payload_kind,
            GuardHookPayloadKindV2::EncryptedPayloadRef
        );
        assert_eq!(
            result.receipt.reviewed_output_sha256,
            Some(hex::encode(Sha256::digest(
                original["tool_response"].as_str().unwrap().as_bytes()
            )))
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(payload["guard_payload_ref"]["key"].as_str().unwrap()));
        assert!(!serialized.contains("ordinary café"));
        assert!(!serialized.contains(payload["guard_payload_ref"]["path"].as_str().unwrap()));
    }
}

#[test]
fn source_full_read_tail_secret_and_changed_source_oracles_remain_active() {
    for (filename, contents, replacement, reason) in [
        (
            "source.txt",
            "clean content\n".to_owned(),
            None,
            "no_output_to_review",
        ),
        (
            "source.rs",
            "clean content\n".to_owned(),
            None,
            "source_full_scan_allow",
        ),
        (
            "source.rs",
            format!(
                "{}\n{}{}",
                "ordinary\n".repeat(10_000),
                ["gh", "p_"].concat(),
                "b".repeat(30)
            ),
            None,
            "source_secret_match",
        ),
        (
            "source.rs",
            "clean content\n".to_owned(),
            Some("changed"),
            "no_output_to_review",
        ),
    ] {
        let workspace = Fixture::new(b"placeholder");
        fs::write(
            workspace.root.join(filename),
            replacement.unwrap_or(&contents),
        )
        .unwrap();
        let classified = guard_secure_fs::classify_source_path(
            filename,
            &workspace.root,
            Some(&workspace.root),
            false,
        );
        assert_eq!(classified.allowed, filename == "source.rs");
        assert_eq!(
            classified.reason_code,
            if filename == "source.rs" {
                "source_extension"
            } else {
                "not_source_like"
            }
        );
        let value = json!({"hook_event_name":"PostToolUse","tool_name":"Read","is_error":false,
            "tool_input":{"file_path":filename},"guard_source_ref":{"version":1,"path":filename,
                "output_sha256":hex::encode(Sha256::digest(contents.as_bytes())),"output_chars":contents.chars().count()}});
        let (plain, _) = edge_result(value.clone(), "pi", Some(&workspace.root));
        assert_eq!(plain.result["reason_code"], reason);
        let (_cipher, payload) = Fixture::encrypted(&value);
        let (result, digest) = edge_result(payload, "pi", Some(&workspace.root));
        assert_eq!(result.result, plain.result);
        assert_eq!(result.result["reason_code"], reason);
        assert_eq!(result.receipt.request_digest, digest);
        assert_eq!(
            result.receipt.decision,
            if reason == "source_full_scan_allow" {
                "allow"
            } else {
                "deny"
            }
        );
        assert_eq!(
            result.receipt.payload_kind,
            GuardHookPayloadKindV2::EncryptedPayloadRef
        );
    }
}

#[test]
fn pretool_and_other_harness_references_remain_unsupported() {
    let (_fixture, payload) = Fixture::encrypted(&inner());
    let mut pre = envelope("PreToolUse", payload.clone());
    pre.harness = "pi".to_owned();
    pre.raw_payload["hook_event_name"] = json!("PreToolUse");
    assert_eq!(
        evaluate_isolated(pre).unwrap_err(),
        "native_hook_encrypted_payload_unsupported"
    );
    assert_eq!(
        evaluate_isolated(envelope("PostToolUse", payload)).unwrap_err(),
        "native_hook_encrypted_payload_unsupported"
    );
}

#[test]
fn authenticated_inner_uses_unchanged_policy_join_and_intrinsic_floor() {
    use crate::policy_enforcement::AdmittedPolicySnapshot;
    use guard_policy_snapshot::{
        PolicySnapshotV3, POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_SCHEMA,
    };
    for mode in ["enforce", "observe"] {
        for secret in [false, true] {
            let mut value = inner();
            if secret {
                value["tool_response"] =
                    json!(format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30)));
            }
            let (_fixture, wrapped) = Fixture::encrypted(&value);
            let snapshot:PolicySnapshotV3=serde_json::from_value(json!({
                "schema":POLICY_SNAPSHOT_SCHEMA,"version":3,"generation":1,
                "policy_digest":"a".repeat(64),"config_digest":"b".repeat(64),
                "rule_digest":guard_rule_contract::rule_digest(),"runtime_identity":"d".repeat(64),
                "protocol_version":1,"mode":mode,
                "scope_contract":{"schema":"guard-native-scope.v1","kind":"guard-home",
                    "scope_digest":"e".repeat(64),"workspace_binding":"request-source"},
                "effective_policy":{"protection_posture":"protected","security_level":"balanced",
                    "default_action":"block","unknown_publisher_action":"review",
                    "changed_hash_action":"require-reapproval","new_network_domain_action":"allow",
                    "subprocess_action":"allow","risk_actions":{},"harness_risk_actions":{},
                    "harness_actions":{},"publisher_actions":{},"artifact_actions":{},
                    "sandbox_analysis":"off","receipt_redaction_level":"full"},
                "command_extensions":null,"issued_at_ms":1,"expires_at_ms":2,
                "integrity":{"algorithm":POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,"key_id":"f".repeat(64),"mac":"0".repeat(64)}
            })).unwrap();
            // This existing constructor compiles an already-admitted test snapshot;
            // this control does not claim a signed publisher/install exchange.
            let admitted = AdmittedPolicySnapshot::new(snapshot).unwrap();
            let evaluate = |payload| {
                let mut request = envelope("PostToolUse", payload);
                request.harness = "pi".to_owned();
                request.deadline_budget_ms = Some(1000);
                let home = request.source.guard_home.clone();
                let digest = crate::edge::request_identity(&request).unwrap().1;
                let validated =
                    crate::edge::validate_envelope_shape(request, Instant::now()).unwrap();
                let result = crate::edge::evaluate_validated_envelope(validated, Some(&admitted));
                fs::remove_dir_all(home).unwrap();
                let result: GuardHookEdgeResultV2 =
                    serde_json::from_slice(&result.unwrap()).unwrap();
                assert_eq!(result.receipt.request_digest, digest);
                result
            };
            let plain = evaluate(value);
            let encrypted = evaluate(wrapped);
            assert_eq!(encrypted.result, plain.result);
            assert_eq!(encrypted.receipt.policy_action, plain.receipt.policy_action);
            assert_eq!(
                encrypted.receipt.payload_kind,
                GuardHookPayloadKindV2::EncryptedPayloadRef
            );
            assert_eq!(
                encrypted.receipt.decision,
                if secret || mode == "enforce" {
                    "deny"
                } else {
                    "allow"
                }
            );
        }
    }
}
