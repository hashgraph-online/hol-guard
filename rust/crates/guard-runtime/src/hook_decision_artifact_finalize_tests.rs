//! Parity vectors recorded from the retired Python final-action settle
//! (`set_native_artifact_hook_final_action` and the browser outcome section of
//! `finalize_native_artifact_hook`, frozen in
//! `scripts/ci/artifact_finalize_oracle.py`), replayed through the
//! resident `hook_decide` operation.

use guard_contracts::{HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE, HOOK_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/artifact_finalize_vectors.json.gz");
const CANONICAL: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

fn reply_bytes(kind: &str, inputs: &Value) -> Option<Vec<u8>> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-artifact-finalize",
            "query": {"kind": kind, "inputs": inputs},
        }
    });
    crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None).ok()
}

/// The answer's payload and the exact text the resident wrote it as.
fn answer(kind: &str, inputs: &Value) -> (Value, String) {
    let bytes = reply_bytes(kind, inputs).expect("hook decision op should answer");
    let reply: Value = serde_json::from_slice(&bytes).expect("reply should be JSON");
    assert_eq!(reply["status"], "ok", "{reply}");
    let text = String::from_utf8(bytes).expect("reply should be text");
    (reply["payload"].clone(), text)
}

fn rejected(kind: &str, inputs: &Value) -> bool {
    match reply_bytes(kind, inputs) {
        None => true,
        Some(bytes) => {
            serde_json::from_slice::<Value>(&bytes).map_or(true, |reply| reply["status"] == "error")
        }
    }
}

/// A browser resolution as the hook would ask for it, unless overridden.
fn browser_facts(policy_action: &str, request: Value, queued: Value) -> Value {
    json!({
        "previous_action": "review",
        "policy_action": policy_action,
        "observed_policy_action": null,
        "approval_source": "browser",
        "approval_request_id": request,
        "queued_request_id": queued,
        "initial_policy_action": "review",
        "receipt_approval_source": null,
        "receipt_approval_request_id": null,
        "receipt_user_override": null,
        "package_review_cloud_reason_code": null,
        "supply_chain_present": false,
        "supply_chain_action": null,
    })
}

#[test]
fn matches_python_settle_vectors() {
    let vectors = gunzip_json(VECTORS);
    let settle = vectors["settle"].as_array().unwrap();
    assert!(settle.len() > 3_000);
    for vector in settle {
        let facts = &vector["facts"];
        let (payload, text) = answer("artifact_finalize", facts);
        assert_eq!(payload["kind"], "artifact_finalize", "{facts}");
        let expected = vector["answer"].as_object().unwrap();
        for (key, value) in expected {
            assert_eq!(&payload[key], value, "{facts}: {key}");
        }
        assert_eq!(
            payload.as_object().unwrap().len(),
            expected.len() + 1,
            "{facts}: the answer carries only what the recording exhibited"
        );
        // The persisted receipt: the fields the vector pins, exactly.
        for key in [
            "policy_decision",
            "approval_source",
            "approval_request_id",
            "user_override",
        ] {
            assert_eq!(
                payload["receipt"][key], vector["receipt"][key],
                "{facts}: receipt {key}"
            );
        }
        // Key order is persisted bytes: the two objects the transport writes
        // into the evidence keep the order the Python settle wrote them in.
        let fields = vector["wire"]["fields"].as_str().unwrap();
        assert!(text.contains(&format!("\"fields\":{fields}")), "{facts}");
        let appended = match vector["wire"]["resolution"].as_str() {
            Some(entry) => format!("\"appended_evidence\":[{entry}]"),
            None => "\"appended_evidence\":[]".to_owned(),
        };
        assert!(text.contains(&appended), "{facts}");
    }
}

#[test]
fn matches_python_browser_outcome_vectors() {
    let vectors = gunzip_json(VECTORS);
    let browser = vectors["browser"].as_array().unwrap();
    assert!(browser.len() > 60);
    for vector in browser {
        let facts = &vector["facts"];
        let (payload, _) = answer("artifact_browser_outcome", facts);
        assert_eq!(payload["kind"], "artifact_browser_outcome", "{facts}");
        let expected = vector["answer"].as_object().unwrap();
        for (key, value) in expected {
            assert_eq!(&payload[key], value, "{facts}: {key}");
        }
        assert_eq!(
            payload.as_object().unwrap().len(),
            expected.len() + 1,
            "{facts}"
        );
    }
}

/// A browser outcome settles the hook only as the user's approval or a
/// terminal verdict. Anything else leaves the review where it was, still
/// offered as Allow once and Always allow.
#[test]
fn only_an_approval_or_a_terminal_verdict_settles_the_hook() {
    let vectors = gunzip_json(VECTORS);
    let mut settled = 0_usize;
    for vector in vectors["browser"].as_array().unwrap() {
        let facts = &vector["facts"];
        let (payload, _) = answer("artifact_browser_outcome", facts);
        let decision = facts["decision"].as_str().unwrap();
        let event = facts["event"].as_str().unwrap();
        if !matches!(decision, "allow" | "block" | "sandbox-required") {
            assert_eq!(payload["settle"], false, "{facts}");
            assert!(payload["action"].is_null(), "{facts}");
            assert!(payload["approval_source"].is_null(), "{facts}");
            assert_eq!(payload["emit_native_allow"], false, "{facts}");
            assert_eq!(payload["finish_without_render"], false, "{facts}");
            continue;
        }
        settled += 1;
        assert_eq!(payload["settle"], true, "{facts}");
        assert_eq!(payload["action"], decision, "{facts}");
        assert_eq!(payload["approval_source"], "browser", "{facts}");
        // Only an approval ends the hook; a terminal verdict is rendered.
        assert_eq!(
            payload["finish_without_render"],
            decision == "allow",
            "{facts}"
        );
        assert_eq!(
            payload["emit_native_allow"],
            decision == "allow" && event != "PreToolUse",
            "{facts}"
        );
    }
    assert!(settled > 20);
}

/// A settle never makes the hook more permissive than the action it was
/// given: an action the lattice does not know settles as `block`, the legacy
/// `ask` as `review`, and only a browser resolution records a user override.
#[test]
fn a_settle_never_loosens_the_action_it_was_given() {
    let vectors = gunzip_json(VECTORS);
    for vector in vectors["settle"].as_array().unwrap() {
        let facts = &vector["facts"];
        let (payload, _) = answer("artifact_finalize", facts);
        let given = facts["policy_action"].as_str().unwrap();
        let settled = payload["action"].as_str().unwrap();
        match given {
            "ask" => assert_eq!(settled, "review", "{facts}"),
            other if CANONICAL.contains(&other) => assert_eq!(settled, other, "{facts}"),
            _ => assert_eq!(settled, "block", "{facts}"),
        }
        assert_eq!(
            payload["receipt"]["policy_decision"], payload["action"],
            "{facts}"
        );
        let browser = facts["approval_source"] == "browser";
        assert_eq!(
            payload["receipt"]["user_override"] == "browser-approval",
            browser,
            "{facts}"
        );
        assert_eq!(
            !payload["receipt"]["appended_evidence"]
                .as_array()
                .unwrap()
                .is_empty(),
            browser,
            "{facts}"
        );
        assert_eq!(
            payload["decision_reason"],
            if browser { "browser-approval" } else { settled },
            "{facts}"
        );
    }
}

#[test]
fn a_terminal_browser_outcome_falls_back_to_the_first_queued_request() {
    let (block, _) = answer(
        "artifact_finalize",
        &browser_facts("block", Value::Null, json!("queued-1")),
    );
    assert_eq!(block["receipt"]["approval_request_id"], "queued-1");
    assert_eq!(
        block["receipt"]["appended_evidence"][0]["approval_request_id"],
        "queued-1"
    );
    let (resolved, _) = answer(
        "artifact_finalize",
        &browser_facts("sandbox-required", json!("req-1"), json!("queued-1")),
    );
    assert_eq!(resolved["receipt"]["approval_request_id"], "req-1");
    // An approval answers the request that was resolved, not a queued one.
    let (allow, _) = answer(
        "artifact_finalize",
        &browser_facts("allow", Value::Null, json!("queued-1")),
    );
    assert!(allow["receipt"]["approval_request_id"].is_null());
    assert!(allow["receipt"]["appended_evidence"][0]["approval_request_id"].is_null());
}

#[test]
fn an_empty_request_id_keeps_the_receipts_own() {
    let mut facts = browser_facts("allow", json!(""), Value::Null);
    facts["receipt_approval_request_id"] = json!("prior-1");
    facts["receipt_approval_source"] = json!("cli");
    let (payload, _) = answer("artifact_finalize", &facts);
    assert_eq!(payload["receipt"]["approval_request_id"], "prior-1");
    assert_eq!(payload["receipt"]["approval_source"], "browser");
    // The evidence records the resolution's own, empty id.
    assert_eq!(
        payload["receipt"]["appended_evidence"][0]["approval_request_id"],
        ""
    );
}

#[test]
fn only_the_cloud_failures_survive_the_new_decision() {
    for (code, kept) in [
        ("cloud_auth_error", true),
        ("cloud_http_error", true),
        ("cloud_timeout", true),
        ("cloud_validation_error", true),
        ("cloud_unrelated", false),
        ("", false),
    ] {
        let mut facts = browser_facts("allow", Value::Null, Value::Null);
        facts["package_review_cloud_reason_code"] = json!(code);
        let (payload, _) = answer("artifact_finalize", &facts);
        if kept {
            assert_eq!(payload["cloud_reason_code"], code);
        } else {
            assert!(payload["cloud_reason_code"].is_null(), "{code}");
        }
    }
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE));
}

#[test]
fn malformed_inputs_fail_closed() {
    let facts = browser_facts("allow", Value::Null, Value::Null);
    let mut extra = facts.clone();
    extra["review_hint_present"] = json!(true);
    assert!(rejected("artifact_finalize", &extra));
    let mut missing = facts.clone();
    missing.as_object_mut().unwrap().remove("policy_action");
    assert!(rejected("artifact_finalize", &missing));
    let mut not_text = facts;
    not_text["policy_action"] = json!(5);
    assert!(rejected("artifact_finalize", &not_text));

    let outcome = json!({"decision": "allow", "event": "PreToolUse"});
    assert!(!rejected("artifact_browser_outcome", &outcome));
    let mut extra = outcome.clone();
    extra["request_id"] = json!("req-1");
    assert!(rejected("artifact_browser_outcome", &extra));
    let mut missing = outcome;
    missing.as_object_mut().unwrap().remove("decision");
    assert!(rejected("artifact_browser_outcome", &missing));
}
