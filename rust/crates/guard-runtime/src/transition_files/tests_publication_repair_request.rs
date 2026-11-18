use serde_json::{json, Value};

use super::dispatch;
use super::tests_publication_repair_plan::Home;

fn ask(home: &Home, kind: &str, payload: Value) -> Result<Value, String> {
    dispatch(&json!({
        "op": "publication_repair_request_plan",
        "home": home.guard().to_string_lossy(),
        "kind": kind,
        "payload": payload,
        "guard_home": home.guard().to_string_lossy(),
        "config_path": home.config().to_string_lossy(),
    }))
    .map_err(|error| format!("{error:?}"))
    .and_then(|answer| match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    })
}

fn native() -> Value {
    json!({"path": "/runtime", "size": 1, "mtime_ns": 2, "sha256": "ab"})
}

fn repair_payload(home: &Home) -> Value {
    json!({
        "schema": "hol-guard.codex-authority-repair-plan.v1",
        "action": "apps.repair.codex-authority",
        "guard_home": home.guard().to_string_lossy(),
        "config_path": home.config().to_string_lossy(),
        "operation_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
        "files": home.files(),
        "native_runtime": native(),
        "verification_workspace": "/workspace",
    })
}

fn refused(home: &Home, kind: &str, payload: Value, code: &str) {
    let error = ask(home, kind, payload).unwrap_err();
    assert!(error.contains(code), "{code}: {error}");
}

#[test]
fn a_payload_with_another_key_set_is_refused() {
    let home = Home::new();
    let mut payload = repair_payload(&home);
    payload["extra"] = json!(1);
    refused(
        &home,
        "repair",
        payload,
        "authority_repair_request_plan_invalid",
    );
    let mut payload = repair_payload(&home);
    payload.as_object_mut().unwrap().remove("files");
    refused(
        &home,
        "repair",
        payload,
        "authority_repair_request_plan_invalid",
    );
    refused(
        &home,
        "repair",
        json!([]),
        "authority_repair_request_plan_invalid",
    );
}

#[test]
fn a_payload_for_another_context_is_refused() {
    let home = Home::new();
    for (key, value) in [
        ("schema", json!("other")),
        ("action", json!("other")),
        ("guard_home", json!("/elsewhere")),
        ("config_path", json!("/elsewhere/config.toml")),
        ("operation_id", json!(7)),
        ("verification_workspace", json!(null)),
    ] {
        let mut payload = repair_payload(&home);
        payload[key] = value;
        refused(
            &home,
            "repair",
            payload,
            "authority_repair_request_context_invalid",
        );
    }
}

#[test]
fn a_runtime_that_is_not_exactly_a_path_size_mtime_and_digest_is_refused() {
    let home = Home::new();
    for runtime in [
        json!(null),
        json!({"path": "/runtime", "size": 1, "mtime_ns": 2}),
        json!({"path": "/runtime", "size": 1.5, "mtime_ns": 2, "sha256": "ab"}),
        json!({"path": "/runtime", "size": 1, "mtime_ns": 2, "sha256": "ab", "x": 1}),
        json!({"path": 3, "size": 1, "mtime_ns": 2, "sha256": "ab"}),
    ] {
        let mut payload = repair_payload(&home);
        payload["native_runtime"] = runtime;
        refused(
            &home,
            "repair",
            payload,
            "authority_repair_request_plan_invalid",
        );
    }
}

#[test]
fn a_file_set_that_is_empty_or_has_no_single_manifest_change_is_refused() {
    let home = Home::new();
    let mut payload = repair_payload(&home);
    payload["files"] = json!([]);
    refused(&home, "repair", payload, "files_invalid");
    let mut payload = repair_payload(&home);
    payload["files"] = json!(["not an object"]);
    refused(&home, "repair", payload, "files_invalid");
    let mut payload = repair_payload(&home);
    payload["files"].as_array_mut().unwrap().remove(0);
    assert!(
        ask(&home, "repair", payload).is_err(),
        "a plan without its manifest change is refused"
    );
}

#[test]
fn a_payload_the_runtime_would_not_derive_is_refused() {
    let home = Home::new();
    let mut payload = repair_payload(&home);
    payload["operation_id"] = json!("not-a-canonical-uuid");
    refused(&home, "repair", payload, "authority_repair_plan_invalid");
}

#[test]
fn an_inverse_binding_needs_its_runtime_operation_and_workspace() {
    let home = Home::new();
    let good = json!({
        "native_runtime": native(),
        "operation_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
        "verification_workspace": "/workspace",
    });
    assert_eq!(ask(&home, "inverse", good.clone()).unwrap(), json!(null));
    for (key, value) in [
        ("native_runtime", json!({"path": "/runtime"})),
        ("operation_id", json!(1)),
        ("verification_workspace", json!(null)),
    ] {
        let mut payload = good.clone();
        payload[key] = value;
        refused(
            &home,
            "inverse",
            payload,
            "authority_repair_request_plan_invalid",
        );
    }
    refused(
        &home,
        "inverse",
        json!("text"),
        "authority_repair_request_plan_invalid",
    );
}

#[test]
fn an_unknown_kind_is_refused() {
    let home = Home::new();
    refused(&home, "other", json!({}), "files_invalid");
}

#[test]
fn a_file_that_would_not_read_back_as_reviewed_is_not_normalized() {
    use super::publication_repair_request::normalized;

    let home = Home::new();
    let good = home.change();
    assert!(normalized(&good));
    let outside = format!("{}/../manifest", home.guard().display());
    for (key, value) in [
        ("no_follow", json!(null)),
        ("expected_digest", json!(null)),
        // `e31=` decodes to `{}` but is not how `{}` is written (`e30=`).
        ("after", json!("e31=")),
        ("path", json!("relative/file")),
        ("path", json!(outside)),
    ] {
        let mut file = good.clone();
        file[key] = value;
        assert!(!normalized(&file), "{file}");
    }
    let mut without = good.clone();
    without.as_object_mut().unwrap().remove("no_follow");
    assert!(!normalized(&without));
    // Bytes that do not decode are the caller's snapshot refusal.
    let mut undecodable = good;
    undecodable["after"] = json!("not base64!");
    assert!(normalized(&undecodable));
}

#[test]
fn an_inverse_request_must_match_the_plan_rebuilt_from_the_journal() {
    let home = Home::new();
    let payload = json!({"operation_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427", "n": 1});
    let ask_bound = |bound: Option<Value>| {
        let mut request = json!({
            "op": "publication_repair_request_plan",
            "home": home.guard().to_string_lossy(),
            "kind": "inverse_bound",
            "payload": payload,
        });
        if let Some(bound) = bound {
            request["bound"] = bound;
        }
        dispatch(&request).unwrap()
    };
    assert_eq!(ask_bound(Some(payload.clone()))["value"], json!(null));
    let mut spelled_as_float = payload.clone();
    spelled_as_float["n"] = json!(1.0);
    assert_eq!(ask_bound(Some(spelled_as_float))["value"], json!(null));
    for bound in [None, Some(json!({"operation_id": "other"}))] {
        let answer = ask_bound(bound);
        assert!(
            answer["error"]
                .to_string()
                .contains("authority_repair_request_plan_invalid"),
            "{answer}"
        );
    }
}

#[test]
fn an_inverse_binding_names_its_operation_as_a_canonical_uuid() {
    let home = Home::new();
    for operation in ["not-a-uuid", "1B4E28BA-2FA1-41D2-883F-0016D3CCA427"] {
        let payload = json!({
            "native_runtime": native(),
            "operation_id": operation,
            "verification_workspace": "/workspace",
        });
        refused(
            &home,
            "inverse",
            payload,
            "authority_repair_request_plan_invalid",
        );
    }
}
