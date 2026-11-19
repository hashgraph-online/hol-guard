use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::super::publication::Call;
use super::super::publication_commit::dispatch;
use super::super::publication_observe_check::{
    canonical_uuid, digest, modern_receipt, protects, strings, OBSERVATION_SCHEMA,
};
use super::super::publication_observe_legacy::{expired_after, Legacy};
use super::super::{Budget, Fault};
use crate::guard_store_db::StoreError;
use crate::hook_process_spawn::desktop_hook_proxy_context;
use crate::native_decision_receipt::sealed_decision_id;
use crate::pyjson::PyVal;

const OPERATION: &str = "0b6f5c1e-2c1f-4f2e-8f43-0a3d2f5b7c11";
const REQUEST: &str = "transition-hook-0123456789abcdef0123456789abcdef";
const RUNTIME: &str = "b";

fn receipt(request_id: &str, decision: &str, action: &str) -> Value {
    let mut receipt = json!({
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "",
        "request_id": request_id,
        "request_digest": if decision == "allow" { "a" } else { "b" }.repeat(64),
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": "b".repeat(64),
        "rule_digest": null,
        "runtime_identity": RUNTIME.repeat(64),
        "decision": decision,
        "model_output_action": "allow_original",
        "policy_action": action,
        "observed_policy_action": null,
        "reason_code": "policy_decision",
        "workspace_bound": false,
        "source_ref_external_allowed": false,
        "reviewed_output_sha256": null,
        "observe_mode": false,
        "deadline_budget_ms": null,
    });
    seal(&mut receipt);
    receipt
}

fn seal(receipt: &mut Value) {
    let parsed = crate::pyjson::parse(&receipt.to_string()).unwrap();
    receipt["decision_id"] = Value::from(sealed_decision_id(&parsed));
}

fn observation(receipt: &Value) -> Value {
    json!({
        "schema": OBSERVATION_SCHEMA,
        "operation_id": OPERATION,
        "request_id": REQUEST,
        "native_receipt": receipt,
    })
}

fn stderr_of(observation: &Value) -> String {
    format!("phase: resident\n  {observation}  \nphase: done\n")
}

#[test]
fn the_observation_line_among_diagnostics_yields_its_receipt() {
    let allowed = receipt(REQUEST, "allow", "allow");
    let found = modern_receipt(&stderr_of(&observation(&allowed)), OPERATION, REQUEST);
    assert_eq!(found, Some(allowed));
    for stderr in ["", "phase: only\n", "{\"schema\":\"other\"}\n"] {
        assert_eq!(modern_receipt(stderr, OPERATION, REQUEST), None);
    }
}

#[test]
fn an_observation_the_probe_does_not_name_proves_nothing() {
    let allowed = receipt(REQUEST, "allow", "allow");
    let line = |observation: &Value| stderr_of(observation);
    let stderr = line(&observation(&allowed));
    assert_eq!(modern_receipt(&stderr, "other", REQUEST), None);
    assert_eq!(
        modern_receipt(&stderr, OPERATION, "transition-hook-x"),
        None
    );
    let mut extra = observation(&allowed);
    extra["extra"] = json!(1);
    assert_eq!(modern_receipt(&line(&extra), OPERATION, REQUEST), None);
    let mut tampered = allowed.clone();
    tampered["decision"] = json!("deny");
    assert_eq!(
        modern_receipt(&line(&observation(&tampered)), OPERATION, REQUEST),
        None
    );
    let mut observing = allowed.clone();
    observing["observe_mode"] = json!(true);
    seal(&mut observing);
    assert_eq!(
        modern_receipt(&line(&observation(&observing)), OPERATION, REQUEST),
        None
    );
    for (field, value) in [
        ("harness", "claude-code"),
        ("payload_kind", "source_file_ref"),
        ("event_name", "PostToolUse"),
    ] {
        let mut other = allowed.clone();
        other[field] = json!(value);
        seal(&mut other);
        assert_eq!(
            modern_receipt(&line(&observation(&other)), OPERATION, REQUEST),
            None,
            "{field}"
        );
    }
    let mut other_request = receipt("transition-hook-other", "allow", "allow");
    seal(&mut other_request);
    assert_eq!(
        modern_receipt(&line(&observation(&other_request)), OPERATION, REQUEST),
        None
    );
}

#[test]
fn a_hook_must_show_the_expected_decision_in_output_and_receipt() {
    let allowed = receipt(REQUEST, "allow", "allow");
    let denied = receipt(REQUEST, "deny", "block");
    let runtime = RUNTIME.repeat(64);
    let plain = json!({});
    let allow_output = json!({"hookSpecificOutput": {"permissionDecision": "allow"}});
    let deny_output = json!({"hookSpecificOutput": {"permissionDecision": "deny"}});
    assert!(protects(&allowed, &plain, "allow", &runtime));
    assert!(protects(&allowed, &allow_output, "allow", &runtime));
    assert!(protects(
        &allowed,
        &json!({"hookSpecificOutput": null}),
        "allow",
        &runtime
    ));
    assert!(protects(&denied, &deny_output, "deny", &runtime));
    assert!(!protects(
        &allowed,
        &json!({"continue": false}),
        "allow",
        &runtime
    ));
    assert!(!protects(&allowed, &deny_output, "allow", &runtime));
    assert!(!protects(
        &allowed,
        &json!({"hookSpecificOutput": {"permissionDecision": 1}}),
        "allow",
        &runtime
    ));
    assert!(!protects(&denied, &plain, "deny", &runtime));
    assert!(!protects(&denied, &allow_output, "deny", &runtime));
    assert!(!protects(&allowed, &plain, "deny", &runtime));
    assert!(!protects(&allowed, &plain, "allow", &"c".repeat(64)));
    let mut warned = allowed.clone();
    warned["policy_action"] = json!("warn");
    assert!(protects(&warned, &plain, "allow", &runtime));
    warned["policy_action"] = json!("block");
    assert!(!protects(&warned, &plain, "allow", &runtime));
}

#[test]
fn evidence_digests_are_the_canonical_compact_json() {
    let value = PyVal::Dict(vec![
        ("b".to_owned(), PyVal::Str("2".to_owned())),
        (
            "a".to_owned(),
            PyVal::List(vec![PyVal::Str("x".to_owned()), PyVal::Int("1".to_owned())]),
        ),
    ]);
    assert_eq!(
        digest(&value),
        "155115a046209a1126ab0088c902566193c3d5fff3c8d3aed8a3855951e9c9ed"
    );
    assert_eq!(
        digest(&strings(&["a".to_owned(), "b".to_owned()])),
        "0473ef2dc0d324ab659d3580c1134e9d812035905c4781fdd6d529b0c6860e13"
    );
}

#[test]
fn only_the_canonical_uuid_spelling_is_an_operation_identity() {
    assert!(canonical_uuid(OPERATION));
    assert!(!canonical_uuid(&OPERATION.to_uppercase()));
    assert!(!canonical_uuid(&OPERATION.replace('-', "")));
    assert!(!canonical_uuid("not-a-uuid"));
    assert!(!canonical_uuid(&format!("{OPERATION}0")));
}

fn fault(answer: &Value) -> Value {
    answer["error"].clone()
}

fn ask(home: &std::path::Path, extra: Value) -> Value {
    let mut args = json!({
        "op": "publication_observe",
        "home": home.to_str().unwrap(),
        "config": home.join("config.toml").to_str().unwrap(),
        "windows": false,
        "long_paths": {},
        "operation_id": OPERATION,
        "artifact_generation": "generation",
        "runtime_sha256": RUNTIME.repeat(64),
        "owned": true,
        "workspace": home.to_str().unwrap(),
        "environ": {},
        "deadline_ms": 60_000,
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    dispatch(
        "publication_observe",
        args.as_object().unwrap(),
        &Budget::none(),
    )
    .unwrap()
}

#[test]
fn an_observation_refuses_before_it_launches_anything() {
    let home = tempfile::tempdir().unwrap();
    let transition = |reason: &str| json!({ "transition": reason });
    assert_eq!(
        fault(&ask(home.path(), json!({"deadline_ms": 0}))),
        transition("admission_deadline_expired")
    );
    assert_eq!(
        fault(&ask(
            home.path(),
            json!({"operation_id": OPERATION.to_uppercase()})
        )),
        transition("admission_identity_invalid")
    );
    assert_eq!(
        fault(&ask(home.path(), json!({"artifact_generation": ""}))),
        transition("admission_identity_invalid")
    );
    let unowned = fault(&ask(home.path(), json!({"owned": false})));
    assert_eq!(unowned["integrity"], "codex_hook_transaction_owner_missing");
    // No config or manifest: there is no authority to observe.
    assert_eq!(
        fault(&ask(home.path(), json!({}))),
        transition("admission_hook_authority_missing")
    );
}

fn legacy_call<'a>(args: &'a Map<String, Value>, budget: &'a Budget) -> Call<'a> {
    Call {
        args,
        budget,
        events: Vec::new(),
    }
}

fn legacy_args(home: &std::path::Path, store_home: &std::path::Path) -> Map<String, Value> {
    json!({
        "legacy_store": {
            "home": store_home.to_str().unwrap(),
            "path": home.join("guard.db").to_str().unwrap(),
            "source": "guard",
        }
    })
    .as_object()
    .unwrap()
    .clone()
}

/// A temporary directory is not private by default; a key's home must be.
fn private_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    home
}

fn reason(fault: Fault) -> String {
    match fault {
        Fault::Transition(reason) => reason.to_owned(),
        other => format!("{other:?}"),
    }
}

#[test]
fn a_legacy_observation_needs_its_store_and_one_stable_key() {
    let budget = Budget::none();
    let deadline = Instant::now() + Duration::from_secs(30);
    let home = private_home();
    let other = tempfile::tempdir().unwrap();
    let missing = Map::new();
    let error = Legacy::open(&legacy_call(&missing, &budget), home.path(), deadline)
        .err()
        .unwrap();
    assert_eq!(reason(error), "legacy_probe_store_unavailable");
    let foreign = legacy_args(home.path(), other.path());
    let error = Legacy::open(&legacy_call(&foreign, &budget), home.path(), deadline)
        .err()
        .unwrap();
    assert_eq!(reason(error), "legacy_probe_store_unavailable");
    let args = legacy_args(home.path(), home.path());
    let error = Legacy::open(&legacy_call(&args, &budget), home.path(), deadline)
        .err()
        .unwrap();
    assert_eq!(reason(error), "legacy_probe_correlation_unavailable");

    crate::hook_evidence_correlation::load_or_create_correlation_key(home.path()).unwrap();
    let legacy = Legacy::open(&legacy_call(&args, &budget), home.path(), deadline).unwrap();
    legacy.recheck().unwrap();
    std::fs::remove_file(
        home.path()
            .join(crate::hook_evidence_correlation::CORRELATION_KEY_FILE),
    )
    .unwrap();
    assert_eq!(
        reason(legacy.recheck().unwrap_err()),
        "legacy_probe_correlation_changed"
    );
    crate::hook_evidence_correlation::load_or_create_correlation_key(home.path()).unwrap();
    assert_eq!(
        reason(legacy.recheck().unwrap_err()),
        "legacy_probe_correlation_changed"
    );
    let late = Legacy::open(&legacy_call(&args, &budget), home.path(), Instant::now())
        .err()
        .unwrap();
    assert_eq!(reason(late), "admission_deadline_expired");
}

#[cfg(unix)]
#[test]
fn a_legacy_observation_refuses_a_key_that_is_unsafe_or_malformed() {
    use std::os::unix::fs::PermissionsExt;

    let budget = Budget::none();
    let deadline = Instant::now() + Duration::from_secs(30);
    let home = private_home();
    let args = legacy_args(home.path(), home.path());
    let key = home
        .path()
        .join(crate::hook_evidence_correlation::CORRELATION_KEY_FILE);
    crate::hook_evidence_correlation::load_or_create_correlation_key(home.path()).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = Legacy::open(&legacy_call(&args, &budget), home.path(), deadline)
        .err()
        .unwrap();
    assert_eq!(reason(error), "legacy_probe_correlation_unavailable");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::write(&key, r#"{"invalid":"fixture"}"#).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = Legacy::open(&legacy_call(&args, &budget), home.path(), deadline)
        .err()
        .unwrap();
    assert_eq!(reason(error), "legacy_probe_correlation_invalid");
}

#[test]
fn a_store_failure_is_named_by_what_the_caller_can_do_about_it() {
    let future = Instant::now() + Duration::from_secs(30);
    let value = |message: &str| Err(Some(StoreError::Value(message.to_owned())));
    assert!(matches!(
        expired_after(future, Ok((Value::Null, None))),
        Ok(None)
    ));
    assert_eq!(
        expired_after(future, Ok((json!({"a": 1}), None))).unwrap(),
        Some(json!({"a": 1}))
    );
    for known in [
        "legacy_probe_receipt_ambiguous",
        "legacy_probe_receipt_capacity",
        "legacy_probe_receipt_invalid",
        "legacy_probe_identity_invalid",
        "admission_deadline_expired",
    ] {
        assert_eq!(
            reason(expired_after(future, value(known)).unwrap_err()),
            known
        );
    }
    assert_eq!(
        reason(expired_after(future, value("anything else")).unwrap_err()),
        "admission_protection_failed"
    );
    assert_eq!(
        reason(expired_after(future, Err(None)).unwrap_err()),
        "legacy_probe_storage_unavailable"
    );
    assert_eq!(
        reason(expired_after(future, Err(Some(StoreError::Invalid("x")))).unwrap_err()),
        "legacy_probe_storage_unavailable"
    );
    let past = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        reason(expired_after(past, Err(None)).unwrap_err()),
        "admission_deadline_expired"
    );
    assert_eq!(
        reason(expired_after(past, Ok((Value::Null, None))).unwrap_err()),
        "admission_deadline_expired"
    );
}

#[test]
fn the_desktop_proxy_crosses_into_the_hook_only_when_explicit_and_absolute() {
    const PROXY: &str = "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard";
    let source = |desktop: Option<&str>, proxy: &str| {
        let mut source = BTreeMap::new();
        if let Some(desktop) = desktop {
            source.insert("HOL_GUARD_DESKTOP".to_owned(), desktop.to_owned());
        }
        source.insert("HOL_GUARD_DESKTOP_HOOK_PROXY".to_owned(), proxy.to_owned());
        source.insert(
            "HOL_GUARD_DESKTOP_RUNTIME_OWNER".to_owned(),
            "/untrusted/owner".to_owned(),
        );
        source
    };
    for (desktop, proxy) in [
        (None, PROXY),
        (Some("0"), PROXY),
        (Some("1"), "relative/proxy"),
    ] {
        assert!(desktop_hook_proxy_context(&source(desktop, proxy)).is_empty());
    }
    let context = desktop_hook_proxy_context(&source(Some("1"), PROXY));
    assert_eq!(context.len(), 2);
    assert_eq!(context["HOL_GUARD_DESKTOP"], "1");
    assert_eq!(context["HOL_GUARD_DESKTOP_HOOK_PROXY"], PROXY);
}

#[cfg(unix)]
#[path = "tests_publication_observe_run.rs"]
mod run;
