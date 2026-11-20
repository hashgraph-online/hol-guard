use super::*;

fn reason(code: &str, message: &str) -> Map<String, Value> {
    json!({"code": code, "message": message})
        .as_object()
        .unwrap()
        .clone()
}

fn package(script_free: Option<Value>) -> Map<String, Value> {
    let mut package = json!({"name": "zod"}).as_object().unwrap().clone();
    if let Some(flag) = script_free {
        package.insert("scriptFreeRegistryInstall".to_owned(), flag);
    }
    package
}

fn settle(
    decision: &str,
    reasons: Vec<Map<String, Value>>,
    packages: Vec<Map<String, Value>>,
) -> Value {
    PackageEvalResult {
        decision: decision.to_owned(),
        reasons,
        packages,
        ..PackageEvalResult::default()
    }
    .review_settlement()
}

#[test]
fn an_allow_continues() {
    assert_eq!(
        settle("allow", vec![], vec![]),
        json!({"action": "allow", "reason": null})
    );
}

#[test]
fn a_watch_continues_only_when_every_package_runs_no_code() {
    let script_free = || package(Some(Value::Bool(true)));
    assert_eq!(
        settle("monitor", vec![], vec![script_free(), script_free()]),
        json!({"action": "allow", "reason": null})
    );
    for packages in [
        vec![],
        vec![script_free(), package(None)],
        vec![package(Some(json!("true")))],
        vec![package(Some(Value::Bool(false)))],
    ] {
        assert_eq!(
            settle("monitor", vec![], packages.clone()),
            json!({"action": "review", "reason": null}),
            "{packages:?}"
        );
    }
}

#[test]
fn a_block_carries_its_first_message() {
    let reasons = vec![
        reason("no_message", ""),
        reason("malware", "left-pad is malware"),
        reason("other", "second"),
    ];
    assert_eq!(
        settle("block", reasons, vec![package(Some(Value::Bool(true)))]),
        json!({"action": "block", "reason": "left-pad is malware"})
    );
    assert_eq!(
        settle("block", vec![], vec![]),
        json!({"action": "block", "reason": DEFAULT_BLOCK_MESSAGE})
    );
}

#[test]
fn an_ask_guides_only_with_lifecycle_script_guidance() {
    let guidance = "Run it again with --ignore-scripts.";
    let reasons = vec![
        reason("no_cached_match", "unknown package"),
        reason(LIFECYCLE_SCRIPTS_ENABLED_CODE, guidance),
    ];
    assert_eq!(
        settle("ask", reasons, vec![]),
        json!({"action": "guide", "reason": guidance})
    );
    assert_eq!(
        settle(
            "ask",
            vec![reason(LIFECYCLE_SCRIPTS_ENABLED_CODE, "")],
            vec![]
        ),
        json!({"action": "review", "reason": null})
    );
    assert_eq!(
        settle("ask", vec![reason("no_cached_match", "unknown")], vec![]),
        json!({"action": "review", "reason": null})
    );
    assert_eq!(
        settle(
            "monitor",
            vec![reason(LIFECYCLE_SCRIPTS_ENABLED_CODE, guidance)],
            vec![]
        ),
        json!({"action": "review", "reason": null})
    );
}
