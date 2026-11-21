use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/hook_direct_saved_decision_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("saved-decision vectors parse")
}

fn environment(vectors: &Value) -> BTreeMap<String, String> {
    serde_json::from_value(vectors["environment"].clone()).expect("vector environment")
}

/// The query with its tool-input pairs in key order. The daemon keeps the
/// payload's key order, which a parsed payload here does not, and the token
/// does not depend on it.
fn sorted(mut query: NativeExactActionQueryV1) -> NativeExactActionQueryV1 {
    if let NativeExactActionQueryV1::ExactAction {
        tool_input: Some(pairs),
        ..
    } = &mut query
    {
        pairs.sort_by(|left, right| left.0.cmp(&right.0));
    }
    query
}

fn input<'a>(
    vectors: &'a Value,
    harness: &'a str,
    payload: &'a Map<String, Value>,
    environment: &'a BTreeMap<String, String>,
) -> QueryInput<'a> {
    QueryInput {
        harness,
        payload,
        workspace: vectors["workspace"].as_str().unwrap(),
        home_dir: vectors["home_dir"].as_str().unwrap(),
        environment,
        control_digest: vectors["control_digest"].as_str().unwrap(),
    }
}

#[test]
fn queries_match_the_daemon_vectors() {
    let vectors = vectors();
    let environment = environment(&vectors);
    let cases = vectors["queries"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let payload = case["payload"].as_object().unwrap();
        let result = case["result"].as_object().unwrap();
        let input = input(
            &vectors,
            case["harness"].as_str().unwrap(),
            payload,
            &environment,
        );
        let outcome = exact_action(&input, result, case.get("receipt"));
        if case["query"].is_null() {
            assert!(
                matches!(outcome, Err(HookDirectDefer::SavedDecision)),
                "{name}: expected a defer"
            );
            continue;
        }
        let (artifact_id, query) = outcome.unwrap_or_else(|_| panic!("{name}: deferred"));
        assert_eq!(
            Some(artifact_id.as_str()),
            case["artifact_id"].as_str(),
            "{name}"
        );
        let expected: NativeExactActionQueryV1 =
            serde_json::from_value(case["query"].clone()).expect("vector query");
        assert_eq!(sorted(query), sorted(expected), "{name}");
    }
}

#[test]
fn clean_path_accepts_only_the_text_the_daemon_sends() {
    for path in ["/", "/a/b", "/a/../b"] {
        assert!(clean_path(path), "{path}");
    }
    for path in ["", "a", "/a/", "/a//b", "/a/./b", "//a"] {
        assert!(!clean_path(path), "{path}");
    }
}

/// The first bound vector, for the cases that change one fact of it.
fn bound_case(vectors: &Value) -> &Value {
    vectors["queries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| !case["query"].is_null())
        .unwrap()
}

/// A Windows workspace, plain or verbatim, defers too: the daemon then reads
/// the saved decision itself, so it still answers the retry.
#[test]
fn an_unclean_workspace_defers() {
    let vectors = vectors();
    let environment = environment(&vectors);
    let case = bound_case(&vectors);
    let payload = case["payload"].as_object().unwrap();
    let mut input = input(
        &vectors,
        case["harness"].as_str().unwrap(),
        payload,
        &environment,
    );
    for workspace in ["/work/repo/", r"C:\work\repo", r"\\?\C:\work\repo"] {
        input.workspace = workspace;
        let outcome = exact_action(
            &input,
            case["result"].as_object().unwrap(),
            case.get("receipt"),
        );
        assert!(
            matches!(outcome, Err(HookDirectDefer::SavedDecision)),
            "{workspace}"
        );
    }
}

#[test]
fn a_fact_the_daemon_would_stringify_defers() {
    let vectors = vectors();
    let environment = environment(&vectors);
    let case = bound_case(&vectors);
    let payload = case["payload"].as_object().unwrap();
    let input = input(
        &vectors,
        case["harness"].as_str().unwrap(),
        payload,
        &environment,
    );
    for value in [json!(true), json!(1), json!(["review"])] {
        let mut result = case["result"].as_object().unwrap().clone();
        result.insert("reason_code".to_owned(), value);
        assert!(matches!(
            facts(&result),
            Err(HookDirectDefer::SavedDecision)
        ));
    }
    let mut result = case["result"].as_object().unwrap().clone();
    result.insert("reason_code".to_owned(), Value::Null);
    let facts = facts(&result).unwrap();
    assert_eq!(facts.reason_code.as_deref(), Some(""));
    assert!(exact_action(&input, &result, case.get("receipt")).is_err());
}

#[test]
fn numbers_the_daemon_could_respell_defer() {
    for text in ["1.5", "1e5", "1.0", "100000000000000000000"] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(!plain_numbers(&value), "{text}");
        let payload: Map<String, Value> =
            serde_json::from_value(json!({"tool_input": {"limit": [{"n": value}]}})).unwrap();
        assert!(
            matches!(
                tool_input_pairs(&payload),
                Err(HookDirectDefer::SavedDecision)
            ),
            "{text}"
        );
    }
    for text in ["0", "-0", "-7", "18446744073709551615"] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(plain_numbers(&value), "{text}");
    }
}

#[test]
fn tool_input_falls_back_to_arguments() {
    let payload: Map<String, Value> =
        serde_json::from_value(json!({"arguments": {"cmd": "ls", "n": 2}})).unwrap();
    let pairs = tool_input_pairs(&payload).unwrap().unwrap();
    assert_eq!(
        pairs,
        vec![("cmd".to_owned(), json!("ls")), ("n".to_owned(), json!(2))]
    );
    let empty = Map::new();
    assert_eq!(tool_input_pairs(&empty).unwrap(), None);
}
