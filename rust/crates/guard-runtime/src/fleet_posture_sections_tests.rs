//! Replays `section_vectors.json`, recorded from the original Python
//! `policy_section` and `project_runtime_posture`, through the native kinds.

use serde_json::{json, Value};

use super::super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../testdata/fleet_posture_sections/section_vectors.json");
const KEY: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";

#[test]
fn sections_match_the_python_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = vectors.as_array().expect("cases");
    assert!(cases.len() > 90);
    for case in cases {
        let kind = case["kind"].as_str().expect("kind");
        let answer = dispatch(kind, &case["request"]);
        if case["expected"].is_null() {
            assert_eq!(answer, Err(ERR_INVALID), "{}", case["label"]);
        } else {
            assert_eq!(answer.as_ref(), Ok(&case["expected"]), "{}", case["label"]);
        }
    }
}

fn item(row: Value) -> Value {
    let answer = dispatch(
        "fleet_runtime_posture",
        &json!({"posture": {"status": "ok", "runtimes": [[row]]}, "hash_key": KEY}),
    )
    .expect("answer");
    answer["items"][0].clone()
}

#[test]
fn codes_and_digests_never_carry_a_trailing_newline() {
    let hex = "e".repeat(64);
    let projected = item(json!({
        "family": "node\n",
        "os": "macos\n",
        "reason": "not_found\n",
        "executable_sha256": format!("{hex}\n"),
    }));
    assert_eq!(projected["family"], "unknown");
    assert_eq!(projected["os"], "unknown");
    assert_eq!(projected["reason"], "unknown");
    assert_eq!(projected["executableHash"], Value::Null);
}

#[test]
fn chunked_lists_join_back_in_order() {
    let answer = dispatch(
        "fleet_runtime_posture",
        &json!({
            "posture": {
                "status": "ok",
                "runtimes": [[{"path": "/a"}], [{"path": "/b"}]],
                "unresolved_launches": [[{}, {}], [{}]],
            },
            "hash_key": KEY,
        }),
    )
    .expect("answer");
    assert_eq!(answer["unresolvedLaunches"], 3);
    assert_eq!(answer["items"].as_array().map(Vec::len), Some(2));
    assert_ne!(
        answer["items"][0]["locationHash"],
        answer["items"][1]["locationHash"]
    );
}

#[test]
fn malformed_requests_are_refused() {
    for (kind, request) in [
        ("fleet_policy_section", json!({"acknowledgement": null})),
        ("fleet_policy_section", json!({"last_error": null})),
        (
            "fleet_policy_section",
            json!({"acknowledgement": [], "last_error": null}),
        ),
        (
            "fleet_policy_section",
            json!({"acknowledgement": null, "last_error": null, "extra": 1}),
        ),
        (
            "fleet_runtime_posture",
            json!({"posture": {"status": "ok"}}),
        ),
        (
            "fleet_runtime_posture",
            json!({"posture": {"status": "ok"}, "hash_key": "short"}),
        ),
        (
            "fleet_runtime_posture",
            json!({"posture": [], "hash_key": KEY}),
        ),
    ] {
        assert_eq!(dispatch(kind, &request), Err(ERR_INVALID), "{request}");
    }
}
