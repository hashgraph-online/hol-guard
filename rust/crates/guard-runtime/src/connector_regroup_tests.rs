use serde_json::{json, Value};

use super::{dispatch, program_name, program_path};
use crate::connector_setup::queue_group_id;
use crate::runner_authority_op::ERR_INVALID;

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const WORKSPACE: &str = "/work/repo";

fn observation(source: Value) -> Value {
    json!(["local-cli.lanectl", HASH, "lanectl", source])
}

fn moves(command: &str, observations: Value, decided: Value) -> Value {
    let answer = dispatch(&json!({
        "reviews": [["r1", command, "action:old", WORKSPACE]],
        "observations": observations,
        "decided": decided,
    }))
    .expect("regroup answer");
    answer["moves"].clone()
}

fn moved(command: &str) -> Value {
    json!([["r1", queue_group_id(HASH, WORKSPACE, command)]])
}

#[test]
fn a_plain_command_moves_to_its_connector_group() {
    let observations = json!([observation(json!("/usr/local/bin/lanectl"))]);
    for command in ["lanectl status", "/usr/local/bin/lanectl ping --verbose"] {
        assert_eq!(
            moves(command, observations.clone(), json!([])),
            moved(command),
            "{command}"
        );
    }
    let no_path = json!([observation(Value::Null)]);
    assert_eq!(
        moves("lanectl status", no_path, json!([])),
        moved("lanectl status")
    );
}

#[test]
fn commands_outside_the_plain_shape_keep_their_group() {
    let observations = json!([observation(json!("/usr/local/bin/lanectl"))]);
    let long = format!("lanectl {}", "a".repeat(5000));
    for command in [
        "lanectl status && rm -rf x",
        "lanectl status | cat",
        "lanectl status > out",
        "lanectl 'status'",
        "lanectl $HOME",
        "lanectl $(whoami)",
        "TOKEN=x lanectl status",
        "npx lanectl status",
        "pnpm lanectl",
        "lanectl stätus",
        "",
        "   ",
        long.as_str(),
        "bin/ status",
        "lanectl;ls",
        ".hidden status",
    ] {
        assert_eq!(
            moves(command, observations.clone(), json!([])),
            json!([]),
            "{command}"
        );
    }
}

#[test]
fn only_one_undecided_observation_at_the_written_path_vouches() {
    let at = |source: Value| json!([observation(source)]);
    let unobserved = json!([["local-cli.other", HASH, "other", null]]);
    assert_eq!(moves("lanectl status", unobserved, json!([])), json!([]));
    let ambiguous = json!([
        observation(json!("/usr/local/bin/lanectl")),
        [
            "local-cli.lanectl-2",
            OTHER,
            "lanectl",
            "/opt/tools/lanectl"
        ],
    ]);
    assert_eq!(moves("lanectl status", ambiguous, json!([])), json!([]));
    let decided = json!([["local-cli.lanectl", HASH]]);
    assert_eq!(
        moves(
            "lanectl status",
            at(json!("/usr/local/bin/lanectl")),
            decided
        ),
        json!([])
    );
    let other_identity = json!([["local-cli.lanectl", OTHER]]);
    assert_eq!(
        moves("lanectl status", at(Value::Null), other_identity),
        moved("lanectl status")
    );
    for (command, source) in [
        ("/opt/tools/lanectl status", json!("/usr/local/bin/lanectl")),
        ("/opt/tools/lanectl status", Value::Null),
        ("./lanectl status", json!("/opt/tools/lanectl")),
    ] {
        assert_eq!(
            moves(command, at(source), json!([])),
            json!([]),
            "{command}"
        );
    }
}

#[test]
fn a_review_without_a_workspace_or_already_grouped_stays() {
    let observations = json!([observation(Value::Null)]);
    let target = queue_group_id(HASH, WORKSPACE, "lanectl status");
    let answer = dispatch(&json!({
        "reviews": [
            ["r1", "lanectl status", "action:old", ""],
            ["r2", "lanectl status", "action:old", null],
            ["r3", "lanectl status", target, WORKSPACE],
            ["r4", null, "action:old", WORKSPACE],
            ["r5", "lanectl   status", "action:old", WORKSPACE],
        ],
        "observations": observations,
        "decided": [],
    }))
    .expect("regroup answer");
    assert_eq!(answer["moves"], json!([["r5", target]]));
}

#[test]
fn python_whitespace_separates_tokens() {
    assert_eq!(program_name("lanectl\u{1c}status"), Some("lanectl"));
    assert_eq!(
        program_path("/opt/tools/lanectl\u{1f}--json"),
        Some("/opt/tools/lanectl")
    );
    assert_eq!(program_name("/opt/tools/lanectl --json"), Some("lanectl"));
    assert_eq!(program_path("lanectl status"), None);
    assert_eq!(program_path(""), None);
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        json!({"reviews": [], "observations": []}),
        json!({"reviews": [["r1", "lanectl", "g"]], "observations": [], "decided": []}),
        json!({"reviews": [], "observations": [["a", "b", "c"]], "decided": []}),
        json!({"reviews": [], "observations": [], "decided": [["a"]]}),
        json!({"reviews": {}, "observations": [], "decided": []}),
        json!([]),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
