use super::{
    block_response, block_verdict, blocked_reason, command_selector, grant_verdict, launch,
    match_command_id, Launch, Verdict, BLOCKED_REASON_CODE, WATCH_REASON,
};
use guard_command::hook_responses::{pre_tool, recording_only_pre_tool, Object};
use guard_contracts::{LocalCliIdentitySourceV1, PackageJsonScriptsV1, UnlistedCliV1};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const VECTORS: &str = include_str!("../tests/fixtures/local_cli_block_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn object(value: &Value) -> Object {
    value.as_object().unwrap().clone()
}

fn source() -> LocalCliIdentitySourceV1 {
    LocalCliIdentitySourceV1::Script {
        entrypoint: json!({ "path": "/work/bin/demo" }),
    }
}

fn fixture_launch(cli_id: &str, identity_hash: &str) -> Launch {
    Launch {
        cli_id: cli_id.to_owned(),
        name: "demo-tool".to_owned(),
        identity_hash: identity_hash.to_owned(),
        kind: "executable".to_owned(),
        runner: None,
        source: source(),
        tokens: None,
    }
}

#[test]
fn command_ids_match_the_daemon() {
    let vectors = vectors();
    for case in vectors["command_ids"].as_array().unwrap() {
        let tokens = strings(&case["tokens"]);
        let catalog: BTreeSet<String> = strings(&case["catalog"]).into_iter().collect();
        let expected = case["expected"].as_str().unwrap();
        assert_eq!(match_command_id(&tokens, &catalog), expected, "{case}");
        let selected = command_selector(&catalog, &tokens);
        if catalog.is_empty() {
            assert_eq!(selected, None, "{case}");
        } else {
            assert_eq!(selected, Some(expected.to_owned()), "{case}");
        }
    }
}

#[test]
fn grant_answers_match_the_daemon() {
    let vectors = vectors();
    let grants = &vectors["grant_answers"];
    let launch = fixture_launch(
        grants["cli_id"].as_str().unwrap(),
        grants["identity_hash"].as_str().unwrap(),
    );
    let cases = grants["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for case in cases {
        let answer = Some(&case["answer"]).filter(|answer| !answer.is_null());
        let expected = match case["expected"].as_str() {
            None | Some("allowed") => Verdict::Unchanged,
            Some("blocked") => Verdict::Blocked(launch.name.clone()),
            Some("unverified") => Verdict::Unverified,
            Some(other) => panic!("unexpected outcome {other}"),
        };
        assert_eq!(grant_verdict(&launch, answer), expected, "{case}");
    }
}

#[test]
fn blocks_render_the_daemon_verdict() {
    let vectors = vectors();
    let cases = vectors["blocks"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for case in cases {
        let harness = case["harness"].as_str().unwrap();
        let name = case["name"].as_str().unwrap();
        let result = object(&case["result"]);
        let expected = &case["expected"];
        assert_eq!(expected["harness"], harness, "{case}");
        let verdict = object(&expected["verdict"]);
        assert_eq!(
            block_verdict(&result, BLOCKED_REASON_CODE, &blocked_reason(name)),
            verdict,
            "{case}"
        );
        let mut rendered = pre_tool(harness, &verdict);
        rendered.insert(
            "approval_reuse_status".to_owned(),
            expected["approval_reuse_status"].clone(),
        );
        assert_eq!(
            block_response(harness, &result, name, false),
            Some(Value::Object(rendered)),
            "{case}"
        );
    }
}

#[test]
fn watch_records_the_block_as_the_daemon_does() {
    let vectors = vectors();
    let watch = &vectors["watch"];
    assert_eq!(watch["reason_code"], BLOCKED_REASON_CODE);
    assert_eq!(watch["reason"], WATCH_REASON);
    for case in vectors["blocks"].as_array().unwrap() {
        let harness = case["harness"].as_str().unwrap();
        let expected = recording_only_pre_tool(harness, BLOCKED_REASON_CODE, WATCH_REASON);
        assert_eq!(
            block_response(harness, &object(&case["result"]), "demo-tool", true),
            Some(Value::Object(expected)),
            "{case}"
        );
    }
}

#[test]
fn a_verdict_too_large_to_render_defers() {
    // The block verdict replaces `reason` with the short extension text, so
    // the bulk has to sit on a field that is still sent to the renderer.
    let result = object(&json!({
        "decision": "allow",
        "minimum_action": "allow",
        "evidence": "x".repeat(64 * 1024),
    }));
    assert_eq!(block_response("codex", &result, "demo-tool", false), None);
}

fn package(identity: Value, content_sha256: &str) -> PackageJsonScriptsV1 {
    serde_json::from_value(json!({
        "manifest_path": "/work/package.json",
        "runner": "npm",
        "focused_script": "build",
        "focused_listed": true,
        "source": {
            "source": "package_json",
            "manifest_path": "/work/package.json",
            "content_sha256": content_sha256,
            "package_name": "demo",
        },
        "identity": identity,
        "commands": [],
        "command_tokens": ["build"],
    }))
    .unwrap()
}

fn unlisted(cli_id: &str, kind: &str) -> UnlistedCliV1 {
    serde_json::from_value(json!({
        "cli_id": cli_id,
        "name": "demo-tool",
        "kind": kind,
        "identity_hash": "c".repeat(64),
        "example_label": "demo-tool",
        "interpreter_name": null,
        "source_path": null,
        "path_class": null,
        "runner": null,
        "identity_source": { "source": "script", "entrypoint": { "path": "/work/bin/demo" } },
    }))
    .unwrap()
}

#[test]
fn the_launch_takes_the_package_identity_then_the_first_unlisted_cli() {
    let hash = "d".repeat(64);
    let identity = json!({
        "cli_id": "local-cli.demo",
        "name": "demo",
        "kind": "script",
        "identity_hash": hash,
    });
    let found = launch(Some(package(identity, &hash)), || panic!("not asked"))
        .unwrap()
        .unwrap();
    assert_eq!(found.cli_id, "local-cli.demo");
    assert_eq!(found.tokens, Some(vec!["build".to_owned()]));

    let fallback = launch(Some(package(Value::Null, &hash)), || {
        Ok(vec![
            unlisted("local-cli.first", "script"),
            unlisted("local-cli.second", "executable"),
        ])
    })
    .unwrap()
    .unwrap();
    assert_eq!(fallback.cli_id, "local-cli.first");
    assert_eq!(fallback.kind, "script");
    assert_eq!(fallback.runner, None);
    assert_eq!(fallback.tokens, Some(vec!["build".to_owned()]));

    assert_eq!(launch(None, || Ok(Vec::new())), Ok(None));
    assert_eq!(launch(None, || Err(())), Err(()));
}

#[test]
fn a_malformed_launch_answer_is_unverified() {
    let hash = "e".repeat(64);
    assert_eq!(
        launch(
            Some(package(Value::Null, "not-a-digest")),
            || Ok(Vec::new())
        ),
        Err(())
    );
    let bad_identity = json!({
        "cli_id": "local-cli.Demo",
        "name": "demo",
        "kind": "script",
        "identity_hash": hash,
    });
    assert_eq!(
        launch(Some(package(bad_identity, &hash)), || Ok(Vec::new())),
        Err(())
    );
    for (cli_id, kind) in [
        ("local-cli.demo", "binary"),
        ("cli.demo", "script"),
        ("local-cli.a-b-c-d-e-f-g-h-i-j", "script"),
        ("local-cli.demo-", "script"),
    ] {
        assert_eq!(
            launch(None, || Ok(vec![unlisted(cli_id, kind)])),
            Err(()),
            "{cli_id} {kind}"
        );
    }
}
