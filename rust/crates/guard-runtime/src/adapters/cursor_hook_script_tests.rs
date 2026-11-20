//! Replays the clients and recovery commands the retired Python renderer
//! wrote, and pins the template the native bridge reads back.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{dispatch, py_repr, TEMPLATE};
use crate::cursor_hook_bridge_script::{normalize, ScriptConstants, CURSOR_SCRIPT_SHA256};
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/cursor/cursor_hook_script_vectors.json");

fn cases(op: &str) -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], "guard-cursor-hook-script-vectors.v1");
    document[op].as_array().expect("cases").clone()
}

fn render(guard_cli: &[&str], home: Option<&str>) -> String {
    let answer = dispatch(&json!({
        "op": "render",
        "guard_home": "/home dir é/.hol-guard",
        "guard_home_resolved": "/home dir é/.hol-guard",
        "home": home,
        "guard_cli": guard_cli,
        "recovery_command": ["/bin/hol-guard", "recover"],
    }))
    .expect("render answers");
    answer["source"].as_str().expect("source").to_owned()
}

#[test]
fn every_recorded_client_replays() {
    let cases = cases("render");
    assert_eq!(cases.len(), 4);
    for case in &cases {
        let answer = dispatch(&case["args"]).expect("render answers");
        assert_eq!(
            answer,
            json!({ "source": case["source"] }),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn every_recorded_recovery_command_replays() {
    let cases = cases("recovery");
    assert_eq!(cases.len(), 3);
    for case in &cases {
        let answer = dispatch(&case["args"]).expect("recovery answers");
        assert_eq!(
            answer,
            json!({ "command": case["command"] }),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_bridge_reader_was_reviewed_against_this_template() {
    // The native bridge reads the client's constants and never runs it, so a
    // template change must keep those lines readable before the digest moves.
    let digest = hex::encode(Sha256::digest(TEMPLATE.as_bytes()));

    assert_eq!(digest, CURSOR_SCRIPT_SHA256);
}

#[test]
fn a_rendered_client_reads_back_as_the_template() {
    let source = render(&["/bin/hol-guard"], Some("/home dir é"));

    let (template, constants) = normalize(&source).expect("the bridge reads the client");

    assert_eq!(template, TEMPLATE);
    assert_eq!(
        constants,
        ScriptConstants {
            guard_home: "/home dir é/.hol-guard".to_owned(),
            home: Some("/home dir é".to_owned()),
            recovery_command: vec!["/bin/hol-guard".to_owned(), "recover".to_owned()],
            timeout_seconds: 42,
        }
    );
}

#[test]
fn the_users_own_home_is_never_named() {
    let source = render(&["/bin/hol-guard"], None);

    let (_, constants) = normalize(&source).expect("the bridge reads the client");

    assert_eq!(constants.home, None);
    assert!(!source.contains("--home"));
}

#[test]
fn stable_cli_names_run_hook_without_the_guard_prefix() {
    let shapes: [(&[&str], bool); 7] = [
        (&["/core/current-hol-guard"], false),
        (&["/core/current-hol-guard.cmd"], false),
        (&["/core/versions/3.0.57/hol-guard"], false),
        (&["/opt/PLUGIN-GUARD.EXE"], false),
        (
            &["/usr/bin/python3", "-m", "codex_plugin_scanner.cli"],
            true,
        ),
        (&["/opt/hol-guard-runtime"], true),
        (&[], true),
    ];
    for (guard_cli, prefixed) in shapes {
        let source = render(guard_cli, None);

        let starts = source.contains("GUARD_HOOK_ARGV = [\"guard\", \"hook\", ");
        assert_eq!(starts, prefixed, "{guard_cli:?}");
        assert!(source.contains("\"hook\", \"--guard-home\", \"/home dir \\u00e9/.hol-guard\""));
    }
}

#[test]
fn repr_matches_python() {
    assert_eq!(py_repr("plain"), "'plain'");
    assert_eq!(py_repr("it's"), "\"it's\"");
    assert_eq!(py_repr("a'b\"c"), "'a\\'b\"c'");
    assert_eq!(py_repr("tab\there\\"), "'tab\\there\\\\'");
    assert_eq!(
        py_repr("é\u{85}\u{2028}😀\u{e0001}"),
        "'é\\x85\\u2028😀\\U000e0001'"
    );
}

#[test]
fn malformed_arguments_are_refused() {
    let render = json!({
        "op": "render",
        "guard_home": "/g",
        "guard_home_resolved": "/g",
        "home": null,
        "guard_cli": ["/bin/hol-guard"],
        "recovery_command": [],
    });
    let recovery = json!({
        "op": "recovery",
        "python": "/usr/bin/python3",
        "import_roots": ["/opt/site"],
        "guard_home": "/g",
        "home": "/h",
    });
    assert!(dispatch(&render).is_ok());
    assert!(dispatch(&recovery).is_ok());
    let mut refused = vec![json!([]), json!({"op": "other"}), json!({})];
    for (base, field, value) in [
        (&render, "op", json!(null)),
        (&render, "guard_home", json!(1)),
        (&render, "guard_home_resolved", json!(null)),
        (&render, "home", json!(false)),
        (&render, "guard_cli", json!("/bin/hol-guard")),
        (&render, "recovery_command", json!([1])),
        (&render, "python", json!("/usr/bin/python3")),
        (&recovery, "op", json!("render")),
        (&recovery, "python", json!(null)),
        (&recovery, "import_roots", json!(null)),
        (&recovery, "guard_home", json!(["/g"])),
        (&recovery, "home", json!(null)),
        (&recovery, "guard_cli", json!([])),
    ] {
        let mut request = base.clone();
        request[field] = value;
        refused.push(request);
    }
    for field in ["guard_home", "home", "guard_cli", "recovery_command"] {
        let mut request = render.clone();
        request.as_object_mut().expect("object").remove(field);
        refused.push(request);
    }
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
