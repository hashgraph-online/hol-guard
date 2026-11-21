use serde_json::{json, Value};

use super::{dispatch, slug};
use crate::runner_authority_op::ERR_INVALID;

#[test]
fn a_tool_name_that_is_a_command_path_is_its_own_id() {
    for name in [
        "read_file",
        "read.file",
        "read-file",
        "READ_FILE",
        "a.b.c.d",
    ] {
        assert_eq!(slug(name), name);
    }
    assert_eq!(slug("  list  "), "list");
    assert_eq!(slug("\x1cpad\x1f"), "pad");
}

#[test]
fn any_other_tool_name_slugs_with_a_digest_of_its_spelling() {
    // Pinned against the Python `slug_local_cli_command_id` these replace,
    // so saved per-tool decisions keep their ids.
    for (name, id) in [
        ("other", "other-d9298a10"),
        ("root", "root-4813494d"),
        ("--dry-run", "dry-run-675ca484"),
        ("Get File!", "get-file-bbe6c3d1"),
        ("a.b.c.d.e", "a-b-c-d-e-94c03661"),
        ("", "tool-e3b0c442"),
        ("   ", "tool-e3b0c442"),
        (
            "tool name with spaces and a long tail beyond limits",
            "tool-name-with-spaces-and-a-lon-17dc6e77",
        ),
        ("\u{24b6}bc", "bc-d4449d57"),
        ("read\u{0903}file", "read-file-4c1cb56a"),
        ("Kelvin\u{212a}", "kelvink-f0a60cf1"),
    ] {
        assert_eq!(slug(name), id, "{name:?}");
    }
    assert_eq!(
        slug(&"x".repeat(45)),
        format!("{}-15b52637", "x".repeat(31))
    );
}

#[test]
fn a_slug_that_is_not_a_command_path_folds_into_other() {
    for name in ["émoji", "ΣΑΣ", "1start"] {
        assert_eq!(slug(name), "other", "{name:?}");
    }
    assert!(!slug("--dry-run").starts_with('-'));
}

#[test]
fn slugs_answer_in_order() {
    let request = json!({ "op": "slugs", "names": ["read_file", "Get File!", "émoji"] });
    assert_eq!(
        dispatch(&request).unwrap(),
        json!({ "ids": ["read_file", "get-file-bbe6c3d1", "other"] })
    );
}

fn tools(listed: Value) -> Vec<Value> {
    let request = json!({ "op": "tools", "tools": listed, "server_name": "demo" });
    dispatch(&request).unwrap()["tools"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn listed_tools_become_rows_and_end_with_other_tools() {
    let rows = tools(json!([
        { "name": " read_file ", "description": "  Read a file.  ", "inputSchema": {} },
        { "name": "read_file", "description": "duplicate" },
        { "name": "   " },
        { "name": 7 },
        { "description": "nameless" },
        { "name": "write", "description": 3 },
    ]));
    assert_eq!(
        rows,
        vec![
            json!({ "command_id": "read_file", "name": "read_file", "usage": "read_file", "description": "Read a file." }),
            json!({ "command_id": "write", "name": "write", "usage": "write", "description": "" }),
            json!({
                "command_id": "other",
                "name": "Other tools",
                "usage": "demo …",
                "description": "Any other tool this MCP server did not list.",
            }),
        ]
    );
}

#[test]
fn a_tool_whose_slug_is_other_folds_into_the_other_tools_row() {
    let rows = tools(json!([{ "name": "émoji" }]));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], json!("Other tools"));
}

#[test]
fn rows_are_trimmed_and_capped() {
    let long = "a".repeat(300);
    let rows = tools(json!([{ "name": long, "description": long }]));
    assert_eq!(rows[0]["name"].as_str().unwrap().chars().count(), 120);
    assert_eq!(rows[0]["usage"].as_str().unwrap().chars().count(), 160);
    assert_eq!(
        rows[0]["description"].as_str().unwrap().chars().count(),
        240
    );
    let many: Vec<Value> = (0..150)
        .map(|index| json!({ "name": format!("tool{index}") }))
        .collect();
    let rows = tools(Value::from(many));
    assert_eq!(rows.len(), 101);
    assert_eq!(rows[99]["command_id"], json!("tool99"));
    assert_eq!(rows[100]["command_id"], json!("other"));
}

fn launch(tokens: &[&str], cwd: &std::path::Path, search_path: &str) -> Value {
    let request = json!({
        "op": "launch",
        "tokens": tokens,
        "cwd": cwd.to_str().unwrap(),
        "search_path": search_path,
    });
    dispatch(&request).unwrap()["argv"].clone()
}

#[cfg(unix)]
fn executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, b"#!/bin/sh\n").expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[cfg(unix)]
#[test]
fn a_bare_launcher_resolves_on_the_search_path_then_under_cwd() {
    let directory = tempfile::tempdir().expect("tempdir");
    let bin = directory.path().join("bin");
    let work = directory.path().join("work");
    std::fs::create_dir_all(&bin).expect("mkdir");
    std::fs::create_dir_all(work.join("data")).expect("mkdir");
    executable(&bin.join("server"));
    std::fs::write(work.join("local-server"), b"x").expect("write");
    let work_resolved = std::fs::canonicalize(&work).unwrap();
    let search = bin.to_str().unwrap();
    assert_eq!(
        launch(
            &[
                "server",
                "--flag",
                "@scope/pkg",
                "data",
                "missing",
                "https://x"
            ],
            &work,
            search
        ),
        json!([
            bin.join("server").to_str().unwrap(),
            "--flag",
            "@scope/pkg",
            work_resolved.join("data").to_str().unwrap(),
            "missing",
            "https://x",
        ])
    );
    assert_eq!(
        launch(&["local-server"], &work, search),
        json!([work.join("local-server").to_str().unwrap()])
    );
    assert_eq!(
        launch(&["./local-server"], &work, search),
        json!([work.join("./local-server").to_str().unwrap()])
    );
    assert_eq!(launch(&["absent"], &work, search), Value::Null);
    assert_eq!(
        launch(&["/opt/abs/server", "/etc/x"], &work, search),
        json!(["/opt/abs/server", "/etc/x"])
    );
}

#[cfg(unix)]
#[test]
fn a_guard_package_shim_is_looked_up_again_by_name() {
    let directory = tempfile::tempdir().expect("tempdir");
    let shims = directory.path().join("package-shims/bin");
    let real = directory.path().join("real");
    std::fs::create_dir_all(&shims).expect("mkdir");
    std::fs::create_dir_all(&real).expect("mkdir");
    executable(&shims.join("npx"));
    executable(&real.join("npx"));
    let shim = shims.join("npx");
    assert_eq!(
        launch(
            &[shim.to_str().unwrap(), "-y", "pkg"],
            directory.path(),
            real.to_str().unwrap()
        ),
        json!([real.join("npx").to_str().unwrap(), "-y", "pkg"])
    );
    assert_eq!(
        launch(&[shim.to_str().unwrap()], directory.path(), ""),
        Value::Null
    );
}

#[test]
fn refuses_malformed_requests() {
    for request in [
        json!([]),
        json!({ "op": "slugs", "names": [1] }),
        json!({ "op": "slugs" }),
        json!({ "op": "tools", "tools": [1], "server_name": "x" }),
        json!({ "op": "tools", "tools": [] }),
        json!({ "op": "launch", "tokens": [], "cwd": "/", "search_path": "" }),
        json!({ "op": "launch", "tokens": ["x"], "cwd": "/" }),
        json!({ "op": "other" }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
