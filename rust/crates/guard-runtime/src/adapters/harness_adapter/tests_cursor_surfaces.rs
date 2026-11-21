//! Cursor's surfaces and local action payload through the `harness_adapter` kind.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::{dispatch, Home};

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn request(home: &Home, workspace: Option<&Path>, op: &str, extra: &Value) -> Value {
    let mut request = json!({
        "harness": "cursor",
        "op": op,
        "context": home.context(json!({"PATH": ""})),
    });
    request["context"]["workspace"] = json!(workspace);
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    request
}

fn ask(home: &Home, workspace: Option<&Path>, op: &str, extra: Value) -> Value {
    dispatch(&request(home, workspace, op, &extra)).unwrap()
}

fn refusal(home: &Home, op: &str, extra: Value) -> Option<String> {
    ask(home, None, op, extra)["refusal"]
        .as_str()
        .map(str::to_owned)
}

fn surfaces(answer: &Value) -> Vec<String> {
    answer["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|surface| surface.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_install_surface_is_all_unless_one_is_named() {
    let home = Home::new();
    let surface = |extra| ask(&home, None, "install_surface", extra)["surface"].clone();
    assert_eq!(surface(json!({"surface": null})), "all");
    assert_eq!(surface(json!({})), "all");
    assert_eq!(surface(json!({"surface": "editor"})), "editor");
    assert_eq!(surface(json!({"surface": "cli"})), "cli");
    for unsupported in ["all", "browser", ""] {
        assert_eq!(
            refusal(&home, "install_surface", json!({"surface": unsupported})),
            Some(format!("Unsupported Cursor surface: {unsupported}")),
        );
    }
}

#[test]
fn managed_installs_name_the_surfaces_they_protect() {
    let home = Home::new();
    let read = |installs: Value| {
        let extra = json!({"managed_installs": installs});
        surfaces(&ask(&home, None, "protected_surfaces", extra))
    };
    assert!(read(json!([])).is_empty());
    assert_eq!(read(json!([{"surface": "cli"}])), ["cli"]);
    assert_eq!(
        read(json!([{"surface": "cli"}, {"surface": "editor"}, {"surface": "cli"}])),
        ["cli", "editor"]
    );
    assert_eq!(
        read(json!([{"manifest": {"surface": "all"}}])),
        ["editor", "cli"]
    );
    assert_eq!(
        read(json!([{"manifest": {"surfaces": ["cli", "bogus", 3, "editor"]}}])),
        ["cli", "editor"]
    );
    assert_eq!(
        read(json!([{"manifest": {"surface": "editor"}}])),
        ["editor"]
    );
    // A row whose own surface is already known still reads its manifest.
    assert_eq!(
        read(json!([
            {"surface": "cli"},
            {"surface": "cli", "manifest": {"surfaces": ["editor"]}}
        ])),
        ["cli", "editor"]
    );
    // Rows, manifests and surfaces that are not what they should be add nothing.
    assert!(
        read(json!([1, {"manifest": []}, {"surface": 4}, {"manifest": {"surface": 4}}])).is_empty()
    );
}

#[test]
fn the_stored_install_decides_the_protected_surfaces() {
    let home = Home::new();
    let read = |extra: Value| surfaces(&ask(&home, None, "protected_surfaces_from_store", extra));
    assert!(read(json!({"installed": false, "managed": {"surface": "cli"}})).is_empty());
    assert_eq!(
        read(json!({"installed": true, "managed": null})),
        ["editor", "cli"]
    );
    assert_eq!(read(json!({"installed": true})), ["editor", "cli"]);
    assert_eq!(
        read(json!({"installed": true, "managed": {"surface": "cli"}})),
        ["cli"]
    );
}

#[test]
fn a_local_action_reports_each_surface_as_the_machine_has_it() {
    let home = Home::new();
    let workspace = home.root.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let action = |surface: Value, extra: Value| {
        let mut fields = json!({"action": "status", "surface": surface});
        for (key, value) in extra.as_object().unwrap() {
            fields[key] = value.clone();
        }
        ask(&home, Some(&workspace), "local_action", fields)
    };

    let none = action(Value::Null, json!({}));
    assert_eq!(
        none["surface_statuses"],
        json!([
            {"surface": "editor", "status": "not_detected"},
            {"surface": "cli", "status": "not_detected"},
        ])
    );
    assert_eq!(none["surface"], "editor");
    assert_eq!(none["status"], "not_detected");
    assert_eq!(none["evidence"]["actionScope"], "cursor:editor:status");
    assert_eq!(none["evidence"]["redactedPath"], "$HOME/.cursor/mcp.json");

    write(
        &home.home().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{}}"#,
    );
    let global = action(json!("editor"), json!({}));
    assert_eq!(global["status"], "detected_unprotected");
    assert_eq!(global["evidence"]["redactedPath"], "$HOME/.cursor/mcp.json");

    write(
        &workspace.join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"fs":{"command":"node","args":["server.js"]}}}"#,
    );
    let project = action(json!("editor"), json!({}));
    assert_eq!(project["status"], "detected_unprotected");
    assert_eq!(
        project["evidence"]["redactedPath"],
        "$WORKSPACE/.cursor/mcp.json"
    );

    let named = action(json!("cli"), json!({"protected_surfaces": ["editor"]}));
    assert_eq!(named["surface"], "cli");
    assert_eq!(named["sync"]["surface"], "cli");
    assert_eq!(
        named["evidence"]["redactedPath"],
        "PATH:guard-cursor-agent|guard-cursor"
    );
    assert_eq!(named["surface_statuses"][0]["status"], "protected");
    assert_eq!(named["surface_statuses"][1]["status"], "not_detected");

    let all = action(json!("editor"), json!({"protected": true}));
    assert_eq!(all["status"], "protected");
    assert_eq!(all["sync"]["daemonReachability"], "local");
    assert_eq!(all["evidence"]["policyDecision"], "monitor");
}

#[test]
fn a_config_routing_a_server_through_a_guard_proxy_is_protected() {
    let home = Home::new();
    let config = home.home().join(".cursor").join("mcp.json");
    let launcher = home.home().join("bin").join("hol-guard");
    let read = |text: &str| {
        write(&config, text);
        let extra = json!({"action": "status", "surface": "editor"});
        ask(&home, None, "local_action", extra)["status"].clone()
    };
    let proxied = json!({"mcpServers": {"fs": {
        "command": launcher,
        "args": ["guard", "mcp-proxy", "--server", "fs"],
    }}});
    assert_eq!(read(&proxied.to_string()), "protected");
    assert_eq!(
        read(r#"{"mcpServers":{"fs":{"command":"node","args":[]}}}"#),
        "detected_unprotected"
    );
    assert_eq!(read("not json"), "detected_unprotected");
    assert_eq!(read("[]"), "detected_unprotected");
    assert_eq!(read(r#"{"mcpServers":[]}"#), "detected_unprotected");
}

#[test]
fn a_guard_cli_shim_is_a_protected_detected_cli() {
    let home = Home::new();
    write(&home.guard().join("bin").join("guard-cursor-agent"), "");
    let extra = json!({"action": "status", "surface": "cli"});
    assert_eq!(
        ask(&home, None, "local_action", extra)["status"],
        "protected"
    );
}

#[test]
fn an_unsupported_local_action_surface_is_refused() {
    let home = Home::new();
    assert_eq!(
        refusal(
            &home,
            "local_action",
            json!({"action": "repair", "surface": "browser"})
        ),
        Some("Unsupported Cursor surface: browser".to_owned()),
    );
}

#[test]
fn malformed_surface_requests_are_invalid() {
    let home = Home::new();
    for (op, extra) in [
        ("local_action", json!({"surface": "editor"})),
        ("local_action", json!({"action": "x", "protected": "yes"})),
        (
            "local_action",
            json!({"action": "x", "protected_surfaces": [1]}),
        ),
        ("protected_surfaces", json!({})),
        ("protected_surfaces_from_store", json!({"managed": {}})),
    ] {
        assert!(
            dispatch(&request(&home, None, op, &extra)).is_err(),
            "{op} {extra}"
        );
    }
}

#[test]
fn the_runtime_reads_the_stored_cursor_install_itself() {
    let home = Home::new();
    let read = |installed: bool| {
        surfaces(&ask(
            &home,
            None,
            "protected_surfaces_from_store",
            json!({"installed": installed, "store_home": home.guard()}),
        ))
    };
    // No store file: an installed Cursor with no record protects both.
    assert_eq!(read(true), ["editor", "cli"]);
    let connection = rusqlite::Connection::open(home.guard().join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
               harness text primary key, active integer not null, workspace text,
               manifest_json text not null, updated_at text not null);",
        )
        .unwrap();
    assert_eq!(read(true), ["editor", "cli"]);
    connection
        .execute(
            "insert into managed_installs values ('cursor', 1, null, ?1, '2026-03-10T10:00:00+00:00')",
            [json!({"surface": "cli"}).to_string()],
        )
        .unwrap();
    assert_eq!(read(true), ["cli"]);
    // An uninstalled Cursor protects nothing whatever the store says.
    assert!(read(false).is_empty());
    // A store that names no Cursor record is the same as no store at all.
    connection
        .execute("delete from managed_installs", [])
        .unwrap();
    assert_eq!(read(true), ["editor", "cli"]);
    let bad = request(
        &home,
        None,
        "protected_surfaces_from_store",
        &json!({"installed": true, "store_home": 3}),
    );
    assert!(dispatch(&bad).is_err());
}
