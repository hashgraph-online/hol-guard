use serde_json::{json, Value};

use super::dispatch;

const NAME: &str = "io.github.example/docs";
const ENDPOINT: &str = "https://mcp.example.com/mcp";
const IDENTIFIER: &str = "@example/docs-mcp";

fn remote_selection() -> Value {
    json!({"registry_name": NAME, "version": "1.2.0", "endpoint": ENDPOINT, "setup_name": "docs"})
}

fn package_selection() -> Value {
    json!({
        "registry_name": NAME,
        "version": "1.2.0",
        "package_identifier": IDENTIFIER,
        "package_version": "1.2.0",
        "setup_name": "docs",
    })
}

fn entry() -> Value {
    json!({
        "name": NAME,
        "version": "1.2.0",
        "status": "active",
        "remote_endpoints": [{"url": ENDPOINT, "transport": "streamable-http"}],
        "package_options": [{
            "identifier": IDENTIFIER,
            "version": "1.2.0",
            "registry_type": "npm",
            "command": "npx",
            "arguments": ["-y", "@example/docs-mcp@1.2.0", "--ünï"],
        }],
    })
}

fn answer(kind: &str, selection: Value, results: Option<Value>) -> Value {
    let mut args = json!({"kind": kind, "selection": selection});
    if let Some(results) = results {
        args["results"] = results;
        if kind == "package" {
            args["commands"] = json!({"npx": "/opt/bin/npx"});
        }
    }
    dispatch(&args).expect("answer")
}

fn error(kind: &str, selection: Value, results: Option<Value>) -> Value {
    answer(kind, selection, results)["error"].clone()
}

#[test]
fn the_search_is_the_last_eighty_characters_of_the_name() {
    assert_eq!(
        answer("remote", remote_selection(), None),
        json!({"query": NAME})
    );
    let long = format!("io.github.example/{}", "é".repeat(100));
    let mut selection = package_selection();
    selection["registry_name"] = json!(long);
    assert_eq!(
        answer("package", selection, None),
        json!({"query": "é".repeat(80)})
    );
}

#[test]
fn a_remote_selection_binds_one_active_listing() {
    let found = answer("remote", remote_selection(), Some(json!([entry()])));
    assert_eq!(
        found["candidate"],
        json!({
            "host": "codex",
            "kind": "remote",
            "registry_name": NAME,
            "version": "1.2.0",
            "endpoint": ENDPOINT,
            "setup_name": "docs",
            "selection_digest": "1699dc2be7db25277abd3875a4ea9bbee39e3eabea8a41c1a492208357b67193",
            "account_binding": "unverified",
        })
    );
}

#[test]
fn a_package_selection_binds_the_pinned_recipe_and_its_runtime() {
    let found = answer("package", package_selection(), Some(json!([entry()])));
    assert_eq!(
        found["candidate"]["selection_digest"],
        json!("4aafed744ca77ff9af3075c3d74ea5700e2f98ae65a80b40993fe089128f945b")
    );
    assert_eq!(found["candidate"]["command"], json!("/opt/bin/npx"));
    assert_eq!(found["candidate"]["registry_type"], json!("npm"));
    assert_eq!(found["candidate"]["verified_package"], json!(false));
    let missing = dispatch(&json!({
        "kind": "package",
        "selection": package_selection(),
        "results": [entry()],
        "commands": {"uvx": "/opt/bin/uvx"},
    }))
    .expect("answer");
    assert_eq!(missing, json!({"error": "package_runtime_unavailable"}));
}

#[test]
fn a_changed_listing_is_refused() {
    let mut inactive = entry();
    inactive["status"] = json!("deprecated");
    let mut other_transport = entry();
    other_transport["remote_endpoints"][0]["transport"] = json!("sse");
    let mut loose_arguments = entry();
    loose_arguments["package_options"][0]["arguments"] = json!(["-y", 1]);
    for (kind, results) in [
        ("remote", json!({"results": []})),
        ("remote", json!([])),
        ("remote", json!([entry(), entry()])),
        ("remote", json!([inactive.clone()])),
        ("remote", json!([other_transport])),
        ("package", json!([inactive])),
        ("package", json!([entry(), entry()])),
        ("package", json!([loose_arguments])),
    ] {
        let selection = if kind == "remote" {
            remote_selection()
        } else {
            package_selection()
        };
        assert_eq!(
            error(kind, selection, Some(results)),
            json!("registry_setup_listing_changed")
        );
    }
}

#[test]
fn an_invalid_selection_is_refused_before_any_search() {
    for (key, value) in [
        ("registry_name", json!("")),
        ("registry_name", json!("x".repeat(257))),
        ("version", json!("v".repeat(81))),
        ("setup_name", json!("Docs")),
        ("setup_name", json!("-docs")),
        ("setup_name", json!("d".repeat(65))),
        ("endpoint", json!(format!("https://h/{}", "p".repeat(2040)))),
        ("endpoint", json!(7)),
    ] {
        let mut selection = remote_selection();
        selection[key] = value;
        assert_eq!(
            error("remote", selection, None),
            json!("invalid_codex_setup_selection"),
            "{key}"
        );
    }
    let mut selection = package_selection();
    selection["package_version"] = json!(null);
    assert_eq!(
        error("package", selection, None),
        json!("invalid_codex_package_selection")
    );
}

#[test]
fn only_a_plain_https_endpoint_is_used() {
    for endpoint in [
        "http://mcp.example.com/mcp",
        "https://user@mcp.example.com/mcp",
        "https://:secret@mcp.example.com/mcp",
        "https://mcp.example.com/mcp?token=1",
        "https://mcp.example.com/mcp#frag",
        "https:mcp.example.com/mcp",
        "https://[::1/mcp",
    ] {
        let mut selection = remote_selection();
        selection["endpoint"] = json!(endpoint);
        assert_eq!(
            error("remote", selection, None),
            json!("invalid_codex_setup_endpoint"),
            "{endpoint}"
        );
    }
    for endpoint in [
        "https://@mcp.example.com/mcp",
        "https://:@mcp.example.com/mcp",
        "https://mcp.example.com/mcp?",
        "HTTPS://MCP.example.com:8443/mcp",
    ] {
        let mut selection = remote_selection();
        selection["endpoint"] = json!(endpoint);
        assert!(
            answer("remote", selection, None).get("query").is_some(),
            "{endpoint}"
        );
    }
}

#[test]
fn a_malformed_request_is_refused() {
    assert!(dispatch(&json!([])).is_err());
    assert!(dispatch(&json!({"kind": "remote"})).is_err());
    assert!(dispatch(&json!({"kind": "stdio", "selection": {}})).is_err());
    assert!(
        dispatch(&json!({"kind": "package", "selection": package_selection(), "results": []}))
            .is_err()
    );
    assert!(dispatch(&json!({
        "kind": "remote",
        "selection": remote_selection(),
        "results": [],
        "commands": {},
    }))
    .is_err());
}
