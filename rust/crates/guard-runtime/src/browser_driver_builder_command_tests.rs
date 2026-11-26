use serde_json::{json, Value};

use super::{proposed_verb, run_command};

fn run(request: Value) -> Value {
    run_command(&serde_json::to_vec(&request).unwrap())
}

fn tools_list() -> String {
    json!({
        "tools": [
            {"name": "page_navigate", "inputSchema": {"properties": {"url": {"type": "string"}}}},
            {"name": "page_click", "inputSchema": {"properties": {"element": {}, "ref": {}}}},
            {"name": "field_fill", "inputSchema": {"properties": {"selector": {}, "value": {}}}},
            {"name": "run_script", "inputSchema": {"properties": {"expression": {}}}},
            {"name": "set_cookies", "inputSchema": {"properties": {}}},
            {"name": "attach_file", "inputSchema": {"properties": {"paths": {}}}},
            {"name": "frobnicate"},
            {"name": "BadName"},
        ]
    })
    .to_string()
}

fn generate_request() -> Value {
    json!({
        "op": "generate",
        "slug": "example-pilot",
        "server": "example-pilot",
        "name": "Example Pilot",
        "publisher": "Example Org",
        "document": tools_list(),
    })
}

#[test]
fn verbs_follow_the_strongest_name_token() {
    assert_eq!(proposed_verb("page_navigate").0, "Navigate");
    assert_eq!(proposed_verb("tab_close").0, "TabControl");
    assert_eq!(proposed_verb("evaluate_click_handler").0, "Evaluate");
    assert_eq!(proposed_verb("get_cookies").0, "CookieRead");
    assert_eq!(proposed_verb("set_cookies").0, "CookieWrite");
    assert_eq!(proposed_verb("clear_local-storage").0, "StorageWrite");
    assert_eq!(proposed_verb("take_screenshot").0, "Screenshot");
    assert_eq!(proposed_verb("frobnicate"), ("Other", None));
}

#[test]
fn generate_drafts_a_strict_unverified_profile_that_compiles() {
    let result = run(generate_request());
    assert_eq!(result["ok"], true, "{result}");
    let profile = &result["profile"];
    assert_eq!(profile["id"], "browser.example-pilot");
    assert_eq!(profile["publisher"]["verified"], false);
    assert_eq!(profile["profileMode"]["default"], "unknown");
    assert_eq!(profile["match"]["mcpServerNames"], json!(["example-pilot"]));
    assert_eq!(
        profile["match"]["toolNamespaces"],
        json!(["mcp__example-pilot__"])
    );
    let tools = profile["tools"].as_array().unwrap();
    let by_name = |name: &str| tools.iter().find(|tool| tool["name"] == name).unwrap();
    assert_eq!(by_name("page_navigate")["url"], json!(["url"]));
    assert_eq!(
        by_name("page_click")["element"],
        json!({"name": ["element", "ref"]})
    );
    assert_eq!(by_name("field_fill")["verb"], "Type");
    assert_eq!(by_name("field_fill")["text"], json!(["value"]));
    assert_eq!(by_name("run_script")["verb"], "Evaluate");
    assert_eq!(by_name("run_script")["script"], json!(["expression"]));
    assert_eq!(by_name("set_cookies")["verb"], "CookieWrite");
    assert_eq!(by_name("attach_file")["verb"], "Attach");
    assert_eq!(by_name("attach_file")["file"], json!(["paths"]));
    assert_eq!(by_name("frobnicate")["verb"], "Other");
    assert!(tools.iter().all(|tool| tool["name"] != "BadName"));
    let notes = result["notes"].to_string();
    assert!(notes.contains("verb_unknown") && notes.contains("frobnicate"));
    assert!(notes.contains("tool_name_unsupported") && notes.contains("BadName"));
    assert!(notes.contains("profile_mode_unknown"));

    let validated = run(json!({"op": "validate", "profile": profile.to_string()}));
    assert_eq!(validated["ok"], true, "{validated}");
    assert_eq!(validated["trustClass"], "contributed");
    assert_eq!(validated["profileMode"], "unknown");
    assert_eq!(validated["tools"], 7);
    assert_eq!(validated["otherTools"], json!(["frobnicate"]));
    assert_eq!(validated["firstPartyOverlap"], json!([]));
}

#[test]
fn generate_reads_a_bare_array_and_a_json_rpc_result() {
    let tools = json!([{"name": "page_navigate"}]);
    for document in [tools.clone(), json!({"result": {"tools": tools}})] {
        let mut request = generate_request();
        request["document"] = json!(document.to_string());
        assert_eq!(run(request)["ok"], true);
    }
}

#[test]
fn generate_refuses_missing_flags_and_reserved_names() {
    for (field, code) in [
        ("slug", "slug_missing"),
        ("server", "server_missing"),
        ("document", "document_missing"),
    ] {
        let mut request = generate_request();
        request.as_object_mut().unwrap().remove(field);
        assert_eq!(run(request)["error"]["code"], code);
    }
    let mut request = generate_request();
    request["document"] = json!("{\"tools\": [{\"name\": \"Upper\"}]}");
    assert_eq!(run(request)["error"]["code"], "tools_empty");
    let mut request = generate_request();
    request["server"] = json!("playwright");
    assert_eq!(
        run(request)["error"]["code"],
        "browser_driver_reserved_name_claimed"
    );
}

#[test]
fn validate_reports_compiler_refusals_and_shipped_ids() {
    let result = run(json!({"op": "validate", "profile": "{}"}));
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "browser_driver_json_invalid");

    let mut profile = run(generate_request())["profile"].clone();
    profile["publisher"]["verified"] = json!(true);
    let result = run(json!({"op": "validate", "profile": profile.to_string()}));
    assert_eq!(
        result["error"]["code"],
        "browser_driver_publisher_verification_unproven"
    );

    let mut profile = run(generate_request())["profile"].clone();
    profile["id"] = json!("browser.browsermcp");
    let result = run(json!({"op": "validate", "profile": profile.to_string()}));
    assert_eq!(result["error"]["code"], "browser_driver_id_duplicate");
}

#[test]
fn validate_names_a_first_party_identity_overlap() {
    let mut request = generate_request();
    request["server"] = json!("browsermcp");
    let profile = run(request)["profile"].clone();
    let result = run(json!({"op": "validate", "profile": profile.to_string()}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["firstPartyOverlap"], json!(["browser.browsermcp"]));
}

#[test]
fn unknown_ops_and_bad_requests_are_refused() {
    assert_eq!(run_command(b"not json")["error"]["code"], "request_invalid");
    assert_eq!(run(json!({"op": "apply"}))["error"]["code"], "op_invalid");
}
