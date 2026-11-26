use rusqlite::{params, Connection};
use serde_json::{json, Value};

use super::run_command;
use crate::local_store_read::STORE_FILE_NAME;

fn store(home: &std::path::Path) -> Connection {
    let connection = Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    connection
        .execute_batch(
            "create table approval_requests (request_id text primary key, harness text, \
             action_envelope_json text, decision_v2_json text, risk_signals_json text)",
        )
        .unwrap();
    connection
}

fn insert(connection: &Connection, request_id: &str, envelope: Value, decision: Value) {
    connection
        .execute(
            "insert into approval_requests values (?1, 'claude-code', ?2, ?3, ?4)",
            params![
                request_id,
                envelope.to_string(),
                decision.to_string(),
                json!([{"signal_id": "browser.unknown_origin", "title": "Opened shop.example.test"}])
                    .to_string()
            ],
        )
        .unwrap();
}

fn hook_envelope(tool: &str, input: Value) -> Value {
    json!({
        "action_type": "mcp_tool",
        "tool_name": format!("mcp__playwright__{tool}"),
        "raw_payload_redacted": {"tool_name": format!("mcp__playwright__{tool}"), "tool_input": input},
    })
}

fn report(home: &std::path::Path, request_id: &str) -> Value {
    let request = json!({"guard_home": home.to_str().unwrap(), "request_id": request_id});
    run_command(request.to_string().as_bytes())
}

/// Every leaf of the argument skeleton is a placeholder.
fn assert_placeholders(value: &Value) {
    match value {
        Value::Object(fields) => fields.values().for_each(assert_placeholders),
        Value::Array(items) => items.iter().for_each(assert_placeholders),
        Value::String(text) => assert!(
            text.starts_with('<') && text.ends_with('>')
                || text.starts_with("https://site-")
                || text.starts_with("http://site-"),
            "{text}"
        ),
        other => panic!("not a placeholder: {other}"),
    }
}

#[test]
fn a_navigation_becomes_a_skeleton_on_site_a() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-1",
        hook_envelope(
            "browser_navigate",
            json!({"url": "https://shop.example.com/cart?item=42"}),
        ),
        json!({"signals": [{"signal_id": "browser.first_visit", "plain_reason": "shop.example.com is new"}]}),
    );
    let reply = report(home.path(), "req-1");
    assert_eq!(reply["ok"], true, "{reply}");
    let skeleton = &reply["skeleton"];
    assert_eq!(skeleton["driver"], "browser.playwright-mcp");
    assert_eq!(skeleton["tool"], "browser_navigate");
    assert_eq!(skeleton["verb"], "navigate");
    assert_eq!(
        skeleton["origin"]["placeholder"],
        "https://site-a.example.test/"
    );
    assert_eq!(skeleton["origin"]["loopback"], false);
    assert_eq!(
        skeleton["arguments"],
        json!({"url": "https://site-a.example.test/"})
    );
    assert_eq!(
        skeleton["reason_codes"],
        json!(["browser.first_visit", "browser.unknown_origin"])
    );
    assert!(skeleton.get("profile_mode").is_some());
    let text = reply.to_string();
    assert!(!text.contains("shop.example.com"));
    assert!(!text.contains("cart"));
    assert!(!text.contains("42"));
}

#[test]
fn typed_text_and_form_fields_are_placeholders() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-type",
        hook_envelope(
            "browser_type",
            json!({"element": "Search box", "ref": "e12", "text": "blue shoes", "submit": true, "slowly": false}),
        ),
        json!({}),
    );
    insert(
        &connection,
        "req-form",
        hook_envelope(
            "browser_fill_form",
            json!({"fields": [
                {"name": "Email", "type": "textbox", "ref": "e1", "value": "someone@example.com"},
                {"name": "Next page", "type": "textbox", "ref": "e2", "value": "http://localhost:3000/next"},
                {"name": "Back", "type": "textbox", "ref": "e3", "value": "https://shop.example.com/"},
            ], "Odd Key With Spaces": 3}),
        ),
        json!({}),
    );
    let typed = report(home.path(), "req-type");
    assert_eq!(typed["ok"], true, "{typed}");
    assert_eq!(
        typed["skeleton"]["arguments"],
        json!({"element": "<text>", "ref": "<text>", "text": "<text>", "submit": "<boolean>", "slowly": "<boolean>"})
    );
    assert!(!typed.to_string().contains("blue shoes"));

    let form = report(home.path(), "req-form");
    assert_eq!(form["ok"], true, "{form}");
    let arguments = &form["skeleton"]["arguments"];
    assert_placeholders(arguments);
    assert_eq!(
        arguments["fields"][1]["value"],
        "http://site-a.example.test/"
    );
    assert_eq!(
        arguments["fields"][2]["value"],
        "https://site-b.example.test/"
    );
    assert!(arguments.get("Odd Key With Spaces").is_none());
    let text = form.to_string();
    for private in [
        "someone@example.com",
        "Email",
        "localhost",
        "shop.example.com",
        "Odd Key",
    ] {
        assert!(!text.contains(private), "{private}");
    }
}

#[test]
fn a_loopback_site_is_marked_but_not_named() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-local",
        hook_envelope(
            "browser_navigate",
            json!({"url": "http://127.0.0.1:5173/items/7"}),
        ),
        json!({}),
    );
    let reply = report(home.path(), "req-local");
    assert_eq!(
        reply["skeleton"]["origin"]["placeholder"],
        "http://site-a.example.test/"
    );
    assert_eq!(reply["skeleton"]["origin"]["loopback"], true);
    assert!(!reply.to_string().contains("5173"));
}

#[test]
fn a_tool_the_driver_does_not_list_is_reported_as_unclassified() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-unknown",
        hook_envelope("browser_frobnicate", json!({"level": 3})),
        json!({}),
    );
    let reply = report(home.path(), "req-unknown");
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["skeleton"]["driver"], "browser.playwright-mcp");
    assert_eq!(reply["skeleton"]["tool"], "browser_frobnicate");
    assert_eq!(reply["skeleton"]["unclassified"], "tool_not_listed");
    assert_eq!(
        reply["skeleton"]["arguments"],
        json!({"<key-1>": "<number>"})
    );
}

#[test]
fn a_data_defined_key_is_replaced_even_when_it_looks_like_a_field_name() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-listed",
        hook_envelope(
            "browser_type",
            json!({"element": "Search box", "text": "x", "customer_alice": 3, "nested": {"account_bob": true}}),
        ),
        json!({}),
    );
    insert(
        &connection,
        "req-unlisted",
        hook_envelope(
            "browser_frobnicate",
            json!({"customer_alice": 3, "url": "https://shop.example.com/"}),
        ),
        json!({}),
    );
    let listed = report(home.path(), "req-listed");
    assert_eq!(listed["ok"], true, "{listed}");
    let arguments = &listed["skeleton"]["arguments"];
    assert_eq!(arguments["element"], "<text>");
    assert_eq!(arguments["text"], "<text>");
    assert_placeholders(arguments);
    let unlisted = report(home.path(), "req-unlisted");
    assert_eq!(unlisted["ok"], true, "{unlisted}");
    assert_eq!(
        unlisted["skeleton"]["arguments"],
        json!({"<key-1>": "<number>", "<key-2>": "https://site-a.example.test/"})
    );
    for reply in [&listed, &unlisted] {
        let text = reply.to_string();
        for private in ["customer_alice", "account_bob", "nested"] {
            assert!(!text.contains(private), "{private}");
        }
    }
}

#[test]
fn reason_codes_skip_anything_that_is_not_a_plain_code() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-codes",
        hook_envelope("browser_navigate", json!({"url": "https://a.example.com/"})),
        json!({"signals": [
            {"signal_id": "Opened https://a.example.com/"},
            {"signal_id": "browser.sensitive_surface"},
            {"reason_code": "x".repeat(200)},
        ]}),
    );
    let reply = report(home.path(), "req-codes");
    assert_eq!(
        reply["skeleton"]["reason_codes"],
        json!(["browser.sensitive_surface", "browser.unknown_origin"])
    );
}

#[test]
fn other_approvals_and_bad_requests_are_refused() {
    let home = tempfile::tempdir().unwrap();
    let connection = store(home.path());
    insert(
        &connection,
        "req-shell",
        json!({"action_type": "shell", "tool_name": "Bash", "command": "ls"}),
        json!({}),
    );
    assert_eq!(
        report(home.path(), "req-shell")["error"]["code"],
        "not_a_browser_call"
    );
    assert_eq!(
        report(home.path(), "req-missing")["error"]["code"],
        "request_not_found"
    );
    assert_eq!(
        report(home.path(), "req 1; drop")["error"]["code"],
        "request_id_invalid"
    );
    let relative = json!({"guard_home": "relative/home", "request_id": "req-1"});
    assert_eq!(
        run_command(relative.to_string().as_bytes())["error"]["code"],
        "guard_home_invalid"
    );
    assert_eq!(run_command(b"{}")["error"]["code"], "request_invalid");
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        report(empty.path(), "req-1")["error"]["code"],
        "request_not_found"
    );
}
