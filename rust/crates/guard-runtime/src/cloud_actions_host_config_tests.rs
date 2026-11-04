use serde_json::{json, Value};

use super::*;

const URL: &str = "https://hol.org/api/guard/gateway/mcp";
const CANARY: &str = "sk-test-CANARY-7f3a9c";
const COMMAND: &str = "/opt/guard/bin/hol-guard";

// Guard Local's own proxy entry, as `hol-guard install codex` writes it.
const CODEX_SETTINGS: &str = r#"# Hand-written; keep this comment.
model = "gpt-5"
approval_policy = "on-request"  # trailing comment

[features]
codex_hooks = true

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "CANARY" }

[mcp_servers."hol-guard::filesystem"]
command = "/opt/hol-guard/bin/hol-guard"
args = ["codex-mcp-proxy", "--server", "filesystem", "--transport", "stdio"]

[profiles.fast]
model = "gpt-5-mini"
"#;

fn codex_settings() -> String {
    CODEX_SETTINGS.replace("\"CANARY\"", &format!("\"{CANARY}\""))
}

fn cursor_settings() -> String {
    let settings = json!({
        "mcpServers": {
            "hol-guard::filesystem": {"command": "/opt/hol-guard/bin/hol-guard", "args": ["cursor-mcp-proxy"]},
            "notion": {"url": "https://mcp.notion.example/mcp"},
            "db": {"command": "pg-mcp", "env": {"PGPASSWORD": CANARY}},
        }
    });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&settings).expect("settings")
    )
}

fn bridge(ai_tool: &str) -> Value {
    json!({
        "command": COMMAND,
        "args": ["cloud-actions", "bridge", ai_tool, "--guard-home", "/home/u/.hol-guard"],
    })
}

fn wanted(ai_tool: &str) -> Value {
    let mut entry = bridge(ai_tool);
    if ai_tool == "claude-code" {
        entry["type"] = json!("stdio");
    }
    entry
}

fn table(ai_tool: &str) -> &'static str {
    tool(ai_tool).expect("tool").table
}

fn plan_of(ai_tool: &str, before: Option<&str>, entry: Value) -> Value {
    answer(json!({"op": "plan", "ai_tool": ai_tool, "before": before, "entry": entry, "url": URL}))
        .expect("answer")
}

fn undo_of(ai_tool: &str, current: &str, written: Value, prior: Option<&str>) -> Value {
    answer(json!({
        "op": "undo", "ai_tool": ai_tool, "current": current, "written": written, "prior": prior,
    }))
    .expect("answer")
}

fn after(plan: &Value) -> &str {
    plan["after"].as_str().expect("after")
}

fn read(ai_tool: &str, text: &str) -> Map<String, Value> {
    document(tool(ai_tool).expect("tool"), text).expect("document")
}

fn without_guard(ai_tool: &str, text: &str) -> Map<String, Value> {
    without_guard_entry(tool(ai_tool).expect("tool"), &read(ai_tool, text))
}

fn seeded(ai_tool: &str) -> String {
    match ai_tool {
        "codex" => codex_settings(),
        "cursor" => cursor_settings(),
        _ => format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({
                "numStartups": 42,
                "projects": {"/work/app": {"mcpServers": {"local": {"command": "node"}}}},
                "mcpServers": {"db": {"command": "pg-mcp", "env": {"PGPASSWORD": CANARY}}},
            }))
            .expect("settings")
        ),
    }
}

#[test]
fn a_plan_adds_only_the_guard_entry() {
    for ai_tool in ["claude-code", "codex", "cursor"] {
        let before = seeded(ai_tool);
        let plan = plan_of(ai_tool, Some(&before), bridge(ai_tool));
        assert_eq!(plan["action"], "add", "{ai_tool}");
        let servers = read(ai_tool, &before)[table(ai_tool)]
            .as_object()
            .expect("servers")
            .len();
        assert_eq!(plan["other_entries"], json!(servers));
        let written = read(ai_tool, after(&plan));
        assert_eq!(written[table(ai_tool)][SERVER_NAME], wanted(ai_tool));
        assert_eq!(
            without_guard(ai_tool, after(&plan)),
            without_guard(ai_tool, &before)
        );
        // Planning the planned file again changes nothing.
        let again = plan_of(ai_tool, Some(after(&plan)), bridge(ai_tool));
        assert_eq!(again["action"], "unchanged", "{ai_tool}");
        assert_eq!(again["after"], Value::Null);
    }
}

#[test]
fn a_codex_plan_keeps_every_line_and_comment() {
    let before = codex_settings();
    let plan = plan_of("codex", Some(&before), bridge("codex"));
    let block = format!(
        "[mcp_servers.{SERVER_NAME}]\ncommand = \"{COMMAND}\"\n\
         args = [\"cloud-actions\", \"bridge\", \"codex\", \"--guard-home\", \"/home/u/.hol-guard\"]\n\n"
    );
    assert_eq!(
        after(&plan),
        before.replace("[profiles.fast]", &format!("{block}[profiles.fast]"))
    );
}

#[test]
fn a_codex_plan_appends_after_the_last_line() {
    let plan = plan_of("codex", Some("model = \"gpt-5\"\n"), bridge("codex"));
    assert!(after(&plan).starts_with("model = \"gpt-5\"\n\n[mcp_servers."));
    assert_eq!(
        Value::Object(read("codex", after(&plan))),
        json!({"model": "gpt-5", "mcp_servers": {SERVER_NAME: bridge("codex")}})
    );
}

#[test]
fn a_codex_plan_keeps_inline_and_dotted_server_tables() {
    for before in [
        "mcp_servers = { github = { command = \"npx\" } }\n",
        "mcp_servers.github.command = \"npx\"\n",
    ] {
        let plan = plan_of("codex", Some(before), bridge("codex"));
        assert_eq!(plan["action"], "add", "{before}");
        assert_eq!(
            Value::Object(read("codex", after(&plan))),
            json!({"mcp_servers": {"github": {"command": "npx"}, SERVER_NAME: bridge("codex")}})
        );
    }
}

#[test]
fn a_json_plan_keeps_indentation_line_endings_and_key_order() {
    let before = "{\r\n    \"zeta\": 1,\r\n    \"mcpServers\": {\r\n        \"db\": {\r\n            \
                  \"command\": \"pg\"\r\n        }\r\n    },\r\n    \"alpha\": [],\r\n    \"name\": \"caf\u{e9}\"\r\n}\r\n";
    let plan = plan_of("cursor", Some(before), json!({"url": URL}));
    assert_eq!(
        after(&plan),
        format!(
            "{{\r\n    \"zeta\": 1,\r\n    \"mcpServers\": {{\r\n        \"db\": {{\r\n            \
             \"command\": \"pg\"\r\n        }},\r\n        \"{SERVER_NAME}\": {{\r\n            \
             \"url\": \"{URL}\"\r\n        }}\r\n    }},\r\n    \"alpha\": [],\r\n    \"name\": \"caf\u{e9}\"\r\n}}\r\n"
        )
    );
    let tabbed = plan_of("cursor", Some("{\n\t\"a\": 1\n}"), json!({"url": URL}));
    assert_eq!(
        after(&tabbed),
        format!("{{\n\t\"a\": 1,\n\t\"mcpServers\": {{\n\t\t\"{SERVER_NAME}\": {{\n\t\t\t\"url\": \"{URL}\"\n\t\t}}\n\t}}\n}}")
    );
}

#[test]
fn a_missing_file_is_created_with_only_the_guard_entry() {
    for ai_tool in ["claude-code", "codex", "cursor"] {
        let plan = plan_of(ai_tool, None, bridge(ai_tool));
        assert_eq!(plan["action"], "create_file");
        assert_eq!(
            Value::Object(read(ai_tool, after(&plan))),
            json!({table(ai_tool): {SERVER_NAME: wanted(ai_tool)}})
        );
    }
    let created = plan_of("cursor", None, json!({"url": URL}));
    assert_eq!(
        after(&created),
        format!("{{\n  \"mcpServers\": {{\n    \"{SERVER_NAME}\": {{\n      \"url\": \"{URL}\"\n    }}\n  }}\n}}\n")
    );
}

#[test]
fn an_update_shows_the_old_address_without_its_secrets() {
    let old = "https://registry-staging.hol.org/api/guard/gateway/mcp?k=qs-CANARY-90d2";
    let before =
        json!({"mcpServers": {SERVER_NAME: {"type": "http", "url": old}, "db": {"command": "x"}}});
    let plan = plan_of(
        "claude-code",
        Some(&before.to_string()),
        bridge("claude-code"),
    );
    assert_eq!(plan["action"], "update");
    assert_eq!(plan["other_entries"], 1);
    assert_eq!(
        plan["previous_url"],
        "https://registry-staging.hol.org/api/guard/gateway/mcp"
    );
    let bad_port = json!({"mcpServers": {SERVER_NAME: {"url": "https://hol.org:99999/mcp"}}});
    let plan = plan_of("cursor", Some(&bad_port.to_string()), bridge("cursor"));
    assert_eq!(plan["action"], "update");
    assert_eq!(plan["previous_url"], Value::Null);
}

#[test]
fn an_earlier_address_only_entry_is_replaced_with_the_bridge() {
    let before = format!("[mcp_servers.{SERVER_NAME}]\nurl = \"{URL}\"\n");
    let plan = plan_of("codex", Some(&before), bridge("codex"));
    assert_eq!(plan["action"], "update");
    assert_eq!(
        Value::Object(read("codex", after(&plan))),
        json!({"mcp_servers": {SERVER_NAME: bridge("codex")}})
    );
}

#[test]
fn another_entry_for_the_same_server_is_reported_not_duplicated() {
    let trailing = json!({"mcpServers": {"guard": {"url": format!("{URL}/")}}});
    let plan = plan_of("cursor", Some(&trailing.to_string()), bridge("cursor"));
    assert_eq!(plan["action"], "already_configured");
    assert_eq!(plan["configured_as"], json!(["guard"]));
    let staging = "https://registry-staging.hol.org/api/guard/gateway/mcp";
    let both = json!({"mcpServers": {SERVER_NAME: {"url": staging}, "zed": {"url": URL}, "guard": {"url": URL}}});
    let plan = plan_of("cursor", Some(&both.to_string()), bridge("cursor"));
    assert_eq!(plan["action"], "already_configured");
    assert_eq!(plan["configured_as"], json!(["guard", "zed"]));
}

#[test]
fn an_entry_with_guards_name_but_other_settings_is_never_replaced() {
    for entry in [
        json!({"type": "http", "url": URL, "headers": {"Authorization": CANARY}}),
        json!({"command": "evil", "env": {"K": CANARY}}),
        json!({"type": "sse", "url": URL}),
        json!("not a table"),
    ] {
        let before = json!({"mcpServers": {SERVER_NAME: entry}}).to_string();
        let plan = plan_of("claude-code", Some(&before), bridge("claude-code"));
        assert_eq!(plan["action"], "conflict", "{entry}");
        assert!(!plan.to_string().contains(CANARY));
    }
    // A bridge for another AI tool is not Guard's entry for this one.
    let other = json!({"mcpServers": {SERVER_NAME: bridge("codex")}}).to_string();
    assert_eq!(
        plan_of("cursor", Some(&other), bridge("cursor"))["action"],
        "conflict"
    );
}

#[test]
fn unreadable_settings_are_left_alone_and_not_echoed() {
    let not_table = "mcpServers in the settings file is not a table of servers.".to_owned();
    let cases = [
        ("cursor", "{\"mcpServers\": {".to_owned(), NOT_JSON),
        (
            "cursor",
            format!("{{\"mcpServers\": {{}}, \"mcpServers\": {{\"db\": {{\"env\": {{\"K\": \"{CANARY}\"}}}}}}}}"),
            REPEATED_KEY,
        ),
        ("cursor", "[1, 2]".to_owned(), NOT_OBJECT),
        ("cursor", format!("{{\"mcpServers\": [\"{CANARY}\"]}}"), not_table.as_str()),
        ("claude-code", "\u{feff}{\"a\": 1}".to_owned(), NOT_JSON),
        (
            "codex",
            format!("mcp_servers = \"{CANARY}\"\n"),
            "mcp_servers in the settings file is not a table of servers.",
        ),
        ("codex", format!("key = \"{CANARY}\n"), NOT_TOML),
        ("codex", "\u{feff}model = \"gpt-5\"\n".to_owned(), NOT_TOML),
        (
            "cursor",
            format!("{{\"mcpServers\": {{\"db\": {{\"env\": {{\"K\": \"{CANARY}\"}}}}}}, \"note\": \"\\ud800\"}}"),
            UNWRITABLE_TEXT,
        ),
    ];
    for (ai_tool, before, problem) in cases {
        let plan = plan_of(ai_tool, Some(&before), bridge(ai_tool));
        assert_eq!(plan["action"], "unreadable", "{before}");
        assert_eq!(plan["problem"], problem, "{before}");
        assert_eq!(plan["after"], Value::Null);
        assert!(!plan.to_string().contains(CANARY));
    }
}

#[test]
fn a_rendering_that_changes_another_entry_is_refused() {
    for ai_tool in ["claude-code", "codex", "cursor"] {
        let tool = tool(ai_tool).expect("tool");
        let before = seeded(ai_tool);
        let fields = Fields::from_request(&bridge(ai_tool)).expect("fields");
        let lossy = render_edit(tool, &before.replace(CANARY, "changed"), &fields).expect("render");
        assert_eq!(
            check_only_changed(tool, &read(ai_tool, &before), &lossy, &fields),
            Err(EDIT_ERROR.to_owned())
        );
        let honest = render_edit(tool, &before, &fields).expect("render");
        assert_eq!(
            check_only_changed(tool, &read(ai_tool, &before), &honest, &fields),
            Ok(())
        );
    }
}

#[test]
fn an_undo_removes_the_entry_guard_added() {
    for (ai_tool, before) in [
        ("codex", codex_settings()),
        ("cursor", cursor_settings()),
        ("claude-code", "{\n  \"a\": 1\n}\n".to_owned()),
    ] {
        let current = after(&plan_of(ai_tool, Some(&before), bridge(ai_tool))).to_owned();
        let undone = undo_of(ai_tool, &current, bridge(ai_tool), Some(&before));
        assert_eq!(undone["removed"], true, "{ai_tool}");
        assert_eq!(undone["after"], before.as_str(), "{ai_tool}");
    }
    // A table Guard created goes again; one that was there stays, empty.
    let created = after(&plan_of("cursor", None, bridge("cursor"))).to_owned();
    let undone = undo_of("cursor", &created, bridge("cursor"), None);
    assert_eq!(undone["after"], "{}\n");
    let empty = "{\n  \"mcpServers\": {}\n}\n";
    let current = after(&plan_of("cursor", Some(empty), bridge("cursor"))).to_owned();
    assert_eq!(
        undo_of("cursor", &current, bridge("cursor"), Some(empty))["after"],
        empty
    );
}

#[test]
fn an_undo_keeps_what_changed_since_and_puts_back_an_earlier_entry() {
    let prior = json!({"mcpServers": {SERVER_NAME: {"url": URL}}}).to_string();
    let current = after(&plan_of("cursor", Some(&prior), bridge("cursor"))).to_owned();
    let edited = current.replacen('{', "{\"added\": true, ", 1);
    let undone = undo_of("cursor", &edited, bridge("cursor"), Some(&prior));
    assert_eq!(undone["removed"], false);
    assert_eq!(
        Value::Object(read("cursor", undone["after"].as_str().expect("after"))),
        json!({"added": true, "mcpServers": {SERVER_NAME: {"url": URL}}})
    );
}

#[test]
fn an_undo_refuses_an_entry_changed_after_guard_wrote_it() {
    let current = after(&plan_of("cursor", None, bridge("cursor"))).to_owned();
    let changed = current.replace("--guard-home", "--other");
    assert_eq!(
        undo_of("cursor", &changed, bridge("cursor"), None),
        json!({"problem": format!("The {SERVER_NAME} entry changed after Guard wrote it.")})
    );
    let not_guards = json!({"mcpServers": {SERVER_NAME: {"command": "evil"}}}).to_string();
    assert_eq!(
        undo_of("cursor", &current, bridge("cursor"), Some(&not_guards)),
        json!({"problem": format!("The earlier {SERVER_NAME} entry was not one Guard wrote.")})
    );
    assert_eq!(
        undo_of("cursor", "{", bridge("cursor"), None),
        json!({"problem": NOT_JSON})
    );
}

#[test]
fn only_a_well_formed_request_is_answered() {
    let plan = json!({"op": "plan", "ai_tool": "cursor", "before": null, "entry": {"url": URL}, "url": URL});
    assert!(answer(plan.clone()).is_some());
    let mut extra = plan.clone();
    extra["extra"] = json!(1);
    let mut windsurf = plan.clone();
    windsurf["ai_tool"] = json!("windsurf");
    let mut odd_entry = plan.clone();
    odd_entry["entry"] = json!({"url": URL, "headers": {}});
    let mut unknown = plan;
    unknown["op"] = json!("write");
    for request in [extra, windsurf, odd_entry, unknown, json!([]), json!({})] {
        assert_eq!(answer(request.clone()), None, "{request}");
    }
    assert_eq!(
        run_command(&b"not json"[..]),
        Err("cloud_actions_host_config_request_invalid".to_owned())
    );
    let answered = run_command(
        serde_json::to_vec(&json!({
            "op": "plan", "ai_tool": "codex", "before": null, "entry": bridge("codex"), "url": URL,
        }))
        .expect("request")
        .as_slice(),
    )
    .expect("answer");
    let answered: Value = serde_json::from_slice(&answered).expect("json");
    assert_eq!(answered["action"], "create_file");
}

#[test]
fn an_address_is_shown_as_python_splits_it() {
    for (value, shown) in [
        (
            "https://user:pw@[::1]:8443/api/guard/gateway/mcp#frag",
            Some("https://[::1]:8443/api/guard/gateway/mcp"),
        ),
        ("https://hol.org:99999/api/guard/gateway/mcp", None),
        ("https://hol.org:x/mcp", None),
        ("HTTPS://Hol.ORG:0443/a?b=c", Some("https://hol.org:443/a")),
        ("https://[::1/mcp", None),
        ("https://[zz::1]/mcp", None),
        ("https://x[::1]/mcp", None),
        (
            "https://[fe80::1%25eth0]/mcp",
            Some("https://[fe80::1%25eth0]/mcp"),
        ),
        ("relative/path?q=1", Some("relative/path")),
    ] {
        assert_eq!(display_url(value).as_deref(), shown, "{value}");
    }
}
