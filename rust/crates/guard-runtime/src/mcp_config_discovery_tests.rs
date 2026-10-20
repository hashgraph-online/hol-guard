//! MCP servers that Claude Code and Oh My Pi keep outside the settings files
//! the recorded detection vectors cover (#5193): `claude mcp add` writes
//! `~/.claude.json`, and Oh My Pi reads `mcp.json` and `.mcp.json`.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;

fn write(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

fn servers(result: &Value) -> Vec<(String, String, String)> {
    result["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|artifact| artifact["artifact_type"] == "mcp_server")
        .map(|artifact| {
            (
                artifact["artifact_id"].as_str().unwrap().to_owned(),
                artifact["command"].as_str().unwrap_or_default().to_owned(),
                artifact["source_scope"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn found(result: &Value, path: &Path) -> bool {
    result["found_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|found| found == path.to_str().unwrap())
}

fn claude(home: &Path, workspace: Option<&Path>) -> Value {
    crate::claude_code_detect::detect(&json!({
        "harness": "claude-code",
        "home": home,
        "workspace": workspace,
    }))
    .expect("claude code detection")
}

fn pi(harness: &str, home: &Path, workspace: &Path) -> Value {
    crate::pi_detect::detect(&json!({
        "harness": harness,
        "home": home,
        "roots": [
            {"path": home.join(".omp/agent"), "scope": "global", "id_scope": format!("{harness}-global")},
            {"path": workspace.join(".omp"), "scope": "project", "id_scope": format!("{harness}-project")},
        ],
    }))
    .expect("pi detection")
}

#[test]
fn claude_code_reads_user_and_local_servers_from_its_state_file() {
    let root = temp_home("claude-state-mcp");
    let (home, workspace) = (root.join("home"), root.join("work"));
    fs::create_dir_all(&workspace).unwrap();
    let state = home.join(".claude.json");
    write(
        &state,
        &json!({
            "numStartups": 3,
            "mcpServers": {"truenas-pilot": {"type": "stdio", "command": "truenas-mcp", "args": ["--read"]}},
            "projects": {
                workspace.to_str().unwrap(): {"mcpServers": {"local-db": {"command": "db-mcp"}}},
                "/elsewhere": {"mcpServers": {"other": {"command": "other-mcp"}}},
            },
        }),
    );
    let result = claude(&home, Some(&workspace));
    assert_eq!(
        servers(&result),
        vec![
            (
                "claude-code:global:mcp:truenas-pilot".to_owned(),
                "truenas-mcp".to_owned(),
                "global".to_owned()
            ),
            (
                "claude-code:project:mcp:local-db".to_owned(),
                "db-mcp".to_owned(),
                "project".to_owned()
            ),
        ]
    );
    assert!(found(&result, &state));
    // Without a workspace only the user scope applies.
    assert_eq!(servers(&claude(&home, None)).len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn claude_code_state_without_servers_adds_nothing() {
    let root = temp_home("claude-state-empty");
    let home = root.join("home");
    let state = home.join(".claude.json");
    write(&state, &json!({"numStartups": 3, "projects": {}}));
    let result = claude(&home, None);
    assert!(servers(&result).is_empty());
    assert!(!found(&result, &state));
    // A settings file's server keeps its entry over the state file's.
    write(
        &home.join(".claude/settings.json"),
        &json!({"mcpServers": {"shared": {"command": "from-settings"}}}),
    );
    write(
        &state,
        &json!({"mcpServers": {"shared": {"command": "from-state"}}}),
    );
    assert_eq!(
        servers(&claude(&home, None)),
        vec![(
            "claude-code:global:mcp:shared".to_owned(),
            "from-settings".to_owned(),
            "global".to_owned()
        )]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn oh_my_pi_reads_mcp_json_in_its_agent_and_project_directories() {
    let root = temp_home("omp-mcp");
    let (home, workspace) = (root.join("home"), root.join("work"));
    let (agent_mcp, agent_dot_mcp, project_mcp) = (
        home.join(".omp/agent/mcp.json"),
        home.join(".omp/agent/.mcp.json"),
        workspace.join(".omp/mcp.json"),
    );
    write(
        &agent_mcp,
        &json!({"mcpServers": {
            "truenas-pilot": {"type": "stdio", "timeout": 60, "command": "truenas-mcp", "args": []},
            "shared": {"command": "first"},
        }}),
    );
    write(
        &agent_dot_mcp,
        &json!({"mcpServers": {"shared": {"command": "second"}, "extra": {"command": "extra-mcp"}}}),
    );
    write(
        &project_mcp,
        &json!({"mcpServers": {"repo-tools": {"command": "repo-mcp"}}}),
    );
    let result = pi("omp", &home, &workspace);
    let expected = [
        ("omp:omp-global:mcp:truenas-pilot", "truenas-mcp", "global"),
        ("omp:omp-global:mcp:shared", "first", "global"),
        ("omp:omp-global:mcp:extra", "extra-mcp", "global"),
        ("omp:omp-project:mcp:repo-tools", "repo-mcp", "project"),
    ];
    let mut actual = servers(&result);
    actual.sort();
    let mut expected: Vec<_> = expected
        .iter()
        .map(|(id, command, scope)| ((*id).to_owned(), (*command).to_owned(), (*scope).to_owned()))
        .collect();
    expected.sort();
    assert_eq!(actual, expected);
    for path in [&agent_mcp, &agent_dot_mcp, &project_mcp] {
        assert!(found(&result, path), "{}", path.display());
    }
    // Pi has no MCP support of its own, so the same files mean nothing to it.
    let result = pi("pi", &home, &workspace);
    assert!(servers(&result).is_empty());
    assert!(!found(&result, &agent_mcp));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_unreadable_optional_file_lists_no_servers_and_hides_nothing() {
    let root = temp_home("mcp-undecodable");
    let (home, workspace) = (root.join("home"), root.join("work"));
    // Claude Code: a state file that is not UTF-8 keeps the settings servers.
    write(
        &home.join(".claude/settings.json"),
        &json!({"mcpServers": {"kept": {"command": "kept-mcp"}}}),
    );
    fs::write(home.join(".claude.json"), b"{\"mcpServers\": \xff}").unwrap();
    assert_eq!(
        servers(&claude(&home, None)),
        vec![(
            "claude-code:global:mcp:kept".to_owned(),
            "kept-mcp".to_owned(),
            "global".to_owned()
        )]
    );
    // Oh My Pi: an undecodable `mcp.json` still lets `.mcp.json` and the
    // extensions beside it through.
    let agent = home.join(".omp/agent");
    fs::create_dir_all(&agent).unwrap();
    fs::write(agent.join("mcp.json"), b"\xff\xfe").unwrap();
    write(
        &agent.join(".mcp.json"),
        &json!({"mcpServers": {"extra": {"command": "extra-mcp"}}}),
    );
    fs::create_dir_all(agent.join("extensions")).unwrap();
    fs::write(agent.join("extensions/tool.ts"), "export default {};\n").unwrap();
    let result = pi("omp", &home, &workspace);
    assert_eq!(
        servers(&result),
        vec![(
            "omp:omp-global:mcp:extra".to_owned(),
            "extra-mcp".to_owned(),
            "global".to_owned()
        )]
    );
    assert!(result["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["artifact_type"] == "extension"));
    assert!(!found(&result, &agent.join("mcp.json")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_relative_workspace_finds_its_local_servers() {
    let root = temp_home("claude-state-relative");
    let home = root.join("home");
    fs::create_dir_all(root.join("work")).unwrap();
    write(
        &home.join(".claude.json"),
        &json!({"projects": {
            root.join("work").to_str().unwrap(): {"mcpServers": {"local-db": {"command": "db-mcp"}}},
        }}),
    );
    let result = crate::claude_code_detect::detect(&json!({
        "harness": "claude-code",
        "home": home,
        "workspace": "work",
        "cwd": root,
    }))
    .expect("claude code detection");
    assert_eq!(
        servers(&result),
        vec![(
            "claude-code:project:mcp:local-db".to_owned(),
            "db-mcp".to_owned(),
            "project".to_owned()
        )]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn server_ids_carry_the_mcp_family_policy_scopes_recognize() {
    let root = temp_home("mcp-family");
    let (home, workspace) = (root.join("home"), root.join("work"));
    write(
        &home.join(".omp/agent/mcp.json"),
        &json!({"mcpServers": {"truenas-pilot": {"command": "truenas-mcp"}}}),
    );
    write(
        &home.join(".claude.json"),
        &json!({"mcpServers": {"truenas-pilot": {"command": "truenas-mcp"}}}),
    );
    for (id, _, _) in servers(&pi("omp", &home, &workspace))
        .into_iter()
        .chain(servers(&claude(&home, None)))
    {
        // `artifact_family_key` reads the third segment as the family.
        assert_eq!(id.split(':').nth(2), Some("mcp"), "{id}");
    }
    fs::remove_dir_all(root).unwrap();
}
