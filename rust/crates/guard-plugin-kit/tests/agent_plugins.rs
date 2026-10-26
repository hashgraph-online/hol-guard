//! Agent Plugins 1.0 conformance: each rule of the specification that the
//! check enforces fails on a plugin that breaks it, a conforming plugin
//! passes, and a package converted to Agent Plugins passes the check.
//!
//! Some cases adapt the examples in the Agent Plugins Specification 1.0.0
//! (https://github.com/agentplugins/agent-plugins-spec, CC-BY-4.0).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

const PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn repo(files: &[(&str, &str)]) -> PathBuf {
    let parent = std::env::temp_dir().join(format!(
        "guard-plugin-kit-ap-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&parent);
    let root = parent.join("repo");
    fs::create_dir_all(&root).expect("repo");
    for (path, content) in files {
        let target = root.join(path);
        fs::create_dir_all(target.parent().expect("parent")).expect("dirs");
        fs::write(target, content).expect("write");
    }
    root.canonicalize().expect("canonical")
}

fn call(request: Value) -> Value {
    guard_plugin_kit::run_request(request.to_string().as_bytes())
}

fn conformance(root: &Path, strict: bool) -> Value {
    let response = call(json!({
        "command": "conformance",
        "root": root.to_str().expect("utf-8 path"),
        "spec": "agent-plugins-1.0",
        "strict": strict,
    }));
    assert_eq!(response["ok"], json!(true), "{response}");
    response["result"].clone()
}

fn codes(result: &Value) -> Vec<String> {
    result["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|finding| finding["code"].as_str().expect("code").to_owned())
        .collect()
}

fn manifest(extra: Value) -> String {
    let mut manifest = json!({"$schema": PLUGIN_SCHEMA, "name": "pdf-tools", "version": "1.0.0"});
    manifest
        .as_object_mut()
        .expect("object")
        .extend(extra.as_object().expect("object").clone());
    manifest.to_string()
}

fn mcp(servers: Value) -> String {
    json!({"$schema": MCP_SCHEMA, "mcpServers": servers}).to_string()
}

const SKILL: &str =
    "---\nname: fill-forms\ndescription: Fill PDF forms from structured data.\n---\n\nSteps.\n";

#[test]
fn a_minimal_plugin_conforms() {
    let root = repo(&[(
        "plugin.json",
        &json!({"$schema": PLUGIN_SCHEMA, "name": "hello"}).to_string(),
    )]);
    let result = conformance(&root, true);
    assert_eq!(result["passed"], json!(true), "{result}");
    assert_eq!(result["spec"], json!("agent-plugins-1.0"));
    assert_eq!(result["plugin"]["name"], json!("hello"));
}

#[test]
fn a_full_plugin_conforms() {
    let root = repo(&[
        (
            "plugin.json",
            &manifest(json!({
                "description": "Fill PDF forms.",
                "author": {"name": "Acme Labs", "url": "https://acme.example"},
                "homepage": "https://acme.example/pdf-tools",
                "repository": "https://github.com/acme/pdf-tools",
                "license": "MIT",
                "keywords": ["pdf"],
                "extensions": {"com.acme": {"tier": "free"}},
            })),
        ),
        ("skills/fill-forms/SKILL.md", SKILL),
        (
            "mcp.json",
            &mcp(json!({
                "local": {
                    "type": "stdio",
                    "command": "./bin/server",
                    "args": ["--data", "${PLUGIN_DATA}"],
                    "env": {"LOG_LEVEL": "info"},
                    "cwd": "${PLUGIN_ROOT}",
                },
                "remote": {"type": "streamable-http", "url": "https://mcp.acme.example/pdf"},
                "dev": {"type": "sse", "url": "http://127.0.0.1:8080/sse"},
            })),
        ),
        ("bin/server", "#!/bin/sh\n"),
    ]);
    let result = conformance(&root, false);
    assert_eq!(result["passed"], json!(true), "{result}");
    assert_eq!(result["summary"]["errors"], json!(0), "{result}");
    assert_eq!(
        result["components"]["skills"],
        json!(["fill-forms"]),
        "{result}"
    );
    assert_eq!(
        result["components"]["mcp_servers"],
        json!(["dev", "local", "remote"]),
        "{result}"
    );
    // SSE is deprecated in MCP, so it is a warning and fails only --strict.
    assert!(codes(&result).contains(&"mcp_sse_deprecated".to_owned()));
    assert_eq!(conformance(&root, true)["passed"], json!(false));
}

#[test]
fn each_broken_rule_fails_the_check() {
    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        ("manifest_missing", vec![("README.md", "# x".into())]),
        ("manifest_invalid_json", vec![("plugin.json", "{".into())]),
        (
            "schema_missing",
            vec![("plugin.json", json!({"name": "pdf-tools"}).to_string())],
        ),
        (
            "spec_version_unsupported",
            vec![(
                "plugin.json",
                json!({
                    "$schema": "https://agent-plugins.org/schemas/2.0.0/plugin.schema.json",
                    "name": "pdf-tools",
                })
                .to_string(),
            )],
        ),
        (
            "name_invalid",
            vec![("plugin.json", manifest(json!({"name": "PDF--Tools"})))],
        ),
        (
            "manifest_unknown_field",
            vec![("plugin.json", manifest(json!({"mcpServers": {}})))],
        ),
        (
            "author_invalid",
            vec![("plugin.json", manifest(json!({"author": "Acme"})))],
        ),
        (
            "skill_name_mismatch",
            vec![
                ("plugin.json", manifest(json!({}))),
                ("skills/forms/SKILL.md", SKILL.into()),
            ],
        ),
        (
            "skill_description_invalid",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "skills/fill-forms/SKILL.md",
                    "---\nname: fill-forms\n---\n".into(),
                ),
            ],
        ),
        (
            "mcp_command_not_single_token",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {"type": "stdio", "command": "npx -y @acme/pdf-mcp"}})),
                ),
            ],
        ),
        (
            "mcp_command_path_invalid",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {"type": "stdio", "command": "/usr/bin/pdf"}})),
                ),
            ],
        ),
        (
            "mcp_command_outside_root",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {"type": "stdio", "command": "./../pdf"}})),
                ),
            ],
        ),
        (
            "mcp_env_reserved",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(
                        json!({"pdf": {"type": "stdio", "command": "pdf", "env": {"PLUGIN_ROOT": "/tmp"}}}),
                    ),
                ),
            ],
        ),
        (
            "mcp_cwd_invalid",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {"type": "stdio", "command": "pdf", "cwd": "/tmp"}})),
                ),
            ],
        ),
        (
            "mcp_url_invalid",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(
                        json!({"pdf": {"type": "streamable-http", "url": "http://mcp.acme.example"}}),
                    ),
                ),
            ],
        ),
        (
            "mcp_header_holds_credential",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {
                        "type": "streamable-http",
                        "url": "https://mcp.acme.example",
                        "headers": {"Authorization": "Bearer abc"},
                    }})),
                ),
            ],
        ),
        (
            "mcp_header_duplicate",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {
                        "type": "streamable-http",
                        "url": "https://mcp.acme.example",
                        "headers": {"X-Tier": "a", "x-tier": "b"},
                    }})),
                ),
            ],
        ),
        (
            "mcp_server_type_invalid",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    mcp(json!({"pdf": {"type": "websocket", "url": "https://mcp.acme.example"}})),
                ),
            ],
        ),
        (
            "mcp_version_mismatch",
            vec![
                ("plugin.json", manifest(json!({}))),
                (
                    "mcp.json",
                    json!({
                        "$schema": "https://agent-plugins.org/schemas/2.0.0/mcp.schema.json",
                        "mcpServers": {},
                    })
                    .to_string(),
                ),
            ],
        ),
    ];
    for (code, files) in cases {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, content)| (*path, content.as_str()))
            .collect();
        let result = conformance(&repo(&files), false);
        assert_eq!(result["passed"], json!(false), "{code}: {result}");
        assert!(
            codes(&result).contains(&code.to_owned()),
            "{code}: {result}"
        );
        assert!(
            result["diagnostics"]
                .as_array()
                .expect("diagnostics")
                .iter()
                .all(|finding| finding["section"].as_str().is_some_and(|s| !s.is_empty())),
            "{code}: every finding names its section"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_plugin_is_rejected() {
    let outside = repo(&[("plugin.json", &manifest(json!({})))]);
    let root = repo(&[]);
    std::os::unix::fs::symlink(outside.join("plugin.json"), root.join("plugin.json"))
        .expect("symlink");
    let result = conformance(&root, false);
    assert_eq!(result["passed"], json!(false), "{result}");
    assert!(codes(&result).contains(&"manifest_outside_root".to_owned()));
}

#[test]
fn an_unknown_spec_is_an_error() {
    let root = repo(&[("plugin.json", &manifest(json!({})))]);
    let response = call(json!({
        "command": "conformance",
        "root": root.to_str().expect("utf-8 path"),
        "spec": "agent-plugins-9",
    }));
    assert_eq!(
        response,
        json!({"ok": false, "error": "plugin_kit_spec_unsupported"})
    );
}

#[test]
fn other_tools_mcp_json_is_not_an_agent_plugins_source() {
    // Cursor and VS Code also use `mcp.json`; without an Agent Plugins
    // `$schema` it is neither a source nor an error.
    let root = repo(&[(
        "mcp.json",
        &json!({"mcpServers": {"pdf": {"command": "npx", "args": ["-y", "pdf"]}}}).to_string(),
    )]);
    let response = call(json!({"command": "check", "root": root.to_str().expect("path")}));
    assert_eq!(response["ok"], json!(true), "{response}");
    assert_eq!(response["result"]["sources"], json!([]), "{response}");
    assert_eq!(
        codes(&response["result"]),
        ["no_plugin_source"],
        "{response}"
    );
}

fn package(root: &Path, runtime: &str) -> PathBuf {
    let out = root.parent().expect("parent").join("dist");
    let response = call(json!({
        "command": "package",
        "root": root.to_str().expect("path"),
        "out_dir": out.to_str().expect("path"),
        "runtimes": [runtime],
    }));
    assert_eq!(response["ok"], json!(true), "{response}");
    assert_eq!(response["result"]["packaged"], json!(true), "{response}");
    out.join(runtime)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read")).expect("json")
}

#[test]
fn an_agent_plugins_package_round_trips() {
    let plugin = json!({
        "$schema": PLUGIN_SCHEMA,
        "name": "pdf-tools",
        "version": "1.0.0",
        "description": "Fill PDF forms.",
        "author": {"name": "Acme Labs"},
        "license": "MIT",
    });
    let servers = json!({
        "pdf": {"type": "stdio", "command": "./bin/server", "args": ["${PLUGIN_ROOT}/data"]},
        "remote": {"type": "streamable-http", "url": "https://mcp.acme.example/pdf"},
    });
    let root = repo(&[
        ("plugin.json", &plugin.to_string()),
        ("mcp.json", &mcp(servers.clone())),
        ("skills/fill-forms/SKILL.md", SKILL),
        ("bin/server", "#!/bin/sh\n"),
        ("data/forms.json", "{}"),
    ]);
    let out = package(&root, "agent-plugins");
    assert_eq!(read_json(&out.join("plugin.json")), plugin);
    assert!(out.join("bin/server").is_file());
    assert!(out.join("data/forms.json").is_file());
    assert_eq!(
        read_json(&out.join("mcp.json")),
        json!({"$schema": MCP_SCHEMA, "mcpServers": servers})
    );
    assert_eq!(
        fs::read_to_string(out.join("skills/fill-forms/SKILL.md")).expect("skill"),
        SKILL
    );
    assert_eq!(conformance(&out, true)["passed"], json!(true));
}

#[test]
fn a_claude_code_plugin_converts_to_a_conforming_package() {
    let root = repo(&[
        (
            ".claude-plugin/plugin.json",
            &json!({
                "name": "pdf-tools",
                "version": "1.0.0",
                "description": "Fill PDF forms.",
                "author": {"name": "Acme"},
            })
            .to_string(),
        ),
        (
            ".mcp.json",
            &json!({"mcpServers": {
                "pdf": {
                    "command": "${CLAUDE_PLUGIN_ROOT}/bin/server",
                    "args": ["${CLAUDE_PLUGIN_ROOT}/data"],
                    "env": {"PDF_API_KEY": "${PDF_API_KEY}"},
                },
                "shell": {"command": "sh -c 'pdf'"},
                "docs": {
                    "type": "http",
                    "url": "https://mcp.acme.example/docs",
                    "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"},
                },
            }})
            .to_string(),
        ),
        ("skills/fill-forms/SKILL.md", SKILL),
        ("commands/fill.md", "Fill the form."),
        ("bin/server", "#!/bin/sh\n"),
        ("data/forms.json", "{}"),
    ]);
    let out = package(&root, "agent-plugins");
    assert!(out.join("bin/server").is_file());
    assert!(out.join("data/forms.json").is_file());
    let result = conformance(&out, true);
    assert_eq!(result["passed"], json!(true), "{result}");
    assert_eq!(
        read_json(&out.join("mcp.json"))["mcpServers"],
        json!({
            "docs": {"type": "streamable-http", "url": "https://mcp.acme.example/docs"},
            "pdf": {"type": "stdio", "command": "./bin/server", "args": ["${PLUGIN_ROOT}/data"]},
        })
    );
    assert!(out.join("skills/fill-forms/SKILL.md").is_file());

    let check = call(json!({"command": "check", "root": root.to_str().expect("path")}));
    let runtime = check["result"]["runtimes"]
        .as_array()
        .expect("runtimes")
        .iter()
        .find(|runtime| runtime["runtime"] == json!("agent-plugins"))
        .expect("agent-plugins")
        .clone();
    assert_eq!(
        runtime,
        json!({
            "runtime": "agent-plugins",
            "supported": true,
            "dropped": [
                "commands",
                "mcp_servers_not_portable",
                "mcp_env",
                "mcp_headers",
            ],
        })
    );
}

fn dropped_for(root: &Path, runtime: &str) -> Value {
    let check = call(json!({"command": "check", "root": root.to_str().expect("path")}));
    check["result"]["runtimes"]
        .as_array()
        .expect("runtimes")
        .iter()
        .find(|entry| entry["runtime"] == json!(runtime))
        .expect("runtime")["dropped"]
        .clone()
}

#[test]
fn servers_whose_files_or_variables_cannot_travel_are_left_out() {
    let root = repo(&[
        (
            ".claude-plugin/plugin.json",
            &json!({"name": "pdf-tools", "version": "1.0.0", "description": "Fill PDF forms."})
                .to_string(),
        ),
        (
            ".mcp.json",
            &json!({"mcpServers": {
                "built": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/dist/index.js"]},
                "home": {"command": "pdf-server", "args": ["--config", "${HOME}/.pdf"]},
                "priced": {"type": "http", "url": "https://mcp.acme.example/mcp?price=$5"},
            }})
            .to_string(),
        ),
        ("skills/fill-forms/SKILL.md", SKILL),
    ]);
    let out = package(&root, "agent-plugins");
    assert_eq!(
        read_json(&out.join("mcp.json"))["mcpServers"],
        json!({
            "priced": {"type": "streamable-http", "url": "https://mcp.acme.example/mcp?price=$5"},
        })
    );
    assert_eq!(
        dropped_for(&root, "agent-plugins"),
        json!(["mcp_servers_not_portable"])
    );
}

#[test]
fn a_root_reference_travels_only_as_plain_files_beside_the_metadata() {
    let root = repo(&[
        (
            ".claude-plugin/plugin.json",
            &json!({"name": "pdf-tools", "version": "1.0.0", "description": "Fill PDF forms."})
                .to_string(),
        ),
        (
            ".mcp.json",
            &json!({"mcpServers": {
                "whole": {"command": "uv", "args": ["run", "--directory", "${CLAUDE_PLUGIN_ROOT}", "server.py"]},
                "dotted": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/lib/../server.js"]},
                "metadata": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/mcp.json"]},
                "skill": {
                    "command": "${CLAUDE_PLUGIN_ROOT}/bin/server",
                    "args": ["${CLAUDE_PLUGIN_ROOT}/skills/fill-forms/SKILL.md"],
                },
            }})
            .to_string(),
        ),
        ("skills/fill-forms/SKILL.md", SKILL),
        ("bin/server", "#!/bin/sh\n"),
        ("lib/index.js", ""),
        ("server.js", ""),
        ("server.py", ""),
        ("mcp.json", "{\"servers\": {}}"),
    ]);
    let out = package(&root, "agent-plugins");
    assert_eq!(
        read_json(&out.join("mcp.json"))["mcpServers"],
        json!({"skill": {
            "type": "stdio",
            "command": "./bin/server",
            "args": ["${PLUGIN_ROOT}/skills/fill-forms/SKILL.md"],
        }})
    );
    assert_eq!(
        fs::read_to_string(out.join("skills/fill-forms/SKILL.md")).expect("skill"),
        SKILL
    );
    assert!(!out.join("server.py").exists());
    assert!(!out.join("server.js").exists());
    assert_eq!(
        dropped_for(&root, "agent-plugins"),
        json!(["mcp_servers_not_portable"])
    );
}

#[test]
fn a_working_folder_inside_the_plugin_travels_with_the_server() {
    let root = repo(&[
        (
            "plugin.json",
            &manifest(json!({"description": "Fill PDF forms."})),
        ),
        (
            "mcp.json",
            &mcp(json!({
                "local": {"type": "stdio", "command": "pdf-server", "cwd": "./work"},
                "missing": {"type": "stdio", "command": "pdf-server", "cwd": "${PLUGIN_ROOT}/gone"},
                "here": {"type": "stdio", "command": "pdf-server", "cwd": "${PLUGIN_ROOT}"},
            })),
        ),
        ("work/config.json", "{}"),
    ]);
    let out = package(&root, "agent-plugins");
    assert!(out.join("work/config.json").is_file());
    let servers = read_json(&out.join("mcp.json"))["mcpServers"].clone();
    let mut names: Vec<_> = servers
        .as_object()
        .expect("servers")
        .keys()
        .cloned()
        .collect();
    names.sort();
    assert_eq!(names, ["here", "local"], "{servers}");
    assert_eq!(conformance(&out, true)["passed"], json!(true));
}

#[test]
fn a_working_folder_with_no_packaged_files_is_reported_not_shipped() {
    let root = repo(&[
        (
            "plugin.json",
            &manifest(json!({"description": "Fill PDF forms."})),
        ),
        (
            "mcp.json",
            &mcp(json!({
                "empty": {"type": "stdio", "command": "pdf-server", "cwd": "./work"},
                "excluded": {"type": "stdio", "command": "pdf-server", "cwd": "./scratch"},
                "kept": {"type": "stdio", "command": "pdf-server", "cwd": "./data"},
            })),
        ),
        (
            ".plugin-scanner.toml",
            "[plugin_kit]\nexclude_paths = [\"scratch/*\"]\n",
        ),
        ("scratch/notes.txt", "draft"),
        ("data/forms.json", "{}"),
    ]);
    std::fs::create_dir(root.join("work")).expect("work folder");
    let out = package(&root, "agent-plugins");
    assert!(!out.join("work").exists());
    assert!(!out.join("scratch").exists());
    assert_eq!(
        read_json(&out.join("mcp.json"))["mcpServers"]
            .as_object()
            .expect("servers")
            .keys()
            .collect::<Vec<_>>(),
        ["kept"]
    );
    assert_eq!(
        dropped_for(&root, "agent-plugins"),
        json!(["mcp_servers_not_portable"])
    );
    assert_eq!(conformance(&out, true)["passed"], json!(true));
}

#[test]
fn an_excluded_file_a_server_names_is_reported_not_shipped() {
    let root = repo(&[
        (
            "plugin.json",
            &manifest(json!({"description": "Fill PDF forms."})),
        ),
        (
            "mcp.json",
            &mcp(json!({
                "secret": {"type": "stdio", "command": "pdf-server", "args": ["${PLUGIN_ROOT}/config/secrets.json"]},
                "kept": {"type": "stdio", "command": "pdf-server", "args": ["${PLUGIN_ROOT}/data/forms.json"]},
            })),
        ),
        (
            ".plugin-scanner.toml",
            "[plugin_kit]\nexclude_paths = [\"config/*\"]\n",
        ),
        ("config/secrets.json", "{}"),
        ("data/forms.json", "{}"),
    ]);
    let out = package(&root, "agent-plugins");
    assert!(!out.join("config").exists());
    assert_eq!(
        read_json(&out.join("mcp.json"))["mcpServers"]
            .as_object()
            .expect("servers")
            .keys()
            .collect::<Vec<_>>(),
        ["kept"]
    );
    assert_eq!(
        dropped_for(&root, "agent-plugins"),
        json!(["mcp_servers_not_portable"])
    );
}

#[test]
fn a_server_file_too_large_to_copy_fails_the_package() {
    let root = repo(&[
        (
            "plugin.json",
            &manifest(json!({"description": "Fill PDF forms."})),
        ),
        (
            "mcp.json",
            &mcp(json!({
                "pdf": {"type": "stdio", "command": "pdf-server", "args": ["${PLUGIN_ROOT}/data/model.bin"]},
            })),
        ),
    ]);
    fs::create_dir_all(root.join("data")).expect("data folder");
    fs::write(root.join("data/model.bin"), vec![0_u8; 5 * 1024 * 1024 + 1]).expect("model");
    let response = package_response(&root);
    let _ = fs::remove_dir_all(root.parent().expect("parent"));
    assert_eq!(
        response,
        json!({"ok": false, "error": "plugin_kit_package_too_large"}),
        "{response}"
    );
}

#[test]
fn a_server_file_inside_a_skill_folder_too_large_to_copy_fails_the_package() {
    // The skill walk reaches the file first; the server still requires it.
    let root = repo(&[
        (
            "plugin.json",
            &manifest(json!({"description": "Fill PDF forms."})),
        ),
        ("skills/fill-forms/SKILL.md", SKILL),
        (
            "mcp.json",
            &mcp(json!({
                "pdf": {"type": "stdio", "command": "pdf-server", "args": ["${PLUGIN_ROOT}/skills/fill-forms/model.bin"]},
            })),
        ),
    ]);
    fs::write(
        root.join("skills/fill-forms/model.bin"),
        vec![0_u8; 5 * 1024 * 1024 + 1],
    )
    .expect("model");
    let response = package_response(&root);
    let _ = fs::remove_dir_all(root.parent().expect("parent"));
    assert_eq!(
        response,
        json!({"ok": false, "error": "plugin_kit_package_too_large"}),
        "{response}"
    );
}

fn package_response(root: &Path) -> Value {
    let out = root.parent().expect("parent").join("dist");
    call(json!({
        "command": "package",
        "root": root.to_str().expect("path"),
        "out_dir": out.to_str().expect("path"),
        "runtimes": ["agent-plugins"],
    }))
}

#[test]
fn an_agent_plugins_source_keeps_its_root_in_other_runtimes() {
    let plugin = json!({
        "$schema": PLUGIN_SCHEMA,
        "name": "pdf-tools",
        "version": "1.0.0",
        "description": "Fill PDF forms.",
    });
    let root = repo(&[
        ("plugin.json", &plugin.to_string()),
        (
            "mcp.json",
            &mcp(json!({
                "pdf": {"type": "stdio", "command": "./bin/server", "args": ["${PLUGIN_ROOT}/data"]},
                "scratch": {"type": "stdio", "command": "pdf-cache", "cwd": "${PLUGIN_DATA}"},
            })),
        ),
        ("bin/server", "#!/bin/sh\n"),
        ("data/forms.json", "{}"),
    ]);
    let out = package(&root, "claude-code");
    assert_eq!(
        read_json(&out.join(".mcp.json"))["mcpServers"],
        json!({"pdf": {
            "command": "${CLAUDE_PLUGIN_ROOT}/bin/server",
            "args": ["${CLAUDE_PLUGIN_ROOT}/data"],
        }})
    );
    assert_eq!(
        dropped_for(&root, "claude-code"),
        json!(["mcp_servers_not_portable"])
    );
    assert_eq!(
        dropped_for(&root, "cursor"),
        json!(["mcp_servers_not_portable"])
    );
}

#[test]
fn a_command_the_package_does_not_contain_is_skipped() {
    let root = repo(&[
        (
            "plugin.json",
            &json!({"$schema": PLUGIN_SCHEMA, "name": "pdf-tools", "version": "1.0.0"}).to_string(),
        ),
        (
            "mcp.json",
            &mcp(json!({"pdf": {"type": "stdio", "command": "./bin/server"}})),
        ),
    ]);
    let result = conformance(&root, false);
    assert_eq!(result["passed"], json!(false), "{result}");
    assert_eq!(codes(&result), ["mcp_command_not_found"], "{result}");
}
