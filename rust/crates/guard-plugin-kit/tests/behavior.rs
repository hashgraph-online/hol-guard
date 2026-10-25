//! Behavior the golden fixtures cannot show: output folder rules, rejected
//! inputs, and how env, header and transport settings survive packaging.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A fresh repository holding `files`, under a fresh parent folder.
fn repo(files: &[(&str, &str)]) -> PathBuf {
    let parent = std::env::temp_dir().join(format!(
        "guard-plugin-kit-{}-{}",
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

fn ok(request: Value) -> Value {
    let response = call(request);
    assert_eq!(response["ok"], json!(true), "{response}");
    response["result"].clone()
}

fn error(request: Value) -> String {
    let response = call(request);
    assert_eq!(response["ok"], json!(false), "{response}");
    response["error"].as_str().expect("code").to_owned()
}

fn root_str(root: &Path) -> String {
    root.to_string_lossy().into_owned()
}

fn plan(root: &Path, runtimes: &[&str]) -> Vec<guard_plugin_kit::Output> {
    let runtimes: Vec<String> = runtimes.iter().map(|name| (*name).to_owned()).collect();
    guard_plugin_kit::package_plan(root, &runtimes).expect("plan")
}

fn json_output(outputs: &[guard_plugin_kit::Output], path: &str) -> Value {
    let output = outputs
        .iter()
        .find(|output| output.path == path)
        .unwrap_or_else(|| panic!("{path} missing"));
    serde_json::from_slice(&output.content).expect("json")
}

fn codes(check: &Value) -> Vec<String> {
    check["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|item| item["code"].as_str().unwrap_or("").to_owned())
        .collect()
}

const SKILL: &str = "---\nname: pdf-tools\ndescription: Use for PDFs.\n---\n# PDF\n";
const MANIFEST: &str = r#"{"name":"pdf-tools","version":"1.0.0","description":"PDF tools.","license":"MIT","repository":"https://github.com/acme/pdf-tools"}"#;

#[test]
fn gemini_context_file_outside_the_extension_is_not_packaged() {
    for context in ["../outside.md", "/etc/hosts"] {
        let manifest = json!({
            "name": "notes", "version": "1.0.0", "description": "Notes.",
            "contextFileName": context,
            "mcpServers": {"notes": {"command": "notes-mcp"}},
        });
        let root = repo(&[("gemini-extension.json", &manifest.to_string())]);
        fs::write(root.parent().expect("parent").join("outside.md"), "secret").expect("outside");
        let outputs = plan(&root, &[]);
        assert!(
            outputs
                .iter()
                .all(|output| output.path != "gemini-cli/GEMINI.md"),
            "{context}"
        );
        let check = ok(json!({"command": "check", "root": root_str(&root)}));
        assert!(codes(&check).contains(&"context_file_invalid".to_owned()));
    }
}

#[test]
fn gemini_context_file_inside_the_extension_is_packaged_and_digested() {
    let manifest = json!({
        "name": "notes", "version": "1.0.0", "description": "Notes.",
        "contextFileName": "docs/CONTEXT.md",
        "mcpServers": {"notes": {"command": "notes-mcp"}},
    });
    let root = repo(&[
        ("gemini-extension.json", &manifest.to_string()),
        ("docs/CONTEXT.md", "one"),
    ]);
    let first = plan(&root, &[]);
    assert!(first
        .iter()
        .any(|output| output.path == "gemini-cli/GEMINI.md"));
    fs::write(root.join("docs/CONTEXT.md"), "two").expect("edit");
    let second = plan(&root, &[]);
    let digest = |outputs: &[guard_plugin_kit::Output]| {
        json_output(outputs, guard_plugin_kit::PROVENANCE_FILE)["source_digest"].clone()
    };
    assert_ne!(digest(&first), digest(&second));
}

#[test]
fn provenance_digest_covers_copied_skill_files() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
        ("skills/pdf-tools/reference.md", "one"),
    ]);
    let digest = || {
        json_output(&plan(&root, &[]), guard_plugin_kit::PROVENANCE_FILE)["source_digest"].clone()
    };
    let before = digest();
    fs::write(root.join("skills/pdf-tools/reference.md"), "two").expect("edit");
    assert_ne!(before, digest());
}

#[cfg(unix)]
#[test]
fn configured_output_through_a_symlink_is_refused() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
    ]);
    let outside = root.parent().expect("parent").join("elsewhere");
    fs::create_dir_all(&outside).expect("outside");
    std::os::unix::fs::symlink(&outside, root.join("dist")).expect("symlink");
    let code = error(json!({"command": "package", "root": root_str(&root), "force": true}));
    assert_eq!(code, "plugin_kit_output_path_blocked");
    assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
}

#[test]
fn output_inside_a_source_folder_is_refused() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
        (
            "hol.json",
            r#"{"schema":"hol.plugin-kit.config.v1","out":"skills/pdf-tools/out"}"#,
        ),
    ]);
    let code = error(json!({"command": "package", "root": root_str(&root)}));
    assert_eq!(code, "plugin_kit_output_inside_source");
}

#[test]
fn forced_package_removes_files_the_new_plan_dropped() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
    ]);
    let out = root.join("dist/hol-plugin");
    ok(json!({"command": "package", "root": root_str(&root)}));
    assert!(out.join("codex").is_dir());
    fs::write(out.join("NOTES.md"), "mine").expect("user file");
    let result = ok(json!({
        "command": "package", "root": root_str(&root),
        "runtimes": ["claude-code"], "force": true,
    }));
    assert!(!out.join("codex").exists());
    assert!(out.join("claude-code/.claude-plugin/plugin.json").is_file());
    assert!(
        out.join("NOTES.md").is_file(),
        "files the Kit did not write stay"
    );
    let runtimes: Vec<&str> = result["runtimes"]
        .as_array()
        .expect("runtimes")
        .iter()
        .filter_map(|runtime| runtime["runtime"].as_str())
        .collect();
    assert_eq!(runtimes, ["claude-code"]);
}

#[test]
fn a_blocked_path_stops_package_before_any_write() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
        ("dist/hol-plugin/codex", "not a folder"),
    ]);
    let code = error(json!({"command": "package", "root": root_str(&root), "force": true}));
    assert_eq!(code, "plugin_kit_output_path_blocked");
    assert!(!root.join("dist/hol-plugin/claude-code").exists());
}

#[test]
fn a_requested_runtime_that_cannot_be_packaged_is_an_error() {
    let root = repo(&[("skills/pdf-tools/SKILL.md", SKILL)]);
    let code =
        error(json!({"command": "package", "root": root_str(&root), "runtimes": ["cursor"]}));
    assert_eq!(code, "plugin_kit_runtime_unsupported");
}

#[test]
fn a_skills_only_repository_passes_check() {
    let root = repo(&[("skills/pdf-tools/SKILL.md", SKILL)]);
    let check = ok(json!({"command": "check", "root": root_str(&root)}));
    assert!(!codes(&check).contains(&"description_missing".to_owned()));
    assert_eq!(check["passed"], json!(true), "{check}");
}

#[test]
fn skills_with_the_same_name_are_an_error() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
        ("examples/pdf-tools/SKILL.md", SKILL),
    ]);
    let check = ok(json!({"command": "check", "root": root_str(&root)}));
    assert!(codes(&check).contains(&"skill_name_duplicate".to_owned()));
}

#[test]
fn nested_commands_and_agents_keep_their_folders() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("commands/pdf/fill.md", "# Fill"),
        ("agents/review/strict.md", "# Strict"),
    ]);
    let outputs = plan(&root, &["claude-code"]);
    for path in [
        "claude-code/commands/pdf/fill.md",
        "claude-code/agents/review/strict.md",
    ] {
        assert!(outputs.iter().any(|output| output.path == path), "{path}");
    }
}

#[test]
fn env_references_headers_and_transport_survive_packaging() {
    let mcp = json!({"mcpServers": {
        "github": {"command": "gh-mcp", "env": {"GITHUB_TOKEN": "${GH_PAT}"}},
        "events": {
            "type": "sse",
            "url": "https://mcp.acme.example/sse",
            "headers": {"Authorization": "Bearer ${API_TOKEN}", "X-Team": "acme"},
        },
    }});
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        (".mcp.json", &mcp.to_string()),
    ]);
    let outputs = plan(&root, &["claude-code", "gemini-cli", "opencode"]);
    let claude = json_output(&outputs, "claude-code/.mcp.json");
    assert_eq!(
        claude["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        "${GH_PAT}"
    );
    let events = &claude["mcpServers"]["events"];
    assert_eq!(events["type"], "sse");
    assert_eq!(
        events["headers"],
        json!({"Authorization": "Bearer ${API_TOKEN}"})
    );
    let gemini = json_output(&outputs, "gemini-cli/gemini-extension.json");
    assert_eq!(
        gemini["mcpServers"]["events"]["url"],
        "https://mcp.acme.example/sse"
    );
    assert_eq!(
        gemini["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        "$GH_PAT"
    );
    let settings: Vec<&str> = gemini["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .filter_map(|setting| setting["envVar"].as_str())
        .collect();
    assert_eq!(settings, ["API_TOKEN", "GH_PAT"]);
    let opencode = json_output(&outputs, "opencode/opencode.json");
    assert_eq!(
        opencode["mcp"]["events"]["headers"]["Authorization"],
        "Bearer {env:API_TOKEN}"
    );
    let check = ok(json!({"command": "check", "root": root_str(&root)}));
    assert!(codes(&check).contains(&"mcp_header_literal".to_owned()));
}

#[test]
fn registry_variable_values_are_not_packaged() {
    let server = json!({
        "name": "io.github.acme/notes", "version": "1.0.0", "description": "Notes.",
        "packages": [{
            "registryType": "npm", "identifier": "@acme/notes", "version": "1.0.0",
            "environmentVariables": [{"name": "NOTES_TOKEN", "value": "sk-live-123"}],
        }],
    });
    let root = repo(&[("server.json", &server.to_string())]);
    let outputs = plan(&root, &["mcp-registry"]);
    let document = json_output(&outputs, "mcp-registry/server.json");
    let variable = &document["packages"][0]["environmentVariables"][0];
    assert_eq!(variable["name"], "NOTES_TOKEN");
    assert!(variable.get("value").is_none());
}

#[test]
fn codex_manifest_always_has_a_version() {
    let root = repo(&[
        (
            ".claude-plugin/plugin.json",
            r#"{"name":"pdf-tools","description":"PDF tools."}"#,
        ),
        ("skills/pdf-tools/SKILL.md", SKILL),
    ]);
    let outputs = plan(&root, &["codex"]);
    let manifest = json_output(&outputs, "codex/.codex-plugin/plugin.json");
    assert_eq!(manifest["version"], "0.1.0");
}

#[test]
fn each_runtime_installs_from_its_own_marketplace() {
    let root = repo(&[
        (".claude-plugin/plugin.json", MANIFEST),
        ("skills/pdf-tools/SKILL.md", SKILL),
        (
            ".claude-plugin/marketplace.json",
            r#"{"name":"acme-claude","plugins":[{"name":"pdf-tools","source":"./"}]}"#,
        ),
        (
            ".agents/plugins/marketplace.json",
            r#"{"name":"acme-codex","plugins":[{"name":"pdf-tools","source":"./"}]}"#,
        ),
    ]);
    let links = ok(json!({"command": "links", "root": root_str(&root)}));
    let commands: Vec<String> = links["install"]
        .as_array()
        .expect("install")
        .iter()
        .flat_map(|entry| entry["commands"].as_array().cloned().unwrap_or_default())
        .filter_map(|command| command.as_str().map(str::to_owned))
        .collect();
    assert!(commands.contains(&"/plugin install pdf-tools@acme-claude".to_owned()));
    assert!(commands.contains(&"codex plugin add pdf-tools@acme-codex".to_owned()));
}

#[test]
fn init_scaffolds_only_a_new_folder_and_never_overwrites() {
    let root = repo(&[("README.md", "# New"), (".gitignore", "dist/")]);
    let result = ok(json!({"command": "init", "root": root_str(&root), "name": "my-plugin"}));
    assert_eq!(result["scaffolded"], json!(true));
    assert_eq!(
        error(json!({"command": "init", "root": root_str(&root), "name": "my-plugin"})),
        "plugin_kit_init_would_overwrite"
    );

    let busy = repo(&[("README.md", "# Busy"), ("src/main.rs", "fn main() {}")]);
    assert_eq!(
        error(json!({"command": "init", "root": root_str(&busy), "name": "my-plugin"})),
        "plugin_kit_init_folder_not_empty"
    );
    assert!(!busy.join(".claude-plugin").exists());
}
