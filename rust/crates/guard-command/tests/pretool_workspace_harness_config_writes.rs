//! File-edit tools may write ordinary workspace files silently, but a write
//! that plants harness configuration (plugins, hooks, settings, MCP servers)
//! goes to review, because the harness loads it unasked. Plain-text
//! instruction files (`AGENTS.md`, `CLAUDE.md`) stay silently writable.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new(name: &str) -> Self {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(name);
        std::fs::create_dir_all(&base).unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = base.join(format!("run-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn decide(home: &str, workspace: &str, tool: &str, relative: &str) -> String {
    let path = format!("{workspace}/{relative}");
    let input = if tool == "Write" {
        json!({"file_path": path, "content": "fixture\n"})
    } else {
        json!({"file_path": path, "old_string": "a", "new_string": "b"})
    };
    evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"toolName": tool, "toolInput": input}),
        None,
        None,
        Some(home),
        Some(workspace),
    )
    .minimum_action
}

#[test]
fn file_edit_tools_review_harness_configuration_inside_the_workspace() {
    let fixture = TestRoot::new("harness-config-write-fixtures");
    let home = fixture.0.to_str().unwrap().to_owned();
    let workspace = fixture.0.join("project");
    for directory in ["src", "tests", "dist"] {
        std::fs::create_dir_all(workspace.join(directory)).unwrap();
    }
    let workspace = workspace.to_str().unwrap().to_owned();
    for tool in ["Write", "Edit"] {
        for relative in [
            "src/example.ts",
            "tests/example.test.ts",
            "dist/index.js",
            "README.md",
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
            "docs/AGENTS.md",
        ] {
            assert_eq!(
                decide(&home, &workspace, tool, relative),
                "allow",
                "{tool} {relative}"
            );
        }
        for relative in [
            ".zcode/x",
            ".opencode/plugins/x.ts",
            ".opencode/plugin/x.ts",
            ".claude/settings.json",
            ".claude/commands/x.md",
            ".codex/config.toml",
            ".cursor/mcp.json",
            ".gemini/settings.json",
            ".kiro/hooks/x.json",
            ".roo/mcp.json",
            ".windsurf/rules/x.md",
            ".continue/config.yaml",
            ".pi/extensions/x.ts",
            ".agents/x",
            ".copilot/x",
            ".clinerules/x.md",
            ".husky/pre-commit",
            ".mcp.json",
            ".vscode/tasks.json",
            ".github/copilot-instructions.md",
            "opencode.json",
            "opencode.jsonc",
            ".github/prompts/x.md",
            ".githooks/pre-push",
        ] {
            assert_ne!(
                decide(&home, &workspace, tool, relative),
                "allow",
                "{tool} {relative}"
            );
        }
    }
}
