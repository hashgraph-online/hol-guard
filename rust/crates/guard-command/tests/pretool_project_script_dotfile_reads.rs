//! A checkout keeps one-off scripts as dotfiles too: `.repair-stage.py`,
//! `.check-routes.ts`. Reading one is the same work as reading the visible
//! script beside it, through a harness's Read tool or through `cat`. A hidden
//! script named for a secret or a tool's login, one under a hidden directory,
//! and one outside any checkout keep their review.

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{assert_decision, layout};
use serde_json::json;
use std::path::Path;

const SCRIPTS: [&str; 4] = [
    ".repair-stage.py",
    ".check-routes.ts",
    ".bootstrap.sh",
    ".lint-rules.mjs",
];

fn read_tool(harness: &str, cwd: &Path, home: &Path, path: &Path) -> bool {
    let path = path.to_str().unwrap();
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":path}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .decision
        == "allow"
}

#[test]
fn reading_a_hidden_project_script_in_a_checkout_is_allowed() {
    let layout = layout("project-script-dotfile");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    for name in SCRIPTS {
        std::fs::write(sibling.join(name), "def main():\n    return 0\n").unwrap();
        std::fs::write(cwd.join(name), "def main():\n    return 0\n").unwrap();
        for harness in ["cursor", "claude-code", "codex"] {
            for path in [sibling.join(name), cwd.join(name)] {
                assert!(
                    read_tool(harness, &cwd, &layout.home, &path),
                    "{harness} Read {}",
                    path.display()
                );
            }
        }
        assert_decision(
            &cwd,
            &layout.home,
            &format!("cat ../service-api/{name}"),
            true,
        );
        assert_decision(&cwd, &layout.home, &format!("head -20 {name}"), true);
    }
}

#[test]
fn hidden_scripts_named_for_a_secret_or_outside_a_checkout_keep_their_review() {
    let layout = layout("project-script-dotfile-negative");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    let named = [
        ".env.py",
        ".env.local.sh",
        ".secrets.py",
        ".deploy-credentials.ts",
        ".mcp.js",
        ".claude-login.py",
        ".aws-config.sh",
        ".private-key.py",
        ".id_rsa.sh",
    ];
    for name in named {
        std::fs::write(sibling.join(name), "value = 1\n").unwrap();
    }
    // Under a hidden directory the script is in some tool's tree.
    let tool_tree = sibling.join(".tool-state/.worker.py");
    // A hidden directory in the home folder is not a checkout.
    let home_tree = layout.home.join(".merge-agent/.worker.py");
    // Nor is a plain folder without a work tree above it.
    let loose = layout.home.join("notes/.stage.py");
    for path in [&tool_tree, &home_tree, &loose] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "value = 1\n").unwrap();
    }
    let mut paths: Vec<_> = named.iter().map(|name| sibling.join(name)).collect();
    paths.extend([tool_tree, home_tree, loose]);
    for path in &paths {
        for harness in ["cursor", "claude-code", "codex"] {
            assert!(
                !read_tool(harness, &cwd, &layout.home, path),
                "{harness} Read {}",
                path.display()
            );
        }
        assert_decision(
            &cwd,
            &layout.home,
            &format!("cat {}", path.display()),
            false,
        );
    }
}
