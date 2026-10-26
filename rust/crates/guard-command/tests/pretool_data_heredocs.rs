#![cfg(unix)]
//! Text written through a quoted `cat` heredoc is file content. Words in it
//! such as `process.env` do not make the command a sensitive access, while a
//! sensitive redirect target, an executed heredoc and an expanding heredoc
//! keep their review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::PathBuf;

fn workspace(name: &str) -> PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-data-heredocs")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(root.join("project/.git")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn reason(root: &std::path::Path, harness: &str, command: &str) -> (String, String) {
    let cwd = root.join("project");
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"toolName":"Bash","toolInput":{"command":command}}),
        None,
        None,
        root.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn scaffold_heredocs_naming_environment_variables_are_not_sensitive_access() {
    let root = workspace("scaffold");
    let command = "mkdir -p src test\n\
cat > package.json <<'EOF'\n{\"name\": \"todo-app\"}\nEOF\n\
cat > .gitignore <<'EOF'\nnode_modules/\ntodos.json\nEOF\n\
cat > src/cli.js <<'EOF'\nimport { readFileSync, writeFileSync } from 'node:fs';\n\
const file = process.env.TODO_FILE ?? 'todos.json';\nconsole.log(process.argv.slice(2), file);\nEOF\n\
chmod +x src/cli.js";
    for harness in ["claude-code", "omp"] {
        let (_, reason_code) = reason(&root, harness, command);
        assert_ne!(reason_code, "native_sensitive_access_review", "{harness}");
    }
}

#[test]
fn sensitive_targets_and_executed_heredocs_keep_review() {
    let root = workspace("kept");
    for command in [
        "cat > .env <<'EOF'\nTOKEN=1\nEOF",
        "cat > ~/.ssh/authorized_keys <<'EOF'\nssh-ed25519 AAAA\nEOF",
        "cat > ~/.zshrc <<'EOF'\nexport A=1\nEOF",
        "bash <<'EOF'\necho $process.env\ncat .env\nEOF",
        "cat <<'EOF' | bash\ncat .env\nEOF",
        "bash <<'X'; cat <<'EOF'\ncat ~/.ssh/id_rsa\nX\nhi\nEOF",
        "bash -s \\\ncat <<'EOF'\ncat ~/.ssh/id_rsa\nEOF",
        ": '\"'; echo \"\ncat <<'EOF'\n$(cat ~/.ssh/id_rsa)\nEOF\n\"\"",
        "cat > notes.txt <<EOF\n$(cat .env)\nEOF",
    ] {
        let (action, _) = reason(&root, "claude-code", command);
        assert_ne!(action, "allow", "{command}");
    }
}
