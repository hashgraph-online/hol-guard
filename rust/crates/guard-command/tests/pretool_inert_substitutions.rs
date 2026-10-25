#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, git_github_controls, FixtureCleanup};
use guard_command::native_command_controls::CompiledNativeCommandControls;
use serde_json::json;

const EVALUATION_FAILED: &str = "native_command_extension_evaluation_failed";

fn workspace(name: &str) -> (std::path::PathBuf, FixtureCleanup) {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-inert-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/src")).unwrap();
    std::fs::write(root.join("project/src/cli.js"), "console.log(1)\n").unwrap();
    (root.clone(), FixtureCleanup(root))
}

fn evaluate(
    root: &std::path::Path,
    controls: &CompiledNativeCommandControls,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

fn lockdown_controls() -> CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":true, "controls":[]
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

#[test]
fn value_producing_substitutions_are_judged_on_the_rest_of_the_chain() {
    let (root, _cleanup) = workspace("judged");
    let controls = git_github_controls("default", "default");
    let cli = root.join("project/src/cli.js");
    let cli = cli.display();

    let result = evaluate(&root, &controls, "echo \"$(date +%Y-%m-%d)\"");
    assert_eq!(result.minimum_action, "allow", "{}", result.reason);

    for command in [
        "cd \"$(mktemp -d)\" && ls".to_owned(),
        format!(
            "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node {cli} add Hello world && TODO_FILE=t.json node {cli} list"
        ),
        format!(
            "node --test test/ 2>&1 | tail -10; export TODO_FILE=$(mktemp -d)/t.json; node {cli} add Try it; node {cli} done 1; node {cli} list"
        ),
        // A line break separates commands as `;` does.
        format!(
            "node --test test/ 2>&1 | tail -10\nexport TODO_FILE=$(mktemp -d)/t.json\nnode {cli} list"
        ),
    ] {
        let result = evaluate(&root, &controls, &command);
        assert_ne!(result.reason_code, EVALUATION_FAILED, "{command}");
        assert_ne!(result.minimum_action, "block", "{command}: {}", result.reason);
    }
    // Running a script from the stand-in directory still needs review.
    let result = evaluate(
        &root,
        &controls,
        &format!("cd \"$(mktemp -d)\" && TODO_FILE=t.json node {cli} list"),
    );
    assert_ne!(result.minimum_action, "allow", "{}", result.reason);
}

#[test]
fn other_substitutions_and_unsafe_uses_are_never_allowed() {
    let (root, _cleanup) = workspace("refused");
    let controls = git_github_controls("default", "default");
    for command in [
        "cd \"$(gh pr list)\"",
        "echo $(cat ~/.ssh/id_rsa)",
        "echo $(mktemp -p /etc)",
        "echo $(mktemp ../x.XXX)",
        "echo $(mktemp -d $(whoami))",
        "echo $(date -s 2020)",
        "echo $(date +.env)",
        "cat \"$(dirname x)/.env\"",
        "cat \"$(date +%s)/.env\"",
        "cd \"$(mktemp -d)\" && rm -rf /",
        "rm -rf \"$(mktemp -d)\"",
        "rm -rf \"$(mktemp -d)/../..\"",
        "touch \"$(mktemp -d)/x\"",
        "echo hi > \"$(mktemp -d)/x\"",
        "export X=$(mktemp -d); rm -rf \"$X\"",
        "export X=$(mktemp -d)/../..; rm -rf \"$X\"",
        "export PATH=$(mktemp -d); rm -rf /",
        "export X=$(mktemp -d)\nrm -rf \"$X\"",
        "cat > f <<EOF\n$(cat ~/.ssh/id_rsa)\nEOF\ncd \"$(mktemp -d)\" && ls",
        "cat > f <<EOF\n$(mktemp -d)\nEOF\nsh f",
        "cd \"$(mktemp -d)\" && cat <<'EOF'\nunterminated",
    ] {
        let result = evaluate(&root, &controls, command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
    let result = evaluate(&root, &controls, "cd \"$(mktemp -d)\" && rm -rf /");
    assert_eq!(result.minimum_action, "block", "{}", result.reason);
}

#[test]
fn lockdown_keeps_substitutions_closed() {
    let (root, _cleanup) = workspace("lockdown");
    let controls = lockdown_controls();
    for command in [
        "echo \"$(date +%Y-%m-%d)\"",
        "cd \"$(mktemp -d)\" && ls",
        "export TODO_FILE=$(mktemp -d)/t.json; ls",
        "node --version\nexport TODO_FILE=$(mktemp -d)/t.json\nls",
    ] {
        let result = evaluate(&root, &controls, command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
}
