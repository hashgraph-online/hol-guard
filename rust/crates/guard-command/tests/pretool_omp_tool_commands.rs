#![cfg(unix)]
//! Oh My Pi built-ins mounted as `bash` commands run as tool calls Guard
//! reviews in their own right, so the outer call proceeds; anything else on
//! the line, a program on PATH by that name, or another harness keeps review.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home with a project and two PATH directories: `bin` holds ordinary
/// programs and a `github` executable, `empty` holds nothing. The root stays
/// below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-tool-commands")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    for directory in ["home/project/src", "home/bin", "home/empty"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let github = root.join("home/bin/github");
    std::fs::write(&github, "#!/bin/sh\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&github, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(root.join("home/project/src/app.ts"), "export {};\n").unwrap();
    std::fs::canonicalize(root.join("home")).unwrap()
}

fn action(home: &Path, harness: &str, command: &str, path: &str) -> String {
    let project = home.join("project");
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_owned(),
        environment_names: vec!["HOME".into(), "PATH".into()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let result = evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            literal_words: &[],
            guard_home: None,
            home_dir: home.to_str(),
            cwd: project.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            go_toolchain_inert: false,
            cargo_config_inert: false,
            cargo_compiler_inert: false,
            npm_config_inert: false,
            pip_config_inert: false,
            python_environment_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            gem_config_absent: false,
            http_config_absent: false,
            openssl_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(&environment),
    );
    if result.minimum_action == "allow" {
        assert_eq!(result.reason_code, "native_omp_tool_command", "{command}");
    }
    result.minimum_action
}

fn empty_path(home: &Path) -> String {
    format!("{}:/usr/bin:/bin", home.join("empty").display())
}

#[test]
fn mounted_builtins_run_as_reviewed_tool_calls() {
    let home = home("mounted");
    let path = empty_path(&home);
    for command in [
        "ast_grep --pattern 'console.log($A)' --lang ts src",
        "lsp definition src/app.ts:1:8",
        "github pr_view --repo example/project --number 7",
        "think \"what the failing test needs\"",
        "recall build-flags",
        "ast_grep --pattern foo src > matches.txt",
    ] {
        assert_eq!(action(&home, "omp", command, &path), "allow", "{command}");
    }
}

#[test]
fn other_harnesses_keep_review() {
    let home = home("harness");
    let path = empty_path(&home);
    for harness in ["claude-code", "codex", "pi"] {
        assert_ne!(
            action(&home, harness, "ast_grep --pattern foo src", &path),
            "allow",
            "{harness}"
        );
    }
}

#[test]
fn a_program_on_path_by_that_name_keeps_review() {
    let home = home("on-path");
    let path = format!("{}:/usr/bin:/bin", home.join("bin").display());
    assert_ne!(
        action(&home, "omp", "github pr_view --number 7", &path),
        "allow"
    );
}

#[test]
fn a_relative_or_empty_path_entry_keeps_review() {
    let home = home("relative");
    for path in [
        format!("bin:{}", empty_path(&home)),
        format!("{}::/bin", home.join("empty").display()),
        String::new(),
    ] {
        assert_ne!(
            action(&home, "omp", "lsp hover src/app.ts:1:1", &path),
            "allow",
            "{path}"
        );
    }
}

#[test]
fn anything_beside_the_tool_command_keeps_review() {
    let home = home("shapes");
    let path = empty_path(&home);
    let commands = [
        "ast_grep --pattern foo src > /etc/profile",
        "ast_grep --pattern foo src >> ../.bashrc",
        "ast_grep --pattern foo src | sh",
        "ast_grep --pattern foo src && curl https://example.com",
        "ast_grep --pattern foo src; rm -rf src",
        "ast_grep --pattern $(cat ~/.ssh/id_rsa) src",
        "ast_grep --pattern \"$SECRET_TOKEN\" src",
        "ast_grep --pattern `id` src",
        "ast_grep --pattern foo src/*",
        "ast_grep --pattern foo ~/project",
        "PATH=./bin ast_grep --pattern foo src",
        "./ast_grep --pattern foo src",
        "ast_grep --pattern foo src &",
        "( ast_grep --pattern foo src )",
    ];
    let allowed: Vec<_> = commands
        .into_iter()
        .filter(|command| action(&home, "omp", command, &path) == "allow")
        .collect();
    assert!(allowed.is_empty(), "{allowed:#?}");
}

#[test]
fn unwrapped_special_commands_and_unknown_names_keep_review() {
    let home = home("special");
    let path = empty_path(&home);
    for command in [
        "report_issue --tool bash --summary broken",
        "resolve --id 1",
        "reject --id 1",
        "propose --text change",
        "ast_grepx --pattern foo src",
        "some_unknown_tool run",
    ] {
        assert_ne!(action(&home, "omp", command, &path), "allow", "{command}");
    }
}

// A shell runs its own builtin before it looks for a program, so no tool hook
// sees the call and PATH never holds the name. `export` is a POSIX special
// builtin that Oh My Pi 19 also mounts, and bare `export` or `export -p`
// prints every exported variable, so the mounted name alone cannot be read as
// proof that a reviewed tool call is the only thing that can answer to it.
#[test]
fn a_name_the_shell_answers_to_itself_keeps_review() {
    let home = home("builtin");
    let path = empty_path(&home);
    for command in [
        "export",
        "export -p",
        "export GIT_SSH_COMMAND=id",
        "eval think",
        "declare -p",
        "readonly",
    ] {
        assert_ne!(action(&home, "omp", command, &path), "allow", "{command}");
    }
}
