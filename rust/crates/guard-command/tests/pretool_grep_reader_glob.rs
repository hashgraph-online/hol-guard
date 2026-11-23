#![cfg(unix)]
//! `grep -l TODO ~/scratch/tool/*.py` names one folder and a pattern for its
//! files. Without `-r` grep opens each match once, exactly as `cat` would, yet
//! the grep proof only expanded a pattern inside a repository below home, so
//! the search went to review while `cat ~/scratch/tool/*.py` passed.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn fixture(label: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-reader-glob")
        .join(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home/work")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn decision(harness: &str, command: &str, home: &Path) -> String {
    decision_with(harness, command, home, home)
}

/// `shell_home` is the HOME the shell expands `~` from, stamped the way a
/// harness hook stamps it.
fn decision_with(harness: &str, command: &str, home: &Path, shell_home: &Path) -> String {
    let cwd = home.join("work");
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(shell_home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            literal_words: &[],
            guard_home: None,
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
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
    )
    .decision
}

const HARNESSES: [&str; 4] = ["zcode", "claude-code", "codex", "cursor"];

#[test]
fn grep_over_a_file_glob_outside_a_repository_reads_like_cat() {
    let root = fixture("reader-glob");
    let home = root.join("home");
    let tool = home.join("scratch/tool");
    write(tool.join("setup.py"), "# TODO\n");
    write(tool.join("server.py"), "print(1)\n");
    write(tool.join("notes.txt"), "TODO\n");
    let mixed = home.join("scratch/mixed");
    write(mixed.join("app.py"), "x\n");
    write(mixed.join(".env"), "TOKEN=x\n");
    let keys = home.join("scratch/keys");
    write(keys.join("id_rsa.pem"), "key\n");
    write(keys.join("credentials.json"), "{}\n");
    let nested = home.join("scratch/nested");
    write(nested.join("a.txt"), "x\n");
    write(nested.join("sub/.env"), "TOKEN=x\n");
    write(home.join(".ssh/config"), "Host x\n");
    let absolute = tool.to_str().unwrap().to_owned();

    for harness in HARNESSES {
        for allowed in [
            "grep -l TODO ~/scratch/tool/*.py".to_owned(),
            "grep -n print ~/scratch/tool/s*.py".to_owned(),
            format!("grep -c TODO {absolute}/*.py {absolute}/notes.txt"),
        ] {
            assert_eq!(
                decision(harness, &allowed, &home),
                "allow",
                "{harness}: {allowed}"
            );
        }
        // The shell expands `~` from its own `HOME`, so a `~` pattern measured
        // in a different declared home proves nothing; the absolute spelling
        // still does.
        assert_ne!(
            decision_with(harness, "grep -l TODO ~/scratch/tool/*.py", &home, &root),
            "allow",
            "{harness}: ~ with a different shell home"
        );
        assert_eq!(
            decision_with(
                harness,
                &format!("grep -l TODO {absolute}/*.py"),
                &home,
                &root
            ),
            "allow",
            "{harness}: absolute pattern with a different shell home"
        );
        for denied in [
            // `*` under dotglob would also read `.env`.
            "grep -l x ~/scratch/mixed/*",
            "grep x ~/scratch/keys/*.pem",
            "grep x ~/scratch/keys/*.json",
            "grep -r x ~/scratch/nested/*",
            "grep -l x ~/scratch/nested/* -r",
            "grep -l x ~/scratch/nested/* --directories=recurse",
            "grep x ~/.ssh/*",
        ] {
            assert_ne!(
                decision(harness, denied, &home),
                "allow",
                "{harness}: {denied}"
            );
        }
    }
}
