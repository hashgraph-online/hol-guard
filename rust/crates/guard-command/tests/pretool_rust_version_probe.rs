use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn decide(harness: &str, command: &str, home: &std::path::Path, cwd: &std::path::Path) -> String {
    decide_with(harness, &[], command, home, cwd)
}

#[test]
fn rust_version_queries_are_allowed_unless_a_toolchain_file_selects_a_binary() {
    // Keep the fixture outside the system temporary directory so its
    // ancestors carry no toolchain file of their own.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/rust-version-probe")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let plain = root.join("plain");
    let channel = root.join("channel");
    let pinned = root.join("pinned");
    let nested = pinned.join("nested");
    let legacy = root.join("legacy");
    let linked = root.join("linked");
    let nested_plain = legacy.join("child");
    for directory in [
        &home,
        &plain,
        &channel,
        &nested,
        &legacy,
        &linked,
        &nested_plain,
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(
        channel.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.85.0\"\ncomponents = [\"clippy\"]\n",
    )
    .unwrap();
    std::fs::write(
        pinned.join("rust-toolchain.toml"),
        "[toolchain]\npath = \"/opt/synthetic-toolchain\"\n",
    )
    .unwrap();
    std::fs::write(legacy.join("rust-toolchain"), "../synthetic-toolchain\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        channel.join("rust-toolchain.toml"),
        linked.join("rust-toolchain.toml"),
    )
    .unwrap();
    // A symlinked working directory resolves below the pinned toolchain file,
    // which rustup reads even though the textual path does not contain it.
    #[cfg(unix)]
    let alias = root.join("alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&nested_plain, &alias).unwrap();
    // The nearest toolchain file decides, so an inert file below a pinned one
    // shadows it for rustup.
    std::fs::write(nested.join("rust-toolchain"), "stable\n").unwrap();

    for harness in ["codex", "claude-code", "omp"] {
        for (cwd, command, expected) in [
            (&plain, "cargo --version", "allow"),
            (&plain, "cargo -V", "allow"),
            (&plain, "rustc --version", "allow"),
            (&channel, "cargo --version", "allow"),
            (&nested, "cargo --version", "allow"),
            (&pinned, "cargo --version", "review"),
            (&pinned, "rustc -V", "review"),
            (&legacy, "cargo --version", "review"),
            (&plain, "cargo --version --verbose", "review"),
            (&plain, "cargo +nightly --version", "review"),
            (&plain, "cargo build", "review"),
            (&plain, "RUSTUP_TOOLCHAIN=nightly cargo --version", "review"),
            (&plain, "./cargo --version", "review"),
            (&plain, "npm --version", "allow"),
            (&plain, "bun --version", "allow"),
            (&plain, "npm install left-pad", "review"),
            (&plain, "cargo install ripgrep", "review"),
        ] {
            let decision = decide(harness, command, &home, cwd);
            let allowed = decision == "allow";
            assert_eq!(
                allowed,
                expected == "allow",
                "{harness} `{command}` in {}: {decision}",
                cwd.display()
            );
        }
        #[cfg(unix)]
        {
            assert_ne!(decide(harness, "cargo --version", &home, &linked), "allow");
            assert_ne!(decide(harness, "cargo --version", &home, &alias), "allow");
        }
        // The hook stamps the harness environment. rustup reads an inherited RUSTUP_TOOLCHAIN or RUSTUP_HOME before any
        // toolchain file, so either one keeps the probe on review.
        assert_eq!(
            decide_with(harness, &[], "cargo --version", &home, &plain),
            "allow"
        );
        for name in ["RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "rustup_toolchain"] {
            assert_ne!(
                decide_with(harness, &[name], "cargo --version", &home, &plain),
                "allow",
                "{harness} {name}"
            );
        }
    }
}

fn decide_with(
    harness: &str,
    environment_names: &[&str],
    command: &str,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap_or_default(),
        environment_names: environment_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&github_controls("enabled")),
        None,
        guard_command::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(&environment),
    )
    .decision
}
