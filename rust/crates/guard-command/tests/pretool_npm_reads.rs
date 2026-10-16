use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn decide(
    environment_names: &[&str],
    shell_home: Option<&std::path::Path>,
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
        home: shell_home.map(|home| home.to_string_lossy().into_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
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
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        Some(&environment),
    )
    .decision
}

// Agents check a package before adding it and inspect the installed tree
// afterwards. Neither runs package code, so neither should need a person.
#[test]
fn registry_and_tree_reads_continue_unless_configuration_moves_npm() {
    let root = std::env::temp_dir().join(format!("guard-npm-reads-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let plain = root.join("plain");
    let clean = root.join("clean");
    let moved = root.join("moved");
    let nested = root.join("scoped").join("app");
    for directory in [&home, &plain, &clean, &moved, &nested] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join("package.json"), "{}\n").unwrap();
    }
    std::fs::write(
        clean.join(".npmrc"),
        "save-exact=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
    )
    .unwrap();
    std::fs::write(
        moved.join(".npmrc"),
        "registry=https://registry.example.test/\n//registry.example.test/:_authToken=${GITHUB_TOKEN}\n",
    )
    .unwrap();
    // npm may pick an ancestor's project config, so a parent counts too.
    std::fs::write(
        root.join("scoped").join(".npmrc"),
        "@scope:registry=https://registry.example.test/\n",
    )
    .unwrap();

    for (cwd, command) in [
        (&plain, "npm view zod version"),
        (&plain, "npm view zod version 2>&1 | tail -3"),
        (&plain, "npm info @types/node versions --json"),
        (&plain, "npm view zod@latest dist-tags.latest"),
        (&plain, "npm ls"),
        (&plain, "npm ls zod --depth=0"),
        (&plain, "npm cache ls"),
        (&plain, "npm cache ls zod"),
        (&plain, "npm cache ls zod 2>&1 | head -10"),
        (&plain, "npm cache ls zod 2>/dev/null | head"),
        (&clean, "npm view zod version"),
    ] {
        assert_eq!(
            decide(&[], Some(&home), command, &home, cwd),
            "allow",
            "{command} in {}",
            cwd.display()
        );
    }
    for (cwd, command) in [
        (&moved, "npm view zod version"),
        (&nested, "npm view zod version"),
        (
            &plain,
            "npm view zod --registry=https://registry.example.test/",
        ),
        (&plain, "npm view user/repo"),
        (&plain, "npm view zod@npm:other"),
        (&plain, "npm view"),
        (&plain, "npm ls -g"),
        (&plain, "npm install zod"),
        (&plain, "npm config get cache"),
        (&plain, "npm cache add zod"),
        (&plain, "npm cache clean --force"),
        (&plain, "npm cache verify"),
        (&plain, "npm cache ls --cache /tmp/x"),
        (&plain, "npm --registry=https://x cache ls"),
        (&moved, "npm cache ls zod"),
        (&plain, "touch notes.txt && npm view zod version"),
    ] {
        assert_ne!(
            decide(&[], Some(&home), command, &home, cwd),
            "allow",
            "{command} in {}",
            cwd.display()
        );
    }
    for name in [
        "npm_config_registry",
        "NPM_CONFIG_USERCONFIG",
        "NODE_OPTIONS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    ] {
        for command in ["npm view zod version", "npm cache ls zod"] {
            assert_ne!(
                decide(&[name], Some(&home), command, &home, &plain),
                "allow",
                "{name}: {command}"
            );
        }
    }
    // An added CA, as for a company's TLS-inspecting proxy, leaves the
    // registry where it was.
    assert_eq!(
        decide(
            &["NODE_EXTRA_CA_CERTS"],
            Some(&home),
            "npm view zod version",
            &home,
            &plain
        ),
        "allow"
    );

    // npm reads the user config from its own HOME, which must be the one checked.
    for shell_home in [None, Some(plain.as_path())] {
        assert_ne!(
            decide(&[], shell_home, "npm view zod version", &home, &plain),
            "allow"
        );
    }

    // The user's own config is read as well.
    std::fs::write(
        home.join(".npmrc"),
        "registry=https://registry.example.test/\n",
    )
    .unwrap();
    assert_ne!(
        decide(&[], Some(&home), "npm view zod version", &home, &plain),
        "allow"
    );
}
