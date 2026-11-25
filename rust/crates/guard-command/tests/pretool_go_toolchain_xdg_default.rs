//! `go version` and named `go env` reads under a shell that exports the
//! default `XDG_CONFIG_HOME`.
//!
//! Many shells export `XDG_CONFIG_HOME=$HOME/.config`. That value names the
//! go environment file the probe already reads, so it must not turn a plain
//! toolchain query into a review. Any other value, or a name with no stamped
//! value, still keeps the review.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use guard_contracts::GuardExecutionEnvironmentV1;
use serde_json::json;

struct FixtureCleanup(std::path::PathBuf);

impl Drop for FixtureCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn go_queries_stay_quiet_under_the_default_xdg_config_home_only() {
    let root = std::env::temp_dir().join(format!("guard-go-xdg-{}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let home_text = home.to_str().unwrap().to_owned();
    let default_config = home.join(".config").to_str().unwrap().to_owned();
    let other_config = root.join("elsewhere").to_str().unwrap().to_owned();

    let stamp = |names: &[&str], xdg: Option<&str>| GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: Some(home_text.clone()),
        xdg_config_home: xdg.map(str::to_owned),
        ..Default::default()
    };
    let decide = |command: &str, environment: &GuardExecutionEnvironmentV1| {
        evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                literal_words: &[],
                guard_home: None,
                home_dir: Some(&home_text),
                cwd: workspace.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
                go_toolchain_inert: false,
                cargo_config_inert: false,
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
            Some(environment),
        )
        .decision
    };

    for command in ["go version", "go env GOPATH"] {
        assert_eq!(
            decide(command, &stamp(&[], None)),
            "allow",
            "{command} with no Go setting exported"
        );
        assert_eq!(
            decide(command, &stamp(&["XDG_CONFIG_HOME"], Some(&default_config))),
            "allow",
            "{command} with XDG_CONFIG_HOME naming ~/.config"
        );
        assert_ne!(
            decide(command, &stamp(&["XDG_CONFIG_HOME"], Some(&other_config))),
            "allow",
            "{command} with XDG_CONFIG_HOME naming another directory"
        );
        assert_ne!(
            decide(command, &stamp(&["XDG_CONFIG_HOME"], None)),
            "allow",
            "{command} with XDG_CONFIG_HOME exported but its value unseen"
        );
        assert_ne!(
            decide(
                command,
                &stamp(&["XDG_CONFIG_HOME", "GOTOOLCHAIN"], Some(&default_config))
            ),
            "allow",
            "{command} with the default XDG_CONFIG_HOME beside GOTOOLCHAIN"
        );
    }

    // A go environment file under the default directory is still read: one
    // that picks a toolchain keeps the review.
    let go_config = home.join(".config").join("go");
    std::fs::create_dir_all(&go_config).unwrap();
    std::fs::write(go_config.join("env"), "GOTOOLCHAIN=go1.99.0\n").unwrap();
    assert_ne!(
        decide(
            "go version",
            &stamp(&["XDG_CONFIG_HOME"], Some(&default_config))
        ),
        "allow",
        "go version with a stored GOTOOLCHAIN under ~/.config"
    );
}
