#![cfg(unix)]
//! `stat` and `file` of programs a tool installed in a hidden home `bin`
//! folder. Their bytes stay behind the content screen; their metadata does
//! not need to.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const NODE: &str = ".nvm/versions/node/v24.0.0";

/// A home with installed programs, a key, and links between them. The root
/// stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-home-program-metadata")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    write(home.join("project/README.md"), "# Fixture\n");
    write(
        home.join(".cargo/bin/tool"),
        "\u{7f}ELF synthetic program\n",
    );
    write(
        home.join(".cargo/credentials.toml"),
        "[registry]\ntoken = \"synthetic\"\n",
    );
    write(
        home.join(".local/bin/script"),
        "#!/bin/sh\necho synthetic\n",
    );
    write(
        home.join(format!("{NODE}/bin/node")),
        "\u{7f}ELF synthetic node\n",
    );
    write(
        home.join(format!("{NODE}/lib/node_modules/npm/bin/npm-cli.js")),
        "console.log('synthetic');\n",
    );
    symlink(
        "../lib/node_modules/npm/bin/npm-cli.js",
        home.join(format!("{NODE}/bin/npm")),
    )
    .unwrap();
    write(home.join(".ssh/id_ed25519"), "SYNTHETIC KEY\n");
    symlink("../../.ssh/id_ed25519", home.join(".cargo/bin/sneaky")).unwrap();
    write(home.join(".claude/bin/helper"), "#!/bin/sh\n");
    write(home.join(".cargo/bin/.hidden"), "#!/bin/sh\n");
    std::fs::canonicalize(home).unwrap()
}

/// The decision both shell harnesses reach, or "mixed" when they differ. The
/// harness-stamped environment lets the Git configuration probe run.
fn shell(home: &Path, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
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
                home_dir: home.to_str(),
                cwd: project.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
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
fn installed_program_metadata_proceeds() {
    let home = home();
    for command in [
        "stat ~/.cargo/bin/tool".to_owned(),
        "file ~/.cargo/bin/tool".to_owned(),
        "file -b ~/.local/bin/script".to_owned(),
        "stat ~/.local/bin/script".to_owned(),
        format!("stat ~/{NODE}/bin/node"),
        format!("file -b ~/{NODE}/bin/node"),
        format!("stat ~/{NODE}/bin"),
        format!("file ~/{NODE}/bin/npm"),
        format!("stat -L ~/{NODE}/bin/npm"),
        format!("stat ~/.cargo/bin/tool ~/{NODE}/bin/node"),
        format!("stat {}/.cargo/bin/tool", home.display()),
    ] {
        assert_eq!(shell(&home, &command), "allow", "{command}");
    }
}

#[test]
fn program_bytes_keys_and_links_into_stores_still_ask() {
    let home = home();
    for command in [
        "cat ~/.cargo/bin/tool".to_owned(),
        "xxd ~/.cargo/bin/tool".to_owned(),
        format!("head -c 64 ~/{NODE}/bin/node"),
        "stat ~/.ssh/id_ed25519".to_owned(),
        "file ~/.ssh/id_ed25519".to_owned(),
        "stat ~/.ssh".to_owned(),
        "stat ~/.cargo/bin/sneaky".to_owned(),
        "file -L ~/.cargo/bin/sneaky".to_owned(),
        "stat ~/.cargo/credentials.toml".to_owned(),
        "stat ~/.cargo/bin/tool ~/.ssh/id_ed25519".to_owned(),
        "stat ~/.claude/bin/helper".to_owned(),
        "stat ~/.cargo/bin/.hidden".to_owned(),
        "stat ~/.cargo/bin/*".to_owned(),
    ] {
        assert_ne!(shell(&home, &command), "allow", "{command}");
    }
}
