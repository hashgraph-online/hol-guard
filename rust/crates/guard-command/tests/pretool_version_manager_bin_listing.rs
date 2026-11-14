#![cfg(unix)]
//! `ls -la ~/.nvm/versions/node/v24.1.0/bin/node` asks whether a runtime
//! version is installed. A version manager keeps one `bin` per installed
//! version a few components below its root, so the tool-bin listing rule,
//! which knew only `~/<tool>/bin`, sent the listing to review while the same
//! listing of `~/.bun/bin/bun` passed.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn fixture(label: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-version-manager-bin-listing")
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
    let cwd = home.join("work");
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            literal_words: &[],
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
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
        None,
    )
    .decision
}

const HARNESSES: [&str; 4] = ["zcode", "claude-code", "codex", "cursor"];

#[test]
fn a_version_managers_bin_lists_metadata_only() {
    let root = fixture("versioned-bin");
    let home = root.join("home");
    let node = home.join(".nvm/versions/node/v24.1.0");
    write(node.join("bin/node"), "binary");
    write(node.join("lib/node_modules/npm/bin/npm-cli.js"), "script");
    std::os::unix::fs::symlink(
        "../lib/node_modules/npm/bin/npm-cli.js",
        node.join("bin/npm"),
    )
    .unwrap();
    write(
        home.join(".fnm/node-versions/v22.3.0/installation/bin/node"),
        "binary",
    );
    write(home.join(".pyenv/versions/3.12.4/bin/python3.12"), "binary");
    write(home.join(".volta/bin/volta-shim"), "binary");
    write(home.join(".asdf/installs/ruby/3.3.0/bin/bundle"), "script");
    write(home.join(".asdf/plugins/ruby/bin/install"), "script");
    write(home.join(".nvm/.cache/bin/node"), "binary");
    write(home.join(".pyenv/versions/3.12.4/lib/notes"), "x");
    write(home.join(".ssh/id_rsa"), "key");
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), node.join("bin/leak")).unwrap();
    // A child link to a directory would let `ls -L` list its entries.
    std::os::unix::fs::symlink(home.join(".ssh"), node.join("bin/keys")).unwrap();
    // A version folder that is a link out of the tree is not an installed
    // version, so its `bin` is not one either.
    write(home.join(".ssh/bin/tool"), "binary");
    std::os::unix::fs::symlink(home.join(".ssh"), home.join(".nvm/versions/node/v9.0.0")).unwrap();

    for harness in HARNESSES {
        for allowed in [
            "ls -la ~/.nvm/versions/node/v24.1.0/bin/node",
            "ls -l ~/.nvm/versions/node/v24.1.0/bin/node ~/.nvm/versions/node/v24.1.0/bin/npm",
            "ls -la ~/.fnm/node-versions/v22.3.0/installation/bin/node",
            "ls -la ~/.pyenv/versions/3.12.4/bin/python3.12",
            "ls -la ~/.volta/bin/volta-shim",
            "ls -la ~/.asdf/installs/ruby/3.3.0/bin/bundle",
        ] {
            assert_eq!(
                decision(harness, allowed, &home),
                "allow",
                "{harness}: {allowed}"
            );
        }
        for denied in [
            "ls -la ~/.nvm/versions/node/v24.1.0/bin/leak",
            "ls -laL ~/.nvm/versions/node/v24.1.0/bin/keys",
            "ls -la ~/.nvm/versions/node/v9.0.0/bin/tool",
            "ls -la ~/.nvm/.cache/bin/node",
            "ls -la ~/.asdf/plugins/ruby/bin/install",
            "ls -la ~/.asdf/installs/.ruby/3.3.0/bin/bundle",
            "ls -la ~/.nvm/versions/node/v24.1.0/bin/../../../../../.ssh/id_rsa",
            "ls -la ~/.nvm/versions/node/.hidden/bin/node",
            "cat ~/.nvm/versions/node/v24.1.0/bin/node",
        ] {
            assert_ne!(
                decision(harness, denied, &home),
                "allow",
                "{harness}: {denied}"
            );
        }
    }
}
