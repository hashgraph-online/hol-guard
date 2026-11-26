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
    decision_with_home_match(harness, command, home, true)
}

// Match the caller's verified execution environment without rewriting the
// process-wide HOME (the test suite runs cases concurrently).
fn decision_with_home_match(
    harness: &str,
    command: &str,
    home: &Path,
    shell_home_matches: bool,
) -> String {
    use sha2::{Digest, Sha256};
    let cwd = home.join("work");
    // The production evaluator reconstructs PathContext from a stamped
    // execution environment; the caller's bare shell_home_matches field is
    // not authoritative. Stamp a full, valid environment for this test.
    let shell_home = if shell_home_matches {
        home.to_path_buf()
    } else {
        home.parent().unwrap().join("different-home")
    };
    let path = std::env::var("PATH").unwrap_or_default();
    let environment = std::collections::BTreeMap::from([
        ("HOME", shell_home.to_string_lossy().into_owned()),
        ("PATH", path.clone()),
    ]);
    let execution = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|name| (*name).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: Some(shell_home.to_string_lossy().into_owned()),
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
            npm_config_inert: false,
            pip_config_inert: false,
            python_environment_inert: false,
            shell_home_matches,
            ripgrep_config_absent: false,
            gem_config_absent: false,
            http_config_absent: false,
            openssl_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(&execution),
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
    write(
        home.join(".local/share/fnm/node-versions/v22.3.0/installation/bin/node"),
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
            "ls -la ~/.local/share/fnm/node-versions/v22.3.0/installation/bin/node",
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

/// A stamped HOME mismatch must never let a harmless declared-home filename
/// prove a different file that the shell actually expands from '~/'.  An
/// absolute operand is not affected by this mismatch.
#[test]
fn tilde_bin_probe_is_not_allowed_when_shell_home_differs() {
    let root = fixture("tilde-home-mismatch");
    let declared_home = root.join("home");
    let shell_home = root.join("different-home");
    let trusted = declared_home.join(".nvm/versions/node/v24.1.0/bin/node");
    write(trusted.clone(), "safe runtime fixture");
    let secret = shell_home.join("credentials.json");
    write(secret.clone(), "SYNTHETIC_FIXTURE_ONLY");
    let shell_path = shell_home.join(".nvm/versions/node/v24.1.0/bin/node");
    std::fs::create_dir_all(shell_path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, shell_path).unwrap();

    let tilde = "ls -la ~/.nvm/versions/node/v24.1.0/bin/node";
    // Prove that the real shell names a different path than Guard's declared
    // home. No actual credential file is read or copied.
    let result = std::process::Command::new("sh")
        .arg("-c")
        .arg(tilde)
        .env("HOME", &shell_home)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("credentials.json"));

    // The sibling node_modules/.bin metadata allowance reads exactly the
    // same tilde operand and must obey the same verified HOME proof.
    let shim = declared_home.join("work/project/node_modules/.bin/prettier");
    write(shim.clone(), "synthetic safe executable");
    let other_shim = shell_home.join("work/project/node_modules/.bin/prettier");
    std::fs::create_dir_all(other_shim.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, &other_shim).unwrap();
    let node_tilde = "ls -la ~/work/project/node_modules/.bin/prettier";
    let other_result = std::process::Command::new("sh")
        .arg("-c")
        .arg(node_tilde)
        .env("HOME", &shell_home)
        .output()
        .unwrap();
    assert!(other_result.status.success());
    assert!(String::from_utf8_lossy(&other_result.stdout).contains("credentials.json"));

    for harness in HARNESSES {
        assert_ne!(
            decision_with_home_match(harness, tilde, &declared_home, false),
            "allow",
            "{harness}: a mismatched shell HOME must retain review"
        );
        assert_eq!(
            decision_with_home_match(harness, tilde, &declared_home, true),
            "allow",
            "{harness}: a verified matching HOME should preserve the safe allow"
        );
        let absolute = format!("ls -la {}", trusted.display());
        assert_eq!(
            decision_with_home_match(harness, &absolute, &declared_home, false),
            "allow",
            "{harness}: an absolute, safe bin path is independent of tilde"
        );
        assert_ne!(
            decision_with_home_match(harness, node_tilde, &declared_home, false),
            "allow",
            "{harness}: a mismatched HOME must retain review of node_modules/.bin"
        );
        assert_eq!(
            decision_with_home_match(harness, node_tilde, &declared_home, true),
            "allow",
            "{harness}: matching HOME keeps benign node_modules/.bin listing allowed"
        );
        let absolute_shim = format!("ls -la {}", shim.display());
        assert_eq!(
            decision_with_home_match(harness, &absolute_shim, &declared_home, false),
            "allow",
            "{harness}: the absolute node_modules/.bin path does not depend on tilde"
        );
    }
}
