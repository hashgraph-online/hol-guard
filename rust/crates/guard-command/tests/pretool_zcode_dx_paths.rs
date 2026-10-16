#![cfg(unix)]
//! Ordinary listings, reads and launcher diagnostics that were paused only
//! because of dot names, tool symlinks or a same-named directory.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn fixture(label: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-zcode-dx-paths")
        .join(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn decide(tool: &str, input: serde_json::Value, home: &Path, cwd: &Path) -> String {
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": input}),
            None,
            None,
            PathContext {
                home_dir: home.to_str(),
                cwd: cwd.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
            },
            None,
        )
        .decision
    });
    assert_eq!(omp, zcode, "harness decisions differ");
    omp
}

fn shell(command: &str, home: &Path, cwd: &Path) -> String {
    decide("bash", json!({"command": command}), home, cwd)
}

#[test]
fn missing_git_marker_probe_is_allowed_but_other_dot_leaves_are_not() {
    let root = fixture("git-probe");
    let home = root.join("home");
    let org = home.join("org");
    std::fs::create_dir_all(org.join("app")).unwrap();
    let org_text = org.to_str().unwrap();
    let probe = format!(
        "ls -d {org_text}/.git 2>/dev/null; ls {org_text} | grep -iE 'app|site' | head -20"
    );
    assert_eq!(shell(&probe, &home, &org), "allow");
    for denied in [
        format!("ls -d {org_text}/.ssh"),
        format!("ls {org_text}/.env"),
        format!("ls {org_text}/.aws"),
        format!("ls {org_text}/.git/config"),
        format!("ls {org_text}/.git.d"),
    ] {
        assert_ne!(shell(&denied, &home, &org), "allow", "{denied}");
    }
}

#[test]
fn existing_empty_hidden_marker_file_in_a_work_tree_lists_and_reads() {
    let root = fixture("hidden-file");
    let home = root.join("home");
    let app = home.join("org/app");
    std::fs::create_dir_all(app.join(".git")).unwrap();
    write(app.join(".deploy-success"), "");
    write(app.join(".state-note"), "not empty\n");
    write(app.join(".env"), "");
    write(app.join(".npmrc"), "");
    let cwd = home.join("org");
    let marker = app.join(".deploy-success");
    let marker_text = marker.to_str().unwrap();
    assert_eq!(
        shell(&format!("ls -la {marker_text}"), &home, &cwd),
        "allow"
    );
    assert_eq!(
        decide("read", json!({"file_path": marker_text}), &home, &cwd),
        "allow"
    );
    // A non-empty hidden file may be listed (metadata) but never read.
    let note = app.join(".state-note");
    assert_ne!(
        decide(
            "read",
            json!({"file_path": note.to_str().unwrap()}),
            &home,
            &cwd
        ),
        "allow"
    );
    for denied in [app.join(".env"), app.join(".npmrc")] {
        let text = denied.to_str().unwrap();
        assert_ne!(
            decide("read", json!({"file_path": text}), &home, &cwd),
            "allow",
            "{text}"
        );
        assert_ne!(
            shell(&format!("ls -la {text}"), &home, &cwd),
            "allow",
            "{text}"
        );
    }
}

#[test]
fn tool_bin_directories_list_metadata_only() {
    let root = fixture("tool-bin");
    let home = root.join("home");
    let cwd = home.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    write(home.join(".bun/bin/bun"), "binary");
    write(home.join(".cargo/bin/tool"), "binary");
    write(home.join(".local/bin/helper"), "binary");
    write(home.join(".bun/install/cache/secret"), "x");
    write(home.join(".cargo/credentials.toml"), "token");
    write(home.join(".local/share/data"), "x");
    write(home.join(".ssh/id_rsa"), "key");
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), home.join(".local/bin/leak")).unwrap();
    // A child link to a directory would let `ls -a` or `ls -L` list its entries.
    write(home.join("work/secrets/notes"), "x");
    std::os::unix::fs::symlink(home.join("work/secrets"), home.join(".local/bin/dir")).unwrap();
    // A package-manager prefix: the visible name is a symlink to its target.
    write(root.join("prefix/Cellar/node/1/bin/npm"), "script");
    std::fs::create_dir_all(root.join("prefix/bin")).unwrap();
    std::os::unix::fs::symlink("../Cellar/node/1/bin/npm", root.join("prefix/bin/npm")).unwrap();
    for allowed in [
        "ls -la ~/.bun/bin/bun".to_owned(),
        "ls -la ~/.bun/bin".to_owned(),
        "ls -la ~/.cargo/bin/tool".to_owned(),
        "ls -la ~/.local/bin/helper".to_owned(),
        format!("ls -la {}/prefix/bin/npm", root.display()),
        // A home dot-directory that stores no credentials lists by name.
        "ls -la ~/.bun".to_owned(),
    ] {
        assert_eq!(shell(&allowed, &home, &cwd), "allow", "{allowed}");
    }
    for denied in [
        "ls -la ~/.bun/install/cache/secret",
        "ls -la ~/.cargo/credentials.toml",
        "ls -la ~/.local/share/data",
        "ls -la ~/.local/bin/leak",
        "ls -la ~/.local/bin/dir",
        "ls -a ~/.local/bin/dir",
        "ls -laL ~/.local/bin/dir",
        "ls -la ~/.local/bin/../share/data",
        "cat ~/.bun/bin/bun",
    ] {
        assert_ne!(shell(denied, &home, &cwd), "allow", "{denied}");
    }
}

#[test]
fn a_directory_named_like_the_launcher_does_not_shadow_it() {
    let root = fixture("launcher");
    let home = root.join("home");
    let cwd = home.join("work");
    std::fs::create_dir_all(cwd.join("hol-guard")).unwrap();
    for command in ["hol-guard status", "hol-guard --version"] {
        assert_eq!(shell(command, &home, &cwd), "allow", "{command}");
    }
    std::fs::remove_dir(cwd.join("hol-guard")).unwrap();
    write(cwd.join("hol-guard"), "#!/bin/sh\n");
    assert_ne!(shell("hol-guard status", &home, &cwd), "allow");
    std::fs::remove_file(cwd.join("hol-guard")).unwrap();
    std::os::unix::fs::symlink(&home, cwd.join("hol-guard")).unwrap();
    assert_ne!(shell("hol-guard status", &home, &cwd), "allow");
}
