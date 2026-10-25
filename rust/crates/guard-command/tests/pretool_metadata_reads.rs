#![cfg(unix)]
//! Disk usage, filesystem, file comparison and Git configuration reads.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// A home holding one committed project. The root stays below the target
/// directory: `$TMPDIR` on macOS resolves under `/private/var`, which the
/// sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-metadata-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    write(project.join("README.md"), "# Fixture\n");
    write(project.join("src/one.ts"), "export const one = 1;\n");
    write(project.join("src/two.ts"), "export const two = 2;\n");
    write(project.join("old/one.ts"), "export const one = 0;\n");
    write(
        home.join(".gitconfig"),
        "[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
    );
    git(&project, &["init", "--quiet"]);
    git(&project, &["config", "user.name", "Fixture"]);
    git(
        &project,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&project, &["add", "."]);
    git(&project, &["commit", "--quiet", "-m", "Synthetic baseline"]);
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
        library_search_paths: Default::default(),
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
                home_dir: home.to_str(),
                cwd: project.to_str(),
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
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn size_and_comparison_reads_proceed() {
    let home = home();
    for command in [
        "du -sh src",
        "du -sh",
        "du -h -d 1 src",
        "du -sh src old --max-depth=0",
        "df -h",
        "df -h /tmp",
        "df -kP .",
        "pwd && df -h /tmp | tail -1",
        "diff README.md src/one.ts",
        "diff -u src/one.ts old/one.ts",
        "diff -ru src old",
        "diff --brief src old",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn unproven_size_and_comparison_reads_still_ask() {
    let home = home();
    write(home.join("project/src/.env"), "SYNTHETIC=1\n");
    for command in [
        "du --files0-from=list",
        "du -sh ~/.ssh",
        "du -ah src",
        "du -h src",
        "du -h -d 1 src",
        "du -shL src",
        "du -L -s src",
        "df -h $(cat list)",
        "diff -r src old",
        "diff src/.env README.md",
        "diff - README.md",
        "diff --from-file=README.md src/one.ts old/one.ts",
        "diff README.md",
    ] {
        assert!(!shell(&home, command).contains("allow"), "{command}");
    }
}

#[test]
fn a_comparison_that_reads_through_a_link_still_asks() {
    let home = home();
    write(home.join("outside/notes.md"), "# Outside\n");
    std::os::unix::fs::symlink(
        home.join("outside/notes.md"),
        home.join("project/src/linked.md"),
    )
    .unwrap();
    // `diff -r` opens what the link points at, so the target needs proof of
    // its own and the comparison keeps asking.
    assert!(!shell(&home, "diff -ru src old").contains("allow"));
    // A recursive search lists the same link without reading through it, so
    // the walk is proven by what it would actually open.
    assert_eq!(shell(&home, "grep -rn export src"), "allow");
}

#[test]
fn configuration_reads_proceed() {
    let home = home();
    for command in [
        "git config user.name",
        "git config --get user.email",
        "git config --list --show-origin",
        "git config -l",
        "git config --global --get user.name",
        "git config --get-regexp ^user",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

/// A long-lived clone records a remote and merge ref for every branch it ever
/// tracked; the listing then runs well past a quarter megabyte.
#[test]
fn configuration_reads_proceed_in_a_long_lived_clone() {
    let home = home();
    let config = home.join("project/.git/config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    for branch in 0..8_000 {
        text.push_str(&format!(
            "[branch \"feature/b{branch}\"]\n\tremote = origin\n\tmerge = refs/heads/feature/b{branch}\n"
        ));
    }
    std::fs::write(&config, &text).unwrap();
    assert!(text.len() > 512 * 1024);
    for command in ["git config --get user.email", "git config --list"] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
    text.push_str("[github]\n\ttoken = synthetic\n");
    std::fs::write(&config, text).unwrap();
    assert!(!shell(&home, "git config --list").contains("allow"));
    assert_eq!(shell(&home, "git config --get user.email"), "allow");
}

#[test]
fn configuration_writes_and_credentials_still_ask() {
    let home = home();
    for command in [
        "git config user.name Someone",
        "git config --unset user.name",
        "git config --file ../other.config --list",
        "git config -e",
    ] {
        assert!(!shell(&home, command).contains("allow"), "{command}");
    }
    for entry in [
        "[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic synthetic\n",
        "[github]\n\ttoken = synthetic\n",
        "[remote \"origin\"]\n\turl = https://user:synthetic@example.com/repo.git\n",
        "[remote \"origin\"]\n\turl = https://example.com/repo.git?access_token=synthetic\n",
    ] {
        let home = self::home();
        let config = home.join("project/.git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(entry);
        std::fs::write(&config, text).unwrap();
        assert!(
            !shell(&home, "git config --list").contains("allow"),
            "{entry}"
        );
        // A read of an unrelated key prints none of it.
        assert_eq!(shell(&home, "git config user.name"), "allow", "{entry}");
    }
}

#[test]
fn a_configured_pager_still_asks() {
    let home = home();
    git(&home.join("project"), &["config", "pager.config", "less"]);
    assert!(!shell(&home, "git config --list").contains("allow"));

    // Listing forms page through core.pager by default; a single get does not.
    let home = self::home();
    git(&home.join("project"), &["config", "core.pager", "less -R"]);
    assert!(!shell(&home, "git config --list").contains("allow"));
    assert!(!shell(&home, "git config --get-all user.name").contains("allow"));
    assert_eq!(shell(&home, "git config user.name"), "allow");
}

#[test]
fn summaries_still_proceed_beside_hidden_directories() {
    let home = home();
    write(home.join("project/src/.env"), "SYNTHETIC=1\n");
    for command in ["du -sh src", "du -h --max-depth=0 src", "du -s -d 0 src"] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn file_type_probes_proceed_but_magic_loads_and_secrets_ask() {
    let home = home();
    write(home.join(".ssh/id_rsa"), "synthetic\n");
    write(home.join("project/src/.env"), "SYNTHETIC=1\n");
    for command in [
        "file /bin/ls",
        "file -b --mime-type src/one.ts",
        "file -L README.md src",
        "file -- src/one.ts missing.bin",
        "file README.md | head -1",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
    for command in [
        "file",
        "file ~/.ssh/id_rsa",
        "file ~/.ssh/missing",
        "file src/.env",
        "file -m ../magic README.md",
        "file --magic-file=../magic README.md",
        "file -f list.txt",
        "file --files-from list.txt",
        "file -C -m magic",
        "file -z README.md",
        "file -s /dev/sda",
        "file -p README.md",
        "file -",
        "file /etc/passwd",
    ] {
        assert!(!shell(&home, command).contains("allow"), "{command}");
    }
}
