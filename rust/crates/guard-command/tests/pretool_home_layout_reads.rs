//! Agents commonly work from a directory that holds several repositories
//! below home (`~/Code/org/app-portal`, `~/Code/org/service-api`). Read-only
//! searches and Git inspection that name a child or sibling repository by its
//! absolute or `~` path are ordinary work and must not ask for review, while
//! hidden, linked-away, sensitive and helper-configured targets still do.
use serde_json::json;
use std::path::{Path, PathBuf};

use crate::git_helper_fixture as fixture;

fn git(directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // Git for Windows maps `/dev/null` to the null device; some releases
        // reject a literal `NUL` here with "unable to access 'NUL'".
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

pub(crate) fn decide(cwd: &Path, home: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

pub(crate) fn repository(path: &Path) {
    std::fs::create_dir_all(path.join(".github/workflows")).unwrap();
    std::fs::create_dir_all(path.join("src")).unwrap();
    std::fs::write(path.join(".github/workflows/ci.yml"), "name: ci\n").unwrap();
    std::fs::write(path.join("src/main.rs"), "fn main() {} // fixture\n").unwrap();
    git(path, &["init", "--quiet"]);
    git(path, &["add", "."]);
    git(path, &["commit", "--quiet", "-m", "fixture"]);
}

pub(crate) struct Layout {
    _cleanup: fixture::FixtureCleanup,
    pub(crate) home: PathBuf,
    pub(crate) org: PathBuf,
}

/// `CARGO_TARGET_TMPDIR` keeps the fixture outside `/var` and dot
/// directories on macOS, which the read screens would otherwise refuse for
/// reasons unrelated to the layout under test.
pub(crate) fn layout(name: &str) -> Layout {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "home-layout-{name}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let cleanup = fixture::FixtureCleanup(root.clone());
    let home = root.join("home");
    let org = home.join("Code").join("org");
    std::fs::create_dir_all(&org).unwrap();
    let home = fixture::canonical_spelling(home);
    let org = fixture::canonical_spelling(org);
    repository(&org.join("app-portal"));
    repository(&org.join("service-api"));
    Layout {
        _cleanup: cleanup,
        home,
        org,
    }
}

pub(crate) fn assert_decision(cwd: &Path, home: &Path, command: &str, allowed: bool) {
    let result = decide(cwd, home, command);
    assert_eq!(
        result.decision == "allow",
        allowed,
        "{command}: {} {}",
        result.decision,
        result.reason_code
    );
}

#[test]
fn search_of_child_repository_by_absolute_or_home_path_is_allowed() {
    let layout = layout("rg");
    let child = layout.org.join("app-portal");
    for command in [
        format!("rg -n fixture {}", fixture::shell_word(&child)),
        format!("rg -n fixture {}/src", fixture::shell_word(&child)),
        "rg -n fixture ~/Code/org/app-portal".to_owned(),
        "rg -n fixture app-portal".to_owned(),
    ] {
        assert_decision(&layout.org, &layout.home, &command, true);
    }
}

#[test]
fn search_root_that_is_hidden_linked_away_or_sensitive_is_reviewed() {
    let layout = layout("rg-negative");
    let hidden = layout.org.join(".private-notes");
    std::fs::create_dir_all(&hidden).unwrap();
    std::fs::write(hidden.join("notes.md"), "fixture\n").unwrap();
    std::fs::create_dir_all(layout.home.join(".ssh")).unwrap();
    // Only unix adds a symlinked case below.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut commands = vec![
        format!("rg -n fixture {}", fixture::shell_word(&hidden)),
        format!(
            "rg -n fixture {}",
            fixture::shell_word(&layout.home.join(".ssh"))
        ),
        "rg -n fixture ~/.ssh".to_owned(),
        format!("rg -n fixture {}/../org", fixture::shell_word(&layout.org)),
    ];
    #[cfg(unix)]
    {
        let link = layout.org.join("notes-link");
        std::os::unix::fs::symlink(&hidden, &link).unwrap();
        commands.push(format!("rg -n fixture {}", fixture::shell_word(&link)));
    }
    for command in commands {
        assert_decision(&layout.org, &layout.home, &command, false);
    }
}

#[test]
fn git_inspection_of_sibling_repository_below_home_is_allowed() {
    let layout = layout("git-sibling");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    for command in [
        "git -C ../service-api log --oneline -3".to_owned(),
        format!("git -C {} status --short", fixture::shell_word(&sibling)),
        "git -C ~/Code/org/service-api diff --stat".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    assert_decision(
        &layout.org,
        &layout.home,
        "git -C app-portal log --oneline -1",
        true,
    );
}

#[test]
fn git_route_to_hidden_home_or_helper_configured_repository_is_reviewed() {
    let layout = layout("git-negative");
    let cwd = layout.org.join("app-portal");
    let hidden = layout.home.join(".config-repo");
    repository(&hidden);
    let helper = layout.org.join("helper-repo");
    repository(&helper);
    git(&helper, &["config", "core.fsmonitor", "./monitor.sh"]);
    let plain = layout.org.join("plain-directory");
    std::fs::create_dir_all(&plain).unwrap();
    for command in [
        format!("git -C {} log --oneline -1", fixture::shell_word(&hidden)),
        "git -C ~ status --short".to_owned(),
        "git -C ../helper-repo status --short".to_owned(),
        format!("git -C {} status --short", fixture::shell_word(&plain)),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

#[test]
fn git_inspection_of_linked_worktree_below_home_is_allowed_unless_forged() {
    let layout = layout("git-worktree");
    let repository = layout.org.join("app-portal");
    let linked = layout.org.join("app-portal-feature");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature",
            linked.to_str().unwrap(),
        ],
    );
    let cwd = layout.org.join("service-api");
    for command in [
        "git -C ../app-portal-feature diff --stat".to_owned(),
        format!("git -C {} log --oneline -1", fixture::shell_word(&linked)),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    // A copied `.git` file names the registry entry, but the entry's
    // backlink still names the real worktree.
    let forged = layout.org.join("forged-checkout");
    std::fs::create_dir_all(&forged).unwrap();
    std::fs::copy(linked.join(".git"), forged.join(".git")).unwrap();
    assert_decision(
        &cwd,
        &layout.home,
        "git -C ../forged-checkout status --short",
        false,
    );
}

/// Agents also keep a multi-repository parent and its sibling worktrees in
/// the shared temporary directory. A sibling there is routable only while
/// every directory below `/tmp` belongs to the user and no one else can write
/// to it.
#[cfg(unix)]
#[test]
fn git_inspection_of_owned_sibling_below_tmp_is_allowed_unless_shared() {
    use std::os::unix::fs::PermissionsExt;
    let layout = layout("git-tmp");
    let scratch = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-tmp-siblings-{}", std::process::id()));
    let _cleanup = fixture::FixtureCleanup(scratch.clone());
    let org = scratch.join("org");
    std::fs::create_dir_all(&org).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    repository(&org.join("app"));
    let linked = scratch.join("app-followup");
    git(
        &org.join("app"),
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "followup",
            linked.to_str().unwrap(),
        ],
    );
    // The umask may leave group write on directories made above.
    for directory in [&org, &org.join("app"), &linked] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for command in [
        format!("git -C {} log --oneline -3", fixture::shell_word(&linked)),
        format!("git -C {} status --short", fixture::shell_word(&linked)),
        format!(
            "git -C {}/org/app rev-parse HEAD",
            fixture::shell_word(&scratch)
        ),
    ] {
        assert_decision(&org, &layout.home, &command, true);
    }
    let shared = scratch.join("shared");
    repository(&shared);
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_decision(
        &org,
        &layout.home,
        &format!("git -C {} log --oneline -1", fixture::shell_word(&shared)),
        false,
    );
}

#[test]
fn quoted_home_or_variable_roots_are_reviewed_and_rootless_fd_matches_dot() {
    let layout = layout("quoted-roots");
    let cwd = layout.org.join("app-portal");
    let escaped_tilde = "rg -n fixture \\~/Code/org/app-portal";
    let mut literal_home = vec![
        "rg -n fixture '~/Code/org/app-portal'",
        "fd -e rs main '~/Code/org/app-portal'",
    ];
    // A POSIX shell reads `\~` as a literal tilde. PowerShell and cmd keep
    // the backslash, so on Windows the word names `\~\Code\...` at the root
    // of the current drive, never the home folder, and is not proven.
    if cfg!(windows) {
        assert_decision(&cwd, &layout.home, escaped_tilde, false);
    } else {
        literal_home.push(escaped_tilde);
    }
    // With no `~` entry in the cwd the literal path names nothing.
    for &command in &literal_home {
        assert_decision(&cwd, &layout.home, command, true);
    }
    for command in [
        "fd -e rs main --search-path=~/Code/org/app-portal",
        "fd . \"$HOME\"",
        "git -C '~/Code/org/service-api' status --short",
        "git -C \"~/Code/org/service-api\" diff --stat",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
    // With the shell's HOME the declared home, `$HOME` names it as a literal
    // path does. Only a POSIX home is substituted.
    assert_decision(&cwd, &layout.home, "fd . $HOME/Code/org", !cfg!(windows));
    // A rootless fd lists the cwd, exactly like an explicit `.` root.
    for directory in [&layout.home, &cwd] {
        assert_eq!(
            decide(directory, &layout.home, "fd -e rs main").decision,
            decide(directory, &layout.home, "fd -e rs main .").decision,
        );
    }
    for command in [
        "fd -e rs main",
        "fd -e rs main ~/Code/org/app-portal",
        "fd -e rs main --search-path ~/Code/org",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
    // Once the cwd holds a `~` entry, the literal path reads something else.
    std::fs::create_dir(cwd.join("~")).unwrap();
    for &command in &literal_home {
        assert_decision(&cwd, &layout.home, command, false);
        // The same cwd spelled from home still sees its `~` entry.
        let spelled = Path::new("~/Code/org/app-portal");
        assert_ne!(
            decide(spelled, &layout.home, command).decision,
            "allow",
            "{command}"
        );
    }
}

#[test]
fn search_of_sibling_repository_by_absolute_home_or_parent_path_is_allowed() {
    let layout = layout("rg-sibling");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    for command in [
        format!("rg -n fixture {}", fixture::shell_word(&sibling)),
        format!("rg -n fixture {}/src", fixture::shell_word(&sibling)),
        "rg -n fixture ~/Code/org/service-api".to_owned(),
        "rg -n fixture ../service-api".to_owned(),
        "rg -n fixture ../service-api/src".to_owned(),
        "rg --files ../service-api".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
}

#[test]
fn search_of_sibling_outside_a_real_repository_or_with_hidden_flags_is_reviewed() {
    let layout = layout("rg-sibling-negative");
    let cwd = layout.org.join("app-portal");
    let plain = layout.org.join("plain-notes");
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(plain.join(".env"), "TOKEN=fixture\n").unwrap();
    // Only unix adds a symlinked case below.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut commands = vec![
        "rg -n fixture ..".to_owned(),
        "rg -n fixture ../plain-notes".to_owned(),
        format!("rg -n fixture {}", fixture::shell_word(&plain)),
        "rg --hidden -n fixture ../service-api".to_owned(),
        "rg -uu -n fixture ../service-api".to_owned(),
        "rg --no-ignore -n fixture ~/Code/org/service-api".to_owned(),
        "rg -n fixture ../service-api/.git".to_owned(),
        "rg -n fixture ../../..".to_owned(),
    ];
    #[cfg(unix)]
    {
        // A `.git` link to another repository does not make a repository root.
        let forged = layout.org.join("forged");
        std::fs::create_dir_all(&forged).unwrap();
        std::fs::write(forged.join(".env"), "TOKEN=fixture\n").unwrap();
        std::os::unix::fs::symlink(layout.org.join("service-api/.git"), forged.join(".git"))
            .unwrap();
        commands.push("rg -n fixture ../forged".to_owned());
    }
    for command in commands {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

pub(crate) fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn sibling_search_prunes_plainly_gitignored_directories() {
    let layout = layout("rg-sibling-ignored");
    let sibling = layout.org.join("service-api");
    write(
        sibling.join(".gitignore"),
        "# build output\n/target\nnode_modules/\ncerts/\n",
    );
    write(sibling.join("target/debug/server.pem"), "fixture\n");
    write(sibling.join("node_modules/pkg/credentials.json"), "{}\n");
    write(sibling.join("web/certs/client.p12"), "fixture\n");
    let cwd = layout.org.join("app-portal");
    assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", true);
    assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api/web", true);
    // Named on the command line, an ignored directory is still searched.
    assert_decision(
        &cwd,
        &layout.home,
        "rg -n fixture ../service-api/target",
        false,
    );
    assert_decision(
        &cwd,
        &layout.home,
        "rg -n fixture ../service-api/web/certs",
        false,
    );
}

/// Each case re-includes a file the search then reaches, which is what makes
/// the rule matter. A rule naming a file that is not there decides nothing,
/// and is covered beside the negation tests.
#[test]
fn sibling_search_whose_ignore_rules_could_widen_it_is_reviewed() {
    let cases: [(&str, &[(&str, &str)]); 6] = [
        (
            "dot-ignore",
            &[(".ignore", "!.env\n"), (".env", "TOKEN=fixture\n")],
        ),
        ("rgignore", &[("src/.rgignore", "!.env\n")]),
        (
            "negated",
            &[
                (".gitignore", "target\n!.env\n"),
                (".env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "nested-negated",
            &[
                ("src/.gitignore", "!.env\n"),
                ("src/.env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "exclude",
            &[
                (".git/info/exclude", "!.env\n"),
                (".env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "credentials",
            &[("config/credentials.txt", "TOKEN=fixture\n")],
        ),
    ];
    for (name, files) in cases {
        let layout = layout(&format!("rg-sibling-{name}"));
        let sibling = layout.org.join("service-api");
        for (path, text) in files {
            write(sibling.join(path), text);
        }
        let cwd = layout.org.join("app-portal");
        assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", false);
    }
    let layout = layout("rg-sibling-parent-ignore");
    write(layout.org.join(".ignore"), "!.env\n");
    let cwd = layout.org.join("app-portal");
    assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", false);

    let nested = self::layout("rg-sibling-subdirectory");
    let sibling = nested.org.join("service-api");
    write(sibling.join("web/.gitignore"), "!.env\n");
    write(sibling.join("web/src/.env"), "TOKEN=fixture\n");
    write(sibling.join("web/src/main.rs"), "fn main() {}\n");
    let cwd = nested.org.join("app-portal");
    assert_decision(
        &cwd,
        &nested.home,
        "rg -n fixture ../service-api/web/src",
        false,
    );
}
