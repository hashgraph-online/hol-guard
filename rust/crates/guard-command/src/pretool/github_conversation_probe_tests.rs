//! Review-conversation writes checked against the remotes Git lists in a
//! real repository, as gh resolves them.

use super::*;
use crate::pretool::PathContext;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const ORIGIN: &str = "[remote \"origin\"]\n\turl = https://github.com/example-org/app-portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n";
const PLAIN: &str = "[core]\n\tbare = false\n";
const UPSTREAM: &str =
    "[remote \"upstream\"]\n\turl = https://github.com/other-org/app-portal.git\n";

fn segment(arguments: &[&str]) -> CommandSegmentV1 {
    prefixed_segment(&[], arguments)
}

fn prefixed_segment(names: &[&str], arguments: &[&str]) -> CommandSegmentV1 {
    let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
    let text = format!("gh {}", arguments.join(" "));
    CommandSegmentV1 {
        tokens: std::iter::once("gh".to_owned())
            .chain(arguments.iter().cloned())
            .collect(),
        executable: Some("gh".to_owned()),
        arguments,
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        wrapper_chain: Vec::new(),
        path_overridden: false,
        execution_context: "direct".to_owned(),
        pipeline_index: 0,
        span: crate::CommandSpanV1 {
            source: text.clone(),
            start: 0,
            end: text.len(),
        },
        text,
    }
}

fn environment(home: &Path, names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["HOME", "PATH", "GIT_CONFIG_NOSYSTEM"]
            .iter()
            .chain(names)
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_string_lossy().into_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    }
}

/// Runs fixture Git with `home` as HOME and no system configuration.
fn git(directory: &Path, home: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args([
            "-c",
            "user.name=Guard Test",
            "-c",
            "user.email=guard@example.invalid",
        ])
        .args(["-c", "init.defaultBranch=main"])
        .args(arguments)
        .current_dir(directory)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn append(path: &Path, text: &str) {
    let mut config = std::fs::read_to_string(path).unwrap();
    config.push_str(text);
    std::fs::write(path, config).unwrap();
}

struct Checkout {
    root: PathBuf,
    project: PathBuf,
}

impl Checkout {
    fn scratch(label: &str) -> PathBuf {
        let nonce = crate::unique_nanos::unique_nanos();
        let root = std::env::temp_dir().join(format!(
            "hg-gh-conversation-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root.canonicalize().unwrap()
    }

    /// A repository whose own configuration also holds `config`.
    fn new(label: &str, config: &str) -> Self {
        let root = Self::scratch(label);
        git(&root, &root, &["init", "-q", "project"]);
        let project = root.join("project");
        append(&project.join(".git/config"), config);
        std::fs::create_dir_all(project.join(".tmp")).unwrap();
        Self { root, project }
    }

    /// A linked worktree whose shared repository's configuration also holds
    /// `config`.
    fn linked(label: &str, config: &str) -> Self {
        let root = Self::scratch(label);
        git(&root, &root, &["init", "-q", "main"]);
        let main = root.join("main");
        git(
            &main,
            &root,
            &["commit", "-q", "--allow-empty", "-m", "base"],
        );
        let project = root.join("project");
        let target = project.to_str().unwrap();
        git(
            &main,
            &root,
            &["worktree", "add", "-q", "-b", "feature", target],
        );
        append(&main.join(".git/config"), config);
        std::fs::create_dir_all(project.join(".tmp")).unwrap();
        Self { root, project }
    }

    /// Global configuration in the fixture HOME.
    fn global(&self, config: &str) {
        std::fs::write(self.root.join(".gitconfig"), config).unwrap();
    }

    fn allows(&self, arguments: &[&str]) -> bool {
        self.allows_segment(&segment(arguments))
    }

    fn allows_segment(&self, segment: &CommandSegmentV1) -> bool {
        self.allows_in(&[], segment)
    }

    /// With `names` also exported in the inherited environment.
    fn allows_in(&self, names: &[&str], segment: &CommandSegmentV1) -> bool {
        let home = self.root.to_str().unwrap();
        let cwd = self.project.to_str().unwrap();
        let environment = environment(&self.root, names);
        let context = PathContext {
            home_dir: Some(home),
            cwd: Some(cwd),
            ..PathContext::default()
        };
        current_repository_write(segment, (context, None, Some(&environment)))
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn literal_secret_free_comments_on_the_origin_repository_pass() {
    let checkout = Checkout::new("literal", ORIGIN);
    std::fs::write(
        checkout.project.join(".tmp/body.md"),
        "Fixed in the latest push; the parser now rejects empty input.\n",
    )
    .unwrap();
    for arguments in [
        &[
            "pr",
            "comment",
            "12",
            "--body",
            "Addressed in the latest commit.",
        ][..],
        &["issue", "comment", "7", "--body", "Thanks, merged the fix."],
        &[
            "pr",
            "comment",
            "12",
            "-R",
            "Example-Org/app-portal",
            "--body",
            "Done.",
        ],
        &["pr", "comment", "12", "--body-file", ".tmp/body.md"],
        &[
            "api",
            "repos/example-org/app-portal/pulls/12/comments/345/replies",
            "-f",
            "body=Addressed in the latest commit.",
        ],
    ] {
        assert!(checkout.allows(arguments), "{arguments:?}");
    }
}

#[test]
fn other_repositories_secrets_and_unsafe_files_stay_reviewed() {
    let checkout = Checkout::new("negative", ORIGIN);
    let tmp = checkout.project.join(".tmp");
    std::fs::write(
        tmp.join("pem-reply.md"),
        "-----BEGIN RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(tmp.join("large.md"), "a".repeat(70 * 1024)).unwrap();
    std::fs::write(tmp.join("empty.md"), "  \n").unwrap();
    std::fs::write(tmp.join("binary.md"), b"text\0more").unwrap();
    std::fs::write(checkout.project.join(".git/notes.md"), "Done.\n").unwrap();
    // A shared directory others can write is neither workspace nor private.
    let shared = checkout.root.join("shared");
    std::fs::create_dir(&shared).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    std::fs::write(shared.join("outside.md"), "Done.\n").unwrap();
    std::fs::write(tmp.join("linked.md"), "Done.\n").unwrap();
    std::fs::hard_link(tmp.join("linked.md"), shared.join("second.md")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(shared.join("outside.md"), tmp.join("link.md")).unwrap();
    let token = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let token_body = format!("token {token}");
    let reply_with_token = format!("body=see {token}");
    for arguments in [
        &["pr", "comment", "12", "--body", token_body.as_str()][..],
        &["pr", "comment", "12", "--body", "   "],
        &[
            "pr",
            "comment",
            "12",
            "-R",
            "other-org/app-portal",
            "--body",
            "Done.",
        ],
        &[
            "pr",
            "comment",
            "12",
            "-R",
            "example.com/example-org/app-portal",
            "--body",
            "Done.",
        ],
        &["pr", "comment", "12", "--body-file", ".tmp/pem-reply.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/large.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/empty.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/binary.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/missing.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/link.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/linked.md"],
        &["pr", "comment", "12", "--body-file", ".git/notes.md"],
        &["pr", "comment", "12", "--body-file", "../shared/outside.md"],
        &["pr", "comment", "12", "--body-file", "-"],
        &["pr", "comment", "12", "--body-file", "~/notes.md"],
        &[
            "api",
            "repos/other-org/app-portal/pulls/12/comments/345/replies",
            "-f",
            "body=Done.",
        ],
        &[
            "api",
            "repos/example-org/app-portal/issues/12/comments",
            "-f",
            reply_with_token.as_str(),
        ],
        &["pr", "review", "12", "--approve", "--body", "Looks good."],
        &["pr", "merge", "12", "--squash"],
    ] {
        assert!(!checkout.allows(arguments), "{arguments:?}");
    }
    let no_context = segment(&["pr", "comment", "12", "--body", "Done."]);
    assert!(!current_repository_write(
        &no_context,
        (PathContext::default(), None, None)
    ));
    // Without the inherited environment Git cannot be asked as gh would.
    let context = PathContext {
        home_dir: checkout.root.to_str(),
        cwd: checkout.project.to_str(),
        ..PathContext::default()
    };
    assert!(!current_repository_write(
        &no_context,
        (context, None, None)
    ));
}

#[test]
fn a_comment_without_a_selector_needs_origin_as_the_base_repository() {
    let reply = ["pr", "comment", "12", "--body", "Done."];
    let selected = [
        "pr",
        "comment",
        "12",
        "-R",
        "example-org/app-portal",
        "--body",
        "Done.",
    ];
    let set_default = format!("{ORIGIN}\tgh-resolved = base\n");
    for (label, config) in [
        ("single", ORIGIN.to_owned()),
        ("set-default", set_default),
        (
            "push-default",
            format!("[remote]\n\tpushDefault = origin\n{ORIGIN}"),
        ),
    ] {
        let checkout = Checkout::new(label, &config);
        assert!(checkout.allows(&reply), "{label}");
        assert!(checkout.allows(&selected), "{label}");
    }
    // gh ranks `upstream` and `github` above `origin`, and honors any remote
    // `gh repo set-default` marked, so a selector-less comment could land on
    // a repository never compared with origin. `-R origin` still passes.
    let upstream = format!("{ORIGIN}{UPSTREAM}");
    let other_default = format!(
        "{ORIGIN}[remote \"fork\"]\n\turl = https://github.com/other-org/app-portal.git\n\tgh-resolved = base\n"
    );
    let resolved_elsewhere = format!("{ORIGIN}\tgh-resolved = other-org/app-portal\n");
    for (label, config, selected_passes) in [
        ("upstream", upstream.as_str(), true),
        ("other-default", other_default.as_str(), true),
        ("resolved-elsewhere", resolved_elsewhere.as_str(), true),
        (
            "gitlab-origin",
            "[remote \"origin\"]\n\turl = https://gitlab.com/example-org/app-portal.git\n",
            false,
        ),
    ] {
        let checkout = Checkout::new(label, config);
        assert!(!checkout.allows(&reply), "{label}");
        assert_eq!(checkout.allows(&selected), selected_passes, "{label}");
    }
    // `GH_REPO` names the base repository before any remote when no `-R` is
    // given; `-R` itself still wins over it.
    let checkout = Checkout::new("gh-repo", ORIGIN);
    assert!(!checkout.allows_segment(&prefixed_segment(&["GH_REPO"], &reply)));
    assert!(checkout.allows_segment(&prefixed_segment(&["GH_REPO"], &selected)));
}

#[test]
fn linked_worktrees_and_remote_free_checkouts_resolve_like_gh() {
    let reply = ["pr", "comment", "12", "--body", "Done."];
    let selected = [
        "pr",
        "comment",
        "12",
        "-R",
        "example-org/app-portal",
        "--body",
        "Done.",
    ];
    // A linked worktree reads its shared repository's configuration.
    let linked = Checkout::linked("linked", ORIGIN);
    assert!(linked.allows(&reply));
    assert!(linked.allows(&selected));
    let linked = Checkout::linked("linked-upstream", &format!("{ORIGIN}{UPSTREAM}"));
    assert!(!linked.allows(&reply));
    assert!(linked.allows(&selected));
    // With no remote at all gh resolves no base repository and posts nothing;
    // a `-R` selector still has to name origin.
    for checkout in [
        Checkout::new("remote-free", PLAIN),
        Checkout::linked("linked-remote-free", PLAIN),
    ] {
        assert!(checkout.allows(&reply));
        assert!(!checkout.allows(&selected));
        assert!(!checkout.allows_segment(&prefixed_segment(&["GH_REPO"], &reply)));
    }
}

#[test]
fn global_remotes_rewrites_and_config_variables_count_like_gh() {
    let reply = ["pr", "comment", "12", "--body", "Done."];
    let selected = [
        "pr",
        "comment",
        "12",
        "-R",
        "example-org/app-portal",
        "--body",
        "Done.",
    ];
    // A remote defined only in global configuration is listed by
    // `git remote -v` and outranks origin, or becomes the only base.
    for (label, config) in [("global-remote-free", PLAIN), ("global-origin", ORIGIN)] {
        let checkout = Checkout::new(label, config);
        assert!(checkout.allows(&reply), "{label}");
        checkout.global(UPSTREAM);
        assert!(!checkout.allows(&reply), "{label}");
        assert_eq!(checkout.allows(&selected), config == ORIGIN, "{label}");
    }
    // A global rewrite moves origin, so `-R` must name where it now points.
    let checkout = Checkout::new("global-rewrite", ORIGIN);
    checkout.global(
        "[url \"https://github.com/other-org/\"]\n\tinsteadOf = https://github.com/example-org/\n",
    );
    assert!(!checkout.allows(&selected));
    // An inherited `GIT_CONFIG_*` variable or a stamped `GH_REPO` can move the
    // remotes or the base repository, so neither form passes.
    let checkout = Checkout::new("config-variables", ORIGIN);
    let reply = segment(&reply);
    let selected = segment(&selected);
    for name in ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_COUNT"] {
        assert!(!checkout.allows_in(&[name], &reply), "{name}");
        assert!(!checkout.allows_in(&[name], &selected), "{name}");
    }
    assert!(!checkout.allows_in(&["GH_REPO"], &reply));
    assert!(checkout.allows_in(&["GH_REPO"], &selected));
    // A host override sends even `-R owner/name` and `gh api` elsewhere.
    let api = segment(&[
        "api",
        "-X",
        "POST",
        "repos/example-org/app-portal/issues/12/comments",
        "-f",
        "body=Done.",
    ]);
    for name in [
        "GH_HOST",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_CONFIG_DIR",
    ] {
        for write in [&reply, &selected, &api] {
            assert!(!checkout.allows_in(&[name], write), "{name}");
            let prefixed = CommandSegmentV1 {
                environment_names: vec![name.to_owned()],
                ..write.clone()
            };
            assert!(!checkout.allows_segment(&prefixed), "{name}");
        }
    }
    assert!(checkout.allows_segment(&api));
}
