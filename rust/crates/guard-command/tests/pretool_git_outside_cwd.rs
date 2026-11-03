#![cfg(unix)]
use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;
use std::path::Path;

fn git(dir: &Path, home: &Path, args: &[&str]) {
    let mut c = std::process::Command::new("git");
    for n in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_PREFIX",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG",
    ] {
        c.env_remove(n);
    }
    let s = c
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(s.success(), "git {args:?}");
}

struct World {
    _cleanup: FixtureCleanup,
    home: std::path::PathBuf,
    parent: std::path::PathBuf,
    app: std::path::PathBuf,
    other: std::path::PathBuf,
}

fn world(tag: &str) -> World {
    let root = Path::new("/tmp").join(format!("guard-outside-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let parent = root.join("w");
    let app = parent.join("app");
    let other = parent.join("other-repo");
    for d in [&home, &app, &other, &home.join("projects/x")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let root = root.canonicalize().unwrap();
    let home = root.join("home");
    // Fake developer-style global configuration.
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = /nonexistent/hooks\n[alias]\n\tcommit = commit -S\n\
         [filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\
         \tprocess = git-lfs filter-process\n\trequired = true\n\
         [difftool \"difftastic\"]\n\tcmd = difft \"$LOCAL\" \"$REMOTE\"\n\
         [credential]\n\thelper = osxkeychain\n[gpg]\n\tprogram = /nonexistent/gpg\n",
    )
    .unwrap();
    let parent = root.join("w");
    let app = parent.join("app");
    let other = parent.join("other-repo");
    for r in [&app, &other] {
        git(r, &home, &["init", "--quiet"]);
        git(r, &home, &["config", "user.email", "f@example.test"]);
        git(r, &home, &["config", "user.name", "f"]);
        std::fs::write(r.join("a.txt"), "x\n").unwrap();
        git(r, &home, &["add", "-A"]);
        git(
            r,
            &home,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "one",
            ],
        );
    }
    World {
        _cleanup: FixtureCleanup(root),
        home,
        parent,
        app,
        other,
    }
}

fn reason(w: &World, cwd: &Path, command: &str) -> (String, String) {
    let controls = github_controls("enabled");
    let r = evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        Some(&controls),
        None,
        w.home.to_str(),
        cwd.to_str(),
    );
    (r.decision.clone(), r.reason_code)
}

const ALLOW: &str = "native_exact_safe_command";

fn allowed(w: &World, cwd: &Path, command: &str) -> bool {
    reason(w, cwd, command) == ("allow".to_owned(), ALLOW.to_owned())
}

#[test]
fn repository_outside_cwd_and_home_is_read_when_owned_and_helper_free() {
    let w = world("route");
    let app = w.app.display();
    let xcwd = w.home.join("projects/x");
    for cwd in [&w.parent, &w.other, &xcwd] {
        for command in [
            format!("git -C {app} log --oneline -3"),
            format!("git -C {app} status --short"),
            format!("git -C {app} diff --stat"),
        ] {
            assert!(allowed(&w, cwd, &command), "{} {command}", cwd.display());
        }
    }
}

#[test]
fn outside_repository_with_helper_config_stays_reviewed() {
    let w = world("unsafe");
    let app = w.app.display();
    git(&w.app, &w.home, &["config", "core.fsmonitor", "/tmp/evil"]);
    git(&w.app, &w.home, &["config", "core.pager", "/tmp/evil"]);
    for command in [
        format!("git -C {app} status --short"),
        format!("git -C {app} log --oneline -3"),
    ] {
        assert!(!allowed(&w, &w.other, &command), "{command}");
    }
}

#[test]
fn outside_repository_with_symlinked_or_hidden_root_stays_reviewed() {
    let w = world("shape");
    let link = w.parent.join("link-app");
    std::os::unix::fs::symlink(w.app.join(".git"), {
        std::fs::create_dir_all(&link).unwrap();
        link.join(".git")
    })
    .unwrap();
    let hidden = w.parent.join(".hidden-app");
    std::fs::create_dir_all(&hidden).unwrap();
    git(&hidden, &w.home, &["init", "--quiet"]);
    for target in [&link, &hidden] {
        let command = format!("git -C {} log --oneline -1", target.display());
        assert!(!allowed(&w, &w.other, &command), "{command}");
    }
}

/// A `-C` target that holds no repository can only print `fatal: not a git
/// repository`, and Git dies in its own setup before it reads a pager or
/// filter setting, so the read needs no repository proof. Where the target
/// lands is still proved: it is read inside the screens that admit a
/// repository route outside the working directory, and reviewed outside them.
#[test]
fn non_repository_outside_cwd_is_read_within_the_route_screens() {
    let w = world("plain");
    let plain = w.parent.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    let command = format!("git -C {} log --oneline -1", plain.display());
    assert!(allowed(&w, &w.other, &command), "{command}");

    let hidden = w.parent.join(".plain");
    std::fs::create_dir_all(&hidden).unwrap();
    let link = w.parent.join("linked-plain");
    std::os::unix::fs::symlink(&plain, &link).unwrap();
    for target in [
        hidden.display().to_string(),
        link.display().to_string(),
        "/usr/share".to_owned(),
        "..".to_owned(),
    ] {
        let command = format!("git -C {target} log --oneline -1");
        assert!(!allowed(&w, &w.other, &command), "{command}");
    }
}

#[test]
fn sequences_of_proven_git_reads_share_one_proof() {
    let w = world("sequence");
    for (cwd, command) in [
        (&w.app, "git rev-parse HEAD; echo ---; git log --oneline -1"),
        (&w.parent, "git log --oneline -1; git status --short"),
        (
            &w.app,
            "git log --format='%h %ad %s' --date=iso -1 HEAD; echo ---; git rev-parse HEAD; echo ---; git log --oneline HEAD..HEAD | wc -l",
        ),
    ] {
        assert!(allowed(&w, cwd, command), "{command}");
    }
}

#[test]
fn sequences_with_a_running_helper_stay_reviewed() {
    let w = world("sequence-unsafe");
    git(&w.app, &w.home, &["config", "core.pager", "/tmp/evil"]);
    git(&w.app, &w.home, &["config", "core.fsmonitor", "/tmp/evil"]);
    for command in [
        "git rev-parse HEAD; echo ---; git log --oneline -1",
        "git rev-parse HEAD; git status --short",
    ] {
        assert!(!allowed(&w, &w.app, command), "{command}");
    }
    // A repository whose attributes route files through a configured filter.
    let w = world("sequence-filter");
    std::fs::write(w.app.join(".gitattributes"), "*.txt filter=lfs\n").unwrap();
    assert!(!allowed(
        &w,
        &w.app,
        "git rev-parse HEAD; git status --short"
    ));
}

fn read_decision(w: &World, cwd: &Path, path: &str) -> (String, String) {
    let controls = github_controls("enabled");
    let r = evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"tool_name":"Read","tool_input":{"file_path":path}}),
        Some(&controls),
        None,
        w.home.to_str(),
        cwd.to_str(),
    );
    (r.decision.clone(), r.reason_code)
}

#[test]
fn bare_repository_route_is_read_when_owned_and_helper_free() {
    let w = world("bare");
    let bare = w.parent.join("remote/app.git");
    std::fs::create_dir_all(&bare).unwrap();
    git(&bare, &w.home, &["init", "--quiet", "--bare"]);
    let command = format!("git --git-dir={} log --oneline -12", bare.display());
    assert!(allowed(&w, &w.other, &command));
    git(&bare, &w.home, &["config", "core.pager", "/tmp/evil"]);
    assert!(!allowed(&w, &w.other, &command));
    // A non-repository directory and a work-tree `.git` are not bare routes.
    let plain = w.parent.join("plain.git");
    std::fs::create_dir_all(&plain).unwrap();
    for target in [plain, w.app.join(".git")] {
        let command = format!("git --git-dir={} log --oneline -1", target.display());
        assert!(!allowed(&w, &w.other, &command), "{command}");
    }
}

#[test]
fn git_config_read_is_allowed_unless_it_holds_credentials() {
    let w = world("config");
    let config = w.app.join(".git/config");
    let path = config.display().to_string();
    assert_eq!(read_decision(&w, &w.app, &path).0, "allow");
    for secret in [
        "[remote \"origin\"]\n\turl = https://user:hunter2@example.test/acme/app.git\n",
        "[http]\n\textraHeader = AUTHORIZATION: basic abc\n",
        "[credential]\n\thelper = store\n",
    ] {
        let original = std::fs::read_to_string(&config).unwrap();
        std::fs::write(&config, format!("{original}{secret}")).unwrap();
        assert_ne!(read_decision(&w, &w.app, &path).0, "allow", "{secret}");
        std::fs::write(&config, original).unwrap();
    }
}

#[test]
fn hardening_flags_do_not_make_reads_riskier() {
    let w = world("hardening");
    let app = w.app.display();
    let hooks = w.parent.join("no-hooks");
    for command in [
        format!(
            "git -C {app} -c core.fsmonitor=false -c core.hooksPath={} status",
            hooks.display()
        ),
        "git -c core.hooksPath=/dev/null status".to_owned(),
        format!("git -C {app} -c core.fsmonitor=false -c core.hooksPath= log --oneline -12"),
    ] {
        assert!(allowed(&w, &w.app, &command), "{command}");
    }
    // A hooks path that holds hooks is not admitted.
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("post-checkout"), "#!/bin/sh\n").unwrap();
    let command = format!("git -c core.hooksPath={} status", hooks.display());
    assert!(!allowed(&w, &w.app, &command));
}

#[test]
fn git_config_isolation_exports_do_not_make_reads_riskier() {
    let w = world("isolation");
    let app = w.app.display();
    for command in [
        format!("export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null; git -C {app} -c core.fsmonitor=false status"),
        format!("export GIT_CONFIG_GLOBAL=/dev/null && git -C {app} log --oneline -1"),
    ] {
        assert!(allowed(&w, &w.other, &command), "{command} {:?}", reason(&w, &w.other, &command));
    }
    // Other exports, or an unproven read after them, keep their own verdict.
    for command in [
        format!("export GIT_CONFIG_GLOBAL=/tmp/other; git -C {app} status"),
        format!("export GIT_PAGER=/tmp/evil; git -C {app} log --oneline -1"),
        format!("export GIT_CONFIG_GLOBAL=/dev/null; git -C {app} push origin main"),
    ] {
        assert!(!allowed(&w, &w.other, &command), "{command}");
    }
    git(&w.app, &w.home, &["config", "core.pager", "/tmp/evil"]);
    let command = format!("export GIT_CONFIG_GLOBAL=/dev/null; git -C {app} log --oneline -1");
    assert!(!allowed(&w, &w.other, &command));
}
