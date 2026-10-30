use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = env::temp_dir().join(format!("guard-git-plan-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    Fixture(root.canonicalize().unwrap())
}

fn directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn trusted(_: &Path, _: &Path, _: &Path, _: &[u32]) -> bool {
    true
}

fn untrusted(_: &Path, _: &Path, _: &Path, _: &[u32]) -> bool {
    false
}

/// A workspace with its own `.git` directory and a stand-in Git image
/// outside it; the trust proof is handed in, so the image is never run.
fn workspace(fixture: &Fixture) -> (PathBuf, PathBuf) {
    let workspace = fixture.0.join("project");
    directory(&workspace.join(".git"));
    directory(&workspace.join("subdir"));
    let git = fixture.0.join("tools/git");
    directory(git.parent().unwrap());
    fs::write(&git, "synthetic image").unwrap();
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
    directory(&fixture.0.join("home"));
    (workspace, git)
}

fn plan(fixture: &Fixture, command: &[&str], trust: GitBinaryTrust) -> Value {
    let (workspace, git) = workspace(fixture);
    let mut argv = vec![git.to_string_lossy().into_owned()];
    argv.extend(command.iter().map(|word| (*word).to_owned()));
    prepare_git(
        &json!({
            "command": argv,
            "workspace": workspace,
            "cwd": workspace,
            "home": fixture.0.join("home"),
            "platform": "darwin",
            "backend_executable": "/usr/bin/true",
            "search_path": "",
            "account_home": fixture.0.join("home"),
            "groups": [],
        }),
        trust,
    )
}

#[test]
fn mutating_reads_helpers_and_shell_effects_are_refused() {
    for command in [
        &["reset", "--hard"][..],
        &["diff", "--ext-diff"],
        &["diff", "--output=x"],
        &["show", ";", "sh"],
        &["stash", "push"],
        &["submodule", "status"],
        &["notes", "add", "-m", "x"],
        &["blame", "--textconv", "example.txt"],
        &["grep", "-nO", "needle"],
        &["grep", "--open", "needle"],
        &["cat-file", "--filters", "HEAD:example.txt"],
        &["-c", "core.pager=sh", "log"],
    ] {
        let fixture = fixture();
        let reply = plan(&fixture, command, trusted);
        assert!(reply.get("value").is_none(), "{command:?} was planned");
        assert!(reply["reason_code"].is_string(), "{command:?}");
    }
}

#[test]
fn everyday_reads_are_planned_behind_their_helper_screens() {
    for (command, arguments) in [
        (
            &["blame", "example.txt"][..],
            &["blame", "--no-textconv", "example.txt"][..],
        ),
        (
            &["grep", "-o", "needle"],
            &["grep", "--no-textconv", "-o", "needle"],
        ),
        (
            &["stash", "show", "-p"],
            &["stash", "show", "--no-ext-diff", "--no-textconv", "-p"],
        ),
        (&["grep", "needle"], &["grep", "--no-textconv", "needle"]),
        (&["reflog"], &["reflog", "--no-ext-diff", "--no-textconv"]),
        (
            &["stash", "list", "-p"],
            &["stash", "list", "--no-ext-diff", "--no-textconv", "-p"],
        ),
        (
            &["rev-list", "--count", "HEAD"],
            &["rev-list", "--count", "HEAD"],
        ),
    ] {
        let fixture = fixture();
        let reply = plan(&fixture, command, trusted);
        let value = &reply["value"];
        let git = fixture.0.join("tools/git");
        assert_eq!(value["profile_version"], "git-readonly-v1", "{reply}");
        assert_eq!(
            value["command"][..4],
            json!([git, "--no-pager", "-c", "core.fsmonitor=false"])
                .as_array()
                .unwrap()[..]
        );
        assert_eq!(
            value["command"].as_array().unwrap()[4..],
            json!(arguments).as_array().unwrap()[..]
        );
        assert_eq!(value["allowed_executables"], json!([git]));
        assert_eq!(value["read_only_roots"], json!([]));
    }
}

#[test]
fn a_routed_read_runs_in_the_directory_it_named_and_stays_inside() {
    let fixture = fixture();
    let reply = plan(&fixture, &["-C", "subdir", "grep", "needle"], trusted);
    let value = &reply["value"];
    assert_eq!(value["cwd"], json!(fixture.0.join("project/subdir")));
    assert_eq!(
        value["command"].as_array().unwrap()[4..],
        json!(["grep", "--no-textconv", "needle"])
            .as_array()
            .unwrap()[..]
    );
    assert!(!value["command"].as_array().unwrap().contains(&json!("-C")));
    let outside = fixture();
    let reply = plan(&outside, &["-C", "..", "grep", "needle"], trusted);
    assert!(reply.get("value").is_none(), "{reply}");
}

#[test]
fn an_untrusted_git_is_refused_before_any_metadata_is_read() {
    let fixture = fixture();
    let workspace = fixture.0.join("project");
    directory(&workspace);
    // A pointer that would fail on its own: trust has to answer first.
    fs::write(workspace.join(".git"), "not a git pointer\n").unwrap();
    let reply = plan(&fixture, &["diff", "--stat"], untrusted);
    assert_eq!(
        reply,
        json!({"reason_code": "git_restricted_invalid_command",
            "message": "Git does not resolve to a trusted executable."})
    );
}

#[test]
fn a_linked_worktree_reads_its_own_and_the_common_metadata_only() {
    let fixture = fixture();
    let common = fixture.0.join("main/.git");
    let gitdir = common.join("worktrees/linked");
    directory(&common.join("objects"));
    directory(&common.join("refs"));
    directory(&gitdir);
    fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    let linked = fixture.0.join("linked");
    directory(&linked);
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
    assert_eq!(
        repository_read_roots(&linked, &linked),
        Some(vec![gitdir.clone(), common.clone()])
    );
    // A shared repository is not the account's own metadata.
    fs::set_permissions(&common, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(repository_read_roots(&linked, &linked), None);
}

#[test]
fn a_metadata_pointer_cannot_grant_an_arbitrary_host_root() {
    for pointer in ["gitdir: /\n", "gitdir: /tmp\n", "not a git pointer\n"] {
        let fixture = fixture();
        fs::write(fixture.0.join(".git"), pointer).unwrap();
        assert_eq!(
            repository_read_roots(&fixture.0, &fixture.0),
            None,
            "{pointer}"
        );
    }
    let fixture = fixture();
    directory(&fixture.0.join("outside"));
    std::os::unix::fs::symlink(fixture.0.join("outside"), fixture.0.join(".git")).unwrap();
    assert_eq!(repository_read_roots(&fixture.0, &fixture.0), None);
}

#[test]
fn the_git_environment_drops_host_git_settings() {
    let reply = evaluate(
        "git_environment",
        &json!({"source": {"PATH": "/usr/bin", "GIT_DIR": "/elsewhere",
            "GIT_CONFIG_GLOBAL": "/x", "PAGER": "sh", "XDG_CONFIG_HOME": "/y"}}),
    )
    .unwrap();
    assert_eq!(
        reply,
        json!({"value": {"PATH": "/usr/bin", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}})
    );
}

#[test]
fn a_linux_plan_uses_the_filtered_readonly_profile() {
    let fixture = fixture();
    let (workspace, git) = workspace(&fixture);
    let reply = prepare_git(
        &json!({
            "command": [git, "diff", "--stat"],
            "workspace": workspace,
            "cwd": workspace,
            "platform": "linux",
            "backend_executable": "/usr/bin/true",
            "account_home": fixture.0.join("home"),
        }),
        trusted,
    );
    assert_eq!(reply["value"]["backend"], "linux-bubblewrap", "{reply}");
    assert_eq!(reply["value"]["profile_version"], "git-readonly-v1");
}
