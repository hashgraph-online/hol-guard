use super::{helper_write_denials, linked_git_dirs, repository_config, write_denials_from};
use std::path::{Path, PathBuf};

/// Only the user's files, so the host's system configuration and environment
/// cannot change the result.
fn workspace_write_denials(workspace: &Path, home: Option<&Path>) -> Option<Vec<PathBuf>> {
    let user = home.unwrap();
    let globals = vec![user.join(".gitconfig"), user.join(".config/git/config")];
    write_denials_from(workspace, home, globals)
}

fn denials(config: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
    helper_write_denials(config, workspace)
}

#[test]
fn workspace_includes_and_outside_hooks_keep_the_command_at_review() {
    let ws = Path::new("/w/repo");
    // Relative includes resolve against `.git/`, so both name workspace files.
    assert_eq!(denials("[include]\n\tpath = ../.gitconfig\n", ws), None);
    assert_eq!(denials("[include]\n\tpath = extra\n", ws), None);
    assert_eq!(
        denials("[includeIf \"gitdir:/w/\"]\n\tpath = /w/repo/cfg\n", ws),
        None
    );
    assert_eq!(denials("[core]\n\thooksPath = /outside/hooks\n", ws), None);
    assert_eq!(denials("[core]\n\thooksPath = ~/hooks\n", ws), None);
    // An include outside the workspace is not writable from the sandbox.
    assert_eq!(
        denials("[include]\n\tpath = /etc/gitconfig.d/team\n", ws),
        Some(vec![])
    );
}

#[test]
fn shell_punctuation_splits_helper_words() {
    let ws = Path::new("/w/repo");
    let config = "[alias]\n\tx = \"!f() { ./tools/x.sh; }; f\"\n\ty = !./tools/a&&git status\n\tz = \"!f() { ./tools/z; }\"\n";
    let got = denials(config, ws).unwrap();
    assert!(got.contains(&ws.join("tools/x.sh")), "{got:?}");
    assert!(got.contains(&ws.join("tools/a")), "{got:?}");
    assert!(got.contains(&ws.join("tools/z")), "{got:?}");
    for expansion in [
        "!$PWD/tools/x.sh",
        "!`pwd`/x.sh",
        "!sh tools\\\\x",
        "!./tools/ru?",
        "!sh tools/*.sh",
        "!./tools/[r]un",
        "!./tools/{run,x}.sh",
    ] {
        let config = format!("[alias]\n\tx = {expansion}\n");
        assert_eq!(denials(&config, ws), None, "{expansion}");
    }
}

#[test]
fn helper_paths_in_any_word_are_write_denied() {
    // Nothing here exists yet: the sandbox could create any of it.
    let ws = Path::new("/w/repo");
    let config = "[core]\n\thooksPath = .githooks\n\tfsmonitor = ./tools/mon\n\
         \tsshCommand = ssh -F sshcfg\n\
         [alias]\n\tx = !sh tools/x\n\ty = !sh x.sh\n\tst = status -s\n\
         \td = difftool --extcmd=./tools/d\n\
         [branch \"main\"]\n\tmerge = refs/heads/main\n";
    let got = denials(config, ws).unwrap();
    assert_eq!(
        got,
        vec![
            ws.join(".githooks"),
            ws.join("tools/mon"),
            ws.join("sshcfg"),
            ws.join("tools/x"),
            ws.join("x.sh"),
            ws.join("tools/d"),
        ]
    );
}

#[test]
fn a_quoted_helper_path_with_spaces_stays_at_review() {
    let ws = Path::new("/w/repo");
    for config in [
        "[alias]\n\tcommit = !sh \\\"./tools/my hook.sh\\\"\n",
        "[alias]\n\tcommit = !sh './tools/my hook.sh'\n",
        "[core]\n\tsshCommand = \"\\\"./my ssh.sh\\\"\"\n",
        "[alias]\n\tcommit = !'./tools/my hook.sh'\n",
    ] {
        assert_eq!(denials(config, ws), None, "{config}");
    }
}

#[test]
fn remote_and_submodule_data_keys_are_not_helpers() {
    let ws = Path::new("/w/repo");
    let config = "[remote \"origin\"]\n\turl = ../origin.git\n\
         \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
         \tuploadpack = ./tools/up\n\
         [submodule \"libs/x\"]\n\tpath = libs/x\n\turl = ./libs/x.git\n\
         \tupdate = !sh tools/sync\n";
    assert_eq!(
        denials(config, ws).unwrap(),
        vec![ws.join("tools/up"), ws.join("tools/sync")]
    );
}

#[test]
fn a_key_on_the_header_line_keeps_the_command_at_review() {
    let ws = Path::new("/w/repo");
    assert_eq!(denials("[core] hooksPath = tools/hooks\n", ws), None);
    assert_eq!(denials("[alias]x = !./tools/evil\n", ws), None);
    assert_eq!(denials("[core\n\thooksPath = h\n", ws), None);
    assert_eq!(
        denials("[core] # comment\n\thooksPath = h\n", ws),
        Some(vec![ws.join("h")])
    );
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-wgc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::create_dir_all(root.join("repo/app")).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn worktree_config_keeps_the_command_at_review() {
    let root = scratch("worktree");
    let (home, repo) = (root.join("home"), root.join("repo"));
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    assert_eq!(workspace_write_denials(&repo, Some(&home)), Some(vec![]));
    std::fs::write(
        repo.join(".git/config.worktree"),
        "[core]\n\thooksPath = h\n",
    )
    .unwrap();
    assert_eq!(workspace_write_denials(&repo, Some(&home)), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn an_enclosing_repository_and_global_hooks_name_workspace_paths() {
    let root = scratch("enclosing");
    let (home, repo) = (root.join("home"), root.join("repo"));
    let app = repo.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(
        repo.join(".git/config"),
        "[core]\n\tfsmonitor = app/tools/mon\n[alias]\n\tx = !sh other/x\n",
    )
    .unwrap();
    // Only paths inside the workspace need a denial; `other/x` is outside
    // the sandbox's writable tree.
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("tools/mon")])
    );
    // A relative global hook directory resolves against the work tree.
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = app/.githooks\n",
    )
    .unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("tools/mon"), app.join(".githooks")])
    );
    std::fs::write(home.join(".gitconfig"), "[core]\n\thooksPath = ../../x\n").unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    std::fs::write(home.join("dotfile"), "[core]\n\thooksPath = ~/.hooks\n").unwrap();
    std::fs::remove_file(home.join(".gitconfig")).unwrap();
    std::os::unix::fs::symlink(home.join("dotfile"), home.join(".gitconfig")).unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("tools/mon")])
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn global_hooks_in_any_form_and_writable_global_files_are_covered() {
    let root = scratch("global-forms");
    let (home, repo) = (root.join("home"), root.join("repo"));
    let app = repo.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
    let global = home.join(".gitconfig");
    // Absolute and home-relative hook directories inside the workspace.
    let absolute = format!("[core]\n\thooksPath = {}/.hooks\n", app.display());
    std::fs::write(&global, absolute).unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join(".hooks")])
    );
    let in_home = home.join("proj");
    std::fs::create_dir_all(&in_home).unwrap();
    std::fs::write(&global, "[core]\n\thooksPath = ~/proj/.hooks\n").unwrap();
    assert_eq!(
        workspace_write_denials(&in_home, Some(&home)),
        Some(vec![in_home.join(".hooks")])
    );
    // Included files are followed, relative to the including file.
    std::fs::write(&global, "[includeIf \"gitdir:~/\"]\n\tpath = extra\n").unwrap();
    std::fs::write(home.join("extra"), "[core]\n\thooksPath = app/.h2\n").unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join(".h2")])
    );
    // A global file the sandbox could write keeps the command at review.
    std::fs::remove_file(&global).unwrap();
    std::fs::write(app.join("gitconfig"), "[user]\n\tname = x\n").unwrap();
    std::os::unix::fs::symlink(app.join("gitconfig"), &global).unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    std::fs::remove_file(&global).unwrap();
    std::fs::write(&global, "[include]\n\tpath = ../repo/app/inc\n").unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    for value in ["~other/.hooks", "app/.hooks ; note", "app", "/"] {
        let text = format!("[core]\n\thooksPath = {value}\n");
        std::fs::write(&global, text).unwrap();
        assert_eq!(workspace_write_denials(&app, Some(&home)), None, "{value}");
    }
    std::fs::remove_file(&global).unwrap();
    // Repository hook paths with an inline comment, or naming the
    // workspace itself, cannot be denied.
    for value in [".githooks ; local hooks", ".githooks # local", "app"] {
        let text = format!("[core]\n\thooksPath = {value}\n");
        std::fs::write(repo.join(".git/config"), text).unwrap();
        assert_eq!(workspace_write_denials(&app, Some(&home)), None, "{value}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn hook_directories_are_denied_where_their_links_lead() {
    let root = scratch("linked-hooks");
    let (home, repo) = (root.join("home"), root.join("repo"));
    let app = repo.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(app.join("real")).unwrap();
    std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
    // A global hook directory outside the workspace that links into it.
    std::os::unix::fs::symlink(app.join("real"), home.join(".githooks")).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = ~/.githooks\n",
    )
    .unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("real")])
    );
    std::fs::remove_file(home.join(".gitconfig")).unwrap();
    // A repository hook link inside the workspace is denied as written, so
    // it cannot be swapped, and where it leads.
    std::os::unix::fs::symlink(app.join("real"), app.join(".hooks")).unwrap();
    std::fs::write(
        repo.join(".git/config"),
        "[core]\n\thooksPath = app/.hooks\n",
    )
    .unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join(".hooks"), app.join("real")])
    );
    // A dangling link keeps the command at review: the sandbox could create
    // its target. So does a global file linked to a missing workspace file.
    std::fs::remove_dir(app.join("real")).unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
    std::fs::remove_file(home.join(".githooks")).unwrap();
    std::os::unix::fs::symlink(app.join("missing"), home.join(".gitconfig")).unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn global_helper_programs_in_the_workspace_are_denied() {
    let root = scratch("global-helpers");
    let home = root.join("home");
    let ws = home.join("proj");
    std::fs::create_dir_all(&ws).unwrap();
    let global = home.join(".gitconfig");
    let config = format!(
        "[core]\n\tfsmonitor = ~/proj/tools/mon\n\tpager = less -R\n\
         [alias]\n\tx = !{}/tools/x\n\ty = !sh run.sh\n\
         [credential]\n\thelper = osxkeychain\n[safe]\n\tdirectory = *\n\
         [difftool \"code\"]\n\tcmd = code --wait --diff \"$LOCAL\" $REMOTE\n",
        ws.display()
    );
    std::fs::write(&global, config).unwrap();
    let mut denied = workspace_write_denials(&ws, Some(&home)).unwrap();
    denied.sort();
    assert_eq!(
        denied,
        vec![ws.join("run.sh"), ws.join("tools/mon"), ws.join("tools/x")]
    );
    // Any other expansion still keeps the command at review.
    for value in ["!sh $(cat x)", "!$PWD/tools/x", "!~other/x", "!sh ./*.sh"] {
        std::fs::write(&global, format!("[alias]\n\tz = {value}\n")).unwrap();
        assert_eq!(workspace_write_denials(&ws, Some(&home)), None, "{value}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_verified_linked_worktree_reads_and_guards_its_shared_repository() {
    let root = scratch("linked");
    let home = root.join("home");
    let common = home.join("main/.git");
    let admin = common.join("worktrees/wt");
    let wt = home.join("wt");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(wt.join("src")).unwrap();
    std::fs::write(common.join("config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", wt.join(".git").display()),
    )
    .unwrap();
    std::fs::write(wt.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    assert_eq!(
        linked_git_dirs(&wt.join("src"), Some(&home)),
        Some((common.clone(), admin.clone()))
    );
    assert_eq!(
        repository_config(&wt),
        Ok(Some("[core]\n\tbare = false\n".to_string()))
    );
    assert_eq!(workspace_write_denials(&wt, Some(&home)), Some(vec![]));
    // A helper in the shared directory, which the run may write, keeps the
    // command at review.
    std::fs::write(
        home.join(".gitconfig"),
        format!("[alias]\n\tx = !{}/x\n", common.join("objects").display()),
    )
    .unwrap();
    assert_eq!(workspace_write_denials(&wt, Some(&home)), None);
    std::fs::remove_file(home.join(".gitconfig")).unwrap();
    // A worktree configuration is read by Git and not by this reader.
    std::fs::write(admin.join("config.worktree"), "").unwrap();
    assert_eq!(repository_config(&wt), Err(()));
    std::fs::remove_file(admin.join("config.worktree")).unwrap();
    // An admin entry that does not link back is no verified worktree.
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", home.join("other/.git").display()),
    )
    .unwrap();
    assert_eq!(linked_git_dirs(&wt, Some(&home)), None);
    assert_eq!(repository_config(&wt), Err(()));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn quoted_and_escaped_values_are_decoded_like_git() {
    let ws = Path::new("/w/repo");
    // An escaped-quote alias naming an absolute script outside the workspace.
    let escaped = "[alias]\n\tcommit = !bash \\\"/opt/hooks/commit.sh\\\"\n";
    assert_eq!(denials(escaped, ws), Some(vec![]));
    let quoted = "[alias]\n\tcommit = \"!bash /opt/hooks/commit.sh\"\n";
    assert_eq!(denials(quoted, ws), Some(vec![]));
    // A relative script is still write-denied, escaped or not.
    let relative = "[alias]\n\tcommit = !bash \\\"./tools/commit.sh\\\"\n";
    let plain = "[alias]\n\tcommit = !bash ./tools/commit.sh\n";
    assert_eq!(denials(relative, ws), denials(plain, ws));
    assert_eq!(
        denials(relative, ws),
        Some(vec![ws.join("tools/commit.sh")])
    );
    // A backtick, a glob, an escaped backslash, an unknown escape, a trailing
    // continuation and an unterminated quote all keep the command at review.
    for value in [
        "!bash \\\"`id`\\\"",
        "!bash \\\"/opt/*.sh\\\"",
        "!bash \\\\x",
        "!bash \\q",
        "!bash /opt/x.sh \\",
        "\"!bash /opt/x.sh",
    ] {
        let config = format!("[alias]\n\tcommit = {value}\n");
        assert_eq!(denials(&config, ws), None, "{value}");
    }
}

#[test]
fn large_repository_config_is_read_within_the_bound() {
    let root = scratch("large-config");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let mut config = String::new();
    for index in 0..9000 {
        config.push_str(&format!(
            "[branch \"b{index}\"]\n\tmerge = refs/heads/b{index}\n"
        ));
    }
    assert!(config.len() > 64 * 1024);
    std::fs::write(root.join(".git/config"), &config).unwrap();
    assert!(super::repository_config(&root).unwrap().is_some());
    config.push_str(&"#".repeat(5 * 1024 * 1024));
    std::fs::write(root.join(".git/config"), &config).unwrap();
    assert!(super::repository_config(&root).is_err());
    let _ = std::fs::remove_dir_all(&root);
}
