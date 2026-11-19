//! The git rules read against real folders: hook folders, the working tree
//! the agent sits in, and the shell's text.

use crate::git_rules_match::{breaks, Breaks};

#[test]
fn a_hooks_folder_counts_only_when_it_runs_no_hook() {
    let root = tempfile::tempdir().expect("temp dir");
    let repo = root.path().join("repo");
    let hooks = repo.join(".githooks");
    let empty = root.path().join("empty-hooks");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    std::fs::create_dir_all(&hooks).expect("hooks dir");
    std::fs::create_dir_all(repo.join(".empty")).expect("empty repo dir");
    std::fs::create_dir_all(&empty).expect("empty dir");
    let idle = repo.join(".idle");
    std::fs::create_dir_all(&idle).expect("idle dir");
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\n").expect("hook");
    std::fs::write(idle.join("pre-commit"), "#!/bin/sh\n").expect("idle hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let runnable = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(hooks.join("pre-commit"), runnable).expect("chmod");
        let idle_mode = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(idle.join("pre-commit"), idle_mode).expect("chmod");
    }
    let cwd = Some(repo.as_path());
    let quote = |path: &std::path::Path| format!("'{}'", path.display());
    let empty = quote(&empty);
    let hooks = quote(&hooks);
    let mut missed = vec![
        format!("git -c core.hooksPath={empty} commit -m wip"),
        "git -c core.hooksPath=.empty commit -m wip".to_owned(),
        "git -c core.hooksPath=missing commit -m wip".to_owned(),
        format!("git config core.hooksPath {empty}"),
    ];
    // Git on Unix skips a hook it may not execute.
    if cfg!(unix) {
        missed.push("git -c core.hooksPath=.idle commit -m wip".to_owned());
    }
    for command in missed {
        assert!(breaks(&command, cwd).hook_bypass, "missed: {command}");
    }
    // A relative folder is read in the checkout `git -C` selects.
    let outside = Some(root.path());
    assert!(
        breaks(
            "git -C repo -c core.hooksPath=.empty commit -m wip",
            outside
        )
        .hook_bypass
    );
    assert_eq!(
        breaks(
            "git -c core.hooksPath=.githooks -C repo commit -m wip",
            outside
        ),
        Breaks::default()
    );
    for command in [
        format!("git -c core.hooksPath={hooks} commit -m wip"),
        "git -c core.hooksPath=.githooks commit -m wip".to_owned(),
        format!("git config core.hooksPath {hooks}"),
        // A hooks folder saved inside the tree is how hook managers set
        // themselves up, before or after they write their hooks.
        "git config core.hooksPath .empty".to_owned(),
        "git config core.hooksPath missing".to_owned(),
    ] {
        assert_eq!(
            breaks(&command, cwd),
            Breaks::default(),
            "flagged: {command}"
        );
    }
}

#[test]
fn the_agent_folder_below_the_top_is_not_the_whole_tree() {
    let root = tempfile::tempdir().expect("temp dir");
    let repo = root.path().join("repo");
    let ui = repo.join("src").join("ui");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    std::fs::create_dir_all(&ui).expect("ui dir");
    assert_eq!(breaks("git add .", Some(&ui)), Breaks::default());
    assert_eq!(
        breaks("cd ../.. && cd src && git add .", Some(&ui)),
        Breaks::default()
    );
    assert!(breaks("git add -A", Some(&ui)).stage_all);
    assert!(breaks("cd ../.. && git add .", Some(&ui)).stage_all);
    assert!(breaks("git add .", Some(&repo)).stage_all);
    assert!(
        breaks(
            "git -C \"$(git rev-parse --show-toplevel)\" add .",
            Some(&ui)
        )
        .stage_all
    );
    let src = repo.join("src");
    assert_eq!(
        breaks("pushd ..; cd src; popd; git add .", Some(&src)),
        Breaks::default()
    );
    assert!(breaks("pushd ..; cd src; popd; cd ..; git add .", Some(&src)).stage_all);
}

#[test]
fn inline_code_too_long_to_read_is_judged_by_its_words() {
    let padding = "x = 1\n".repeat(4_000);
    let risky = format!(
        "python3 -c 'import subprocess\n{padding}subprocess.run([\"git\", \"add\", \"-A\"])'"
    );
    assert!(breaks(&risky, None).stage_all);
    let plain = format!("python3 -c 'print(1)\n{padding}'");
    assert_eq!(breaks(&plain, None), Breaks::default());
}

#[test]
fn words_split_like_the_shell() {
    use crate::git_rules_state::split_words;
    assert_eq!(
        split_words(r#"env -S 'git add -A' "a \"b\"" c\ d"#),
        Some(vec![
            "env".to_owned(),
            "-S".to_owned(),
            "git add -A".to_owned(),
            "a \"b\"".to_owned(),
            "c d".to_owned(),
        ])
    );
    assert_eq!(split_words("''"), Some(vec![String::new()]));
    assert_eq!(split_words("git commit -m 'open"), None);
    assert_eq!(
        split_words("env HUSKY=0 \\\n  git \"a\\\nb\""),
        Some(vec![
            "env".to_owned(),
            "HUSKY=0".to_owned(),
            "git".to_owned(),
            "ab".to_owned(),
        ])
    );
}
