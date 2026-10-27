//! The configuration listings `safe_worktree_config` judges, spelled as
//! `git config --show-scope --null --get-regexp` writes them.

use super::*;

fn listing(entries: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut output = Vec::new();
    for (scope, key, value) in entries {
        output.extend_from_slice(format!("{scope}\0{key}\n{value}\0").as_bytes());
    }
    output
}

fn judged(entries: &[(&str, &str, &str)]) -> Option<Option<ConfigFacts>> {
    safe_worktree_config(&listing(entries), Path::new("/nonexistent-home"))
}

#[test]
fn worktree_guess_remote_is_read_as_a_fact_not_a_review() {
    let Some(Some(facts)) = judged(&[("global", "worktree.guessRemote", "true")]) else {
        panic!("the setting is ordinary developer config");
    };
    assert!(facts.guess_remote);
    let Some(Some(facts)) = judged(&[
        ("global", "worktree.guessRemote", "true"),
        ("local", "worktree.guessRemote", "false"),
    ]) else {
        panic!("the setting is ordinary developer config");
    };
    assert!(!facts.guess_remote, "the last value Git reads wins");
    for value in ["2", "-1", ""] {
        let Some(Some(facts)) = judged(&[("global", "worktree.guessRemote", value)]) else {
            panic!("the setting is ordinary developer config");
        };
        assert!(facts.guess_remote, "Git reads {value:?} as true");
    }
    let Some(Some(facts)) = judged(&[("global", "user.name", "Example")]) else {
        panic!("the setting is ordinary developer config");
    };
    assert!(!facts.guess_remote);
}

#[test]
fn bundled_macos_config_is_judged_as_system_config() {
    let facts = judged(&[
        ("unknown", "credential.helper", "osxkeychain"),
        ("unknown", "init.defaultbranch", "main"),
        ("global", "user.name", "Example"),
        ("local", "core.bare", "false"),
    ]);
    assert!(matches!(facts, Some(Some(_))));
}

#[test]
fn bundled_scope_keeps_execution_settings_reviewed() {
    for (key, value) in [
        ("core.fsmonitor", "/opt/example/run"),
        ("core.sshcommand", "/opt/example/run"),
        ("hook.post-checkout.command", "/opt/example/run"),
        ("pager.worktree", "/opt/example/run"),
        ("include.path", "/opt/example/run"),
        ("includeif.onbranch:main.path", "/opt/example/run"),
        ("extensions.partialclone", "origin"),
    ] {
        let facts = judged(&[("unknown", key, value)]);
        assert!(matches!(facts, Some(None)), "{key}");
    }
}

#[test]
fn global_display_and_transport_settings_are_ordinary_developer_config() {
    for (key, value) in [
        ("core.pager", "delta"),
        ("pager.log", "less -FRX"),
        ("core.fsmonitor", "true"),
        ("core.sshcommand", "ssh -i ~/.ssh/id_work"),
        ("include.path", "~/.gitconfig.d/work"),
        ("includeif.gitdir:~/work/.path", "~/.gitconfig.d/work"),
        ("submodule.recurse", "true"),
        ("extensions.worktreeconfig", "true"),
    ] {
        assert!(
            matches!(judged(&[("global", key, value)]), Some(Some(_))),
            "{key}"
        );
    }
    assert!(matches!(
        judged(&[("local", "extensions.objectformat", "sha256")]),
        Some(Some(_))
    ));
}

#[test]
fn a_display_pager_is_ordinary_in_every_scope() {
    // `worktree add` runs `worktree`, `reset` and `update-ref`. None of
    // them pages, so whichever file spells the pager, it names how another
    // command prints and nothing this one starts.
    for scope in ["global", "system", "unknown", "local", "worktree"] {
        for (key, value) in [
            ("core.pager", "/tmp/run"),
            ("pager.log", "less -FRX"),
            ("pager.diff", "/tmp/run"),
            ("pager.show", "delta"),
        ] {
            assert!(
                matches!(judged(&[(scope, key, value)]), Some(Some(_))),
                "{scope} {key}"
            );
        }
        // A pager named for a command `worktree add` itself runs stays reviewed.
        for key in ["pager.worktree", "pager.reset", "pager.update-ref"] {
            assert!(
                matches!(judged(&[(scope, key, "/tmp/run")]), Some(None)),
                "{scope} {key}"
            );
        }
    }
}

#[test]
fn repository_scoped_execution_settings_stay_reviewed() {
    for (key, value) in [
        ("core.fsmonitor", "/tmp/run"),
        ("core.sshcommand", "/tmp/run"),
        ("include.path", "../.gitconfig"),
        ("includeif.gitdir:/.path", "../.gitconfig"),
    ] {
        assert!(
            matches!(judged(&[("local", key, value)]), Some(None)),
            "{key}"
        );
    }
    for key in [
        "includeif.onbranch:main.path",
        "pager.worktree",
        "core.fsmonitor",
    ] {
        let value = if key == "core.fsmonitor" {
            "/tmp/run"
        } else {
            "/tmp/x"
        };
        assert!(
            matches!(judged(&[("global", key, value)]), Some(None)),
            "{key}"
        );
    }
}

#[test]
fn repository_hooks_path_is_recorded_only_when_relative_and_local() {
    let Some(Some(facts)) = judged(&[("local", "core.hookspath", ".husky/_")]) else {
        panic!("relative repository hooks path rejected");
    };
    assert_eq!(facts.repository_hooks_path.as_deref(), Some(".husky/_"));
    for (scope, value) in [
        // Git resolves a relative value against the working tree, so the
        // directory it names is decided by the tree being checked out.
        ("local", "../hooks"),
        // A `worktree` or `command` value can come from this very
        // invocation, which no file on disk answers for.
        ("worktree", ".husky/_"),
        ("command", ".husky/_"),
        ("worktree", "/opt/hooks"),
        ("command", "/opt/hooks"),
    ] {
        assert!(
            matches!(judged(&[(scope, "core.hookspath", value)]), Some(None)),
            "{scope} {value}"
        );
    }
}

/// Git consults one hooks path: the last value it is given. An earlier
/// value, whichever scope wrote it, names a directory this checkout never
/// reads, so carrying it into the proof sends a command to review over a
/// directory Git has already been told to ignore.
#[test]
fn only_the_last_hooks_path_git_reads_is_judged() {
    let root = tempfile::tempdir().expect("temporary directory");
    let hooks = root.path().join("empty-hooks");
    fs::create_dir(&hooks).expect("hooks directory");
    let spelling = hooks.to_str().expect("path spelling").to_owned();
    let canonical = fs::canonicalize(&hooks).expect("canonical hooks directory");

    let Some(Some(facts)) = judged(&[
        ("local", "core.hookspath", ".husky/_"),
        ("local", "core.hookspath", spelling.as_str()),
    ]) else {
        panic!("the effective fixed directory was rejected");
    };
    assert_eq!(
        facts.repository_hooks_path, None,
        "the relative value is dead"
    );
    assert_eq!(facts.hook_dirs, vec![canonical.clone()]);

    let other = root.path().join("other-hooks");
    fs::create_dir(&other).expect("other hooks directory");
    let Some(Some(facts)) = judged(&[
        (
            "global",
            "core.hookspath",
            other.to_str().expect("path spelling"),
        ),
        ("local", "core.hookspath", spelling.as_str()),
    ]) else {
        panic!("the effective fixed directory was rejected");
    };
    assert_eq!(facts.hook_dirs, vec![canonical]);

    let Some(Some(facts)) = judged(&[
        ("global", "core.hookspath", spelling.as_str()),
        ("local", "core.hookspath", ".husky/_"),
    ]) else {
        panic!("the effective relative value was rejected");
    };
    assert_eq!(facts.repository_hooks_path.as_deref(), Some(".husky/_"));
    assert!(facts.hook_dirs.is_empty(), "the global directory is dead");

    // A value Git has already been told to ignore cannot be judged at all:
    // an earlier directory that no longer exists, or an earlier relative
    // value the working tree would decide, says nothing about the hooks this
    // checkout runs.
    let absent = root.path().join("absent-hooks");
    let absent_spelling = absent.to_str().expect("path spelling").to_owned();
    for (scope, value) in [
        ("global", absent_spelling.as_str()),
        ("local", absent_spelling.as_str()),
        ("local", "../hooks"),
    ] {
        let Some(Some(facts)) = judged(&[
            (scope, "core.hookspath", value),
            ("local", "core.hookspath", spelling.as_str()),
        ]) else {
            panic!("the dead {scope} value {value} was judged");
        };
        assert_eq!(
            facts.hook_dirs,
            vec![fs::canonicalize(&hooks).expect("canonical hooks directory")]
        );
    }
}

/// A hook manager, or a tool that wants Git's hooks out of the way,
/// writes a fixed directory into the repository's own configuration.
/// `git clone` never copies `.git/config`, so that value carries the
/// trust of the user's global one and is judged the same way: by reading
/// the directory. Refusing it outright left every `git worktree add`
/// chain in such a checkout unproven, and the git reads after it were
/// escalated to a review.
#[test]
fn repository_hooks_path_outside_the_checkout_is_read_as_a_directory() {
    let root = tempfile::tempdir().expect("temporary directory");
    let hooks = root.path().join("empty-hooks");
    fs::create_dir(&hooks).expect("hooks directory");
    let spelling = hooks.to_str().expect("path spelling");

    let Some(Some(facts)) = judged(&[("local", "core.hookspath", spelling)]) else {
        panic!("repository hooks directory outside the checkout rejected");
    };
    assert_eq!(
        facts.hook_dirs,
        vec![fs::canonicalize(&hooks).expect("canonical hooks directory")]
    );
    assert_eq!(facts.repository_hooks_path, None);

    let home_spelling = safe_worktree_config(
        &listing(&[("local", "core.hookspath", "~/empty-hooks")]),
        root.path(),
    );
    let Some(Some(facts)) = home_spelling else {
        panic!("repository hooks directory under the home rejected");
    };
    assert_eq!(
        facts.hook_dirs,
        vec![fs::canonicalize(&hooks).expect("canonical hooks directory")]
    );

    let absent = root.path().join("absent-hooks");
    assert!(
        matches!(
            judged(&[(
                "local",
                "core.hookspath",
                absent.to_str().expect("path spelling")
            )]),
            Some(None)
        ),
        "a directory that is not there is doubt"
    );
}

#[test]
fn bundled_scope_after_repository_settings_is_doubt() {
    let facts = judged(&[
        ("local", "core.bare", "false"),
        ("unknown", "credential.helper", "osxkeychain"),
    ]);
    assert!(facts.is_none());
}

#[test]
fn repository_credential_helper_and_filter_stay_reviewed() {
    assert!(matches!(
        judged(&[("local", "credential.helper", "osxkeychain")]),
        Some(None)
    ));
    assert!(matches!(
        judged(&[("local", "filter.lfs.smudge", "git-lfs smudge -- %f")]),
        Some(None)
    ));
    assert!(matches!(
        judged(&[("worktree", "core.hookspath", "/opt/hooks")]),
        Some(None)
    ));
}

#[test]
fn standard_lfs_filter_is_recognised() {
    let Some(Some(facts)) = judged(&[
        ("global", "filter.lfs.clean", "git-lfs clean -- %f"),
        ("global", "filter.lfs.smudge", "git-lfs smudge -- %f"),
        ("global", "filter.lfs.process", "git-lfs filter-process"),
        ("global", "filter.lfs.required", "true"),
    ]) else {
        panic!("standard LFS filter rejected");
    };
    assert!(facts.filters && facts.only_standard_lfs);
    let Some(Some(facts)) = judged(&[("global", "filter.lfs.smudge", "/opt/example/smudge %f")])
    else {
        panic!("global filter rejected");
    };
    assert!(facts.filters && !facts.only_standard_lfs);
}

#[test]
fn install_prefix_needs_a_libexec_git_core_exec_path() {
    let root = std::env::temp_dir().join(format!(
        "guard-worktree-prefix-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let exec_path = root.join("usr/libexec/git-core");
    fs::create_dir_all(&exec_path).expect("exec path");
    let canonical_root = fs::canonicalize(&root).expect("root");
    assert_eq!(
        install_prefix(exec_path.to_str().expect("utf-8")),
        Some(canonical_root.join("usr"))
    );
    assert_eq!(install_prefix(root.to_str().expect("utf-8")), None);
    assert_eq!(install_prefix("usr/libexec/git-core"), None);
    fs::remove_dir_all(root).ok();
}
