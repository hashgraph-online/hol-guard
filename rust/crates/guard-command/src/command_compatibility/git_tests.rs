use super::*;

fn observations(command: &str) -> CompatibilityObservations {
    let model = crate::parse_command(
        &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
    )
    .unwrap();
    let mut result = CompatibilityObservations::default();
    observe_with_context(
        &model.segments[0],
        0,
        &mut result,
        crate::pretool::PathContext::default(),
    );
    result
}

fn observations_in(command: &str, cwd: &std::path::Path) -> CompatibilityObservations {
    let model = crate::parse_command(
        &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
    )
    .unwrap();
    let mut result = CompatibilityObservations::default();
    let cwd = cwd.to_string_lossy().into_owned();
    observe_with_context(
        &model.segments[0],
        0,
        &mut result,
        crate::pretool::PathContext {
            cwd: Some(cwd.as_str()),
            ..crate::pretool::PathContext::default()
        },
    );
    result
}

/// `git diff --cached web/package.json` is the same staged read as
/// `git diff --cached -- web/package.json`, which the diff proof already
/// admits. Narrowing it to a file that is already there must not raise the
/// index owner, while an operand that names a branch or writes a file still
/// does.
#[test]
fn present_pathspec_operands_do_not_raise_the_index_owner() {
    let worktree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(worktree.path().join("web")).unwrap();
    std::fs::write(worktree.path().join("web/package.json"), "{}").unwrap();
    std::fs::write(worktree.path().join("test_calc.py"), "").unwrap();
    std::fs::create_dir_all(worktree.path().join("docs")).unwrap();

    let owns_index = |command: &str| {
        observations_in(command, worktree.path())
            .rule_matches
            .iter()
            .any(|item| item.rule_id == "command.git.index-inspection")
    };
    for command in [
        "git diff --cached web/package.json",
        "git diff --staged test_calc.py web/package.json",
        "git diff --cached docs",
        "git diff --cached .",
        "git diff --cached --stat web/package.json",
        "git diff --cached ':!web/package.json'",
    ] {
        assert!(!owns_index(command), "{command}");
    }
    for command in [
        // A branch is not a file in the worktree, so git reads it as a
        // revision and the staged read proof does not cover it.
        "git diff --cached origin/main",
        "git diff --cached ../service-api",
        "git diff --cached missing/report.json",
        "git diff --cached --output=/tmp/staged.diff web/package.json",
        "git diff --cached web/package.json --ext-diff",
    ] {
        assert!(owns_index(command), "{command}");
    }
}

#[test]
fn a_routed_staged_read_proves_its_operands_where_git_enters() {
    let worktree = tempfile::tempdir().unwrap();
    // A `-C` route is only admitted into a checkout, so the working directory
    // has to look like one.
    std::fs::create_dir_all(worktree.path().join(".git")).unwrap();
    std::fs::create_dir_all(worktree.path().join("web")).unwrap();
    std::fs::write(worktree.path().join("web/report.json"), "{}").unwrap();
    std::fs::create_dir_all(worktree.path().join("release")).unwrap();

    let owns_index = |command: &str| {
        observations_in(command, worktree.path())
            .rule_matches
            .iter()
            .any(|item| item.rule_id == "command.git.index-inspection")
    };
    // `report.json` is in the directory git enters, so the route reads the
    // index it proved.
    assert!(!owns_index("git -C web diff --cached report.json"));
    // `release` is only beside the shell's own working directory. In `web` git
    // reads it as a revision and diffs the index against it.
    assert!(owns_index("git -C web diff --cached release"));
}

#[test]
fn fixed_read_only_inspections_do_not_invent_unrelated_git_owners() {
    for command in [
        "git rev-parse --show-toplevel",
        "git rev-parse --git-dir",
        "git rev-parse --abbrev-ref HEAD",
        "git merge-base HEAD origin/main",
        "git show-ref --verify refs/heads/main",
        "git for-each-ref '--format=%(refname)' refs/heads",
        "git rev-list --count HEAD",
        "git ls-tree -r HEAD",
        "git ls-tree HEAD --name-only src/",
        "git cat-file -p HEAD:README.md",
        "git cat-file -t HEAD",
        "git cat-file blob HEAD:README.md",
        "git symbolic-ref --short HEAD",
        "git config --get remote.origin.url",
        "git config --global --get user.email",
        "git config --list --show-origin",
        "git apply --check workspace/patches/change.patch",
        "git apply --check -p1 workspace/patches/change.patch",
        "git apply --check --stat --summary change.patch",
        "git apply --check -- patches/one.diff patches/two.diff",
    ] {
        assert!(observations(command).rule_matches.is_empty(), "{command}");
    }
}

#[test]
fn bounded_cached_diffs_leave_the_index_owner_to_the_read_proof() {
    let owns_index = |command: &str| {
        observations(command)
            .rule_matches
            .iter()
            .any(|item| item.rule_id == "command.git.index-inspection")
    };
    for command in [
        "git diff --cached",
        "git diff --staged",
        "git diff --cached --check",
        "git diff --cached --numstat",
        "git diff --cached --quiet",
        "git diff --cached --stat",
        "git diff --staged --name-only",
        "git diff --cached --name-status HEAD",
        "git diff --cached -U3 -- src/main.rs",
        "git diff --no-ext-diff --cached --quiet",
    ] {
        assert!(!owns_index(command), "{command}");
    }
    for command in [
        "git diff --staged --output=patch",
        "git diff --cached -o patch",
        "git diff --cached --ext-diff",
        "git diff --cached --textconv",
        "git diff --cached origin/main",
        "git diff --cached src/main.rs",
        "git -c diff.external=payload diff --cached",
    ] {
        assert!(owns_index(command), "{command}");
    }
}

#[test]
fn plain_init_in_the_current_directory_claims_no_owner() {
    for command in [
        "git init",
        "git init .",
        "git init -q",
        "git init -b main",
        "git init --initial-branch=main --quiet",
    ] {
        assert!(observations(command).rule_matches.is_empty(), "{command}");
    }
    for command in [
        "git init --template=/tmp/hooks",
        "git init --separate-git-dir=/tmp/x",
        "git init ../elsewhere",
        "git init --bare",
        "git init -b ../main",
        "git -c init.templateDir=/tmp/hooks init",
        "git -C sub init",
    ] {
        let result = observations(command);
        assert!(!result.rule_matches.is_empty(), "{command}");
        assert!(
            result.rule_matches.iter().all(|item| item.uncertainty),
            "{command}"
        );
    }
}

#[test]
fn inspection_exemption_does_not_cover_execution_routing_or_mutation() {
    for command in [
        "git -C workspace status",
        "git -c alias.apply=payload apply --check change.patch",
        "git -c core.pager=payload rev-parse HEAD",
        "git config user.name payload",
        "git config --unset user.name",
        "git config --file /home/user/.aws/credentials --list",
        "git config --get --file other.cfg key",
        "git symbolic-ref HEAD refs/heads/other",
        "git cat-file --textconv HEAD:file",
        "git cat-file --filters HEAD:file",
        "git cat-file --path=file blob HEAD",
        "git cat-file --batch-check",
        "git -c core.pager=payload cat-file -p HEAD",
        "git apply change.patch",
        "git apply --check --unsafe-paths change.patch",
        "git apply --check ../change.patch",
        "git apply --check -",
        "git apply --check --whitespace=fix change.patch",
        "git apply --check --index change.patch",
    ] {
        let result = observations(command);
        assert!(!result.rule_matches.is_empty(), "{command}");
        assert!(
            result.rule_matches.iter().all(|item| item.uncertainty),
            "{command}"
        );
    }
}

#[test]
fn a_submodule_status_listing_invents_no_unrelated_git_owners() {
    for command in [
        "git submodule",
        "git submodule status",
        "git submodule status -q",
        "git submodule status --quiet",
        "git submodule status vendor/lib",
    ] {
        assert!(observations(command).rule_matches.is_empty(), "{command}");
    }
    for command in [
        "git submodule status --cached",
        "git submodule status --cached -- vendor/lib",
        "git submodule status --recursive",
        "git submodule update",
        "git submodule update --init --recursive",
        "git submodule foreach git status",
        "git submodule add https://example.invalid/lib vendor/lib",
        "git submodule deinit vendor/lib",
    ] {
        let result = observations(command);
        assert!(!result.rule_matches.is_empty(), "{command}");
        assert!(
            result.rule_matches.iter().all(|item| item.uncertainty),
            "{command}"
        );
    }
}

fn after_global_options(command: &str) -> Option<Vec<String>> {
    let arguments: Vec<String> = command
        .split_whitespace()
        .skip(1)
        .map(str::to_owned)
        .collect();
    routed_arguments(&arguments, crate::pretool::PathContext::default()).map(<[String]>::to_vec)
}

/// `--no-replace-objects` turns off the replacement refs and
/// `--literal-pathspecs` turns off pathspec magic, so neither chooses a
/// program or moves the repository Git reads: the words after them name the
/// same operation the proof reads without them. An option that starts the
/// pager or widens what a pathspec reaches is left where it stands, so the
/// operation the proof looks for is not there.
#[test]
fn inert_global_options_leave_the_operation_the_proof_reads() {
    for command in [
        "git --no-replace-objects status",
        "git --literal-pathspecs status",
        "git --no-replace-objects --literal-pathspecs --no-pager status",
    ] {
        assert_eq!(
            after_global_options(command).as_deref(),
            Some(&["status".to_owned()][..]),
            "{command}"
        );
    }
    for command in [
        "git --paginate status",
        "git --bare status",
        "git --glob-pathspecs status",
        "git --icase-pathspecs status",
    ] {
        let rest = after_global_options(command).expect("the scanner stops at the option");
        assert!(
            rest.first().is_some_and(|word| word.starts_with('-')),
            "{command}"
        );
    }
}

/// A bisect session moves `HEAD` across the history it is searching, so it
/// has its own owner. Before it had one it fell to the blanket attribution
/// every unnamed subcommand reaches, which reports each git rule as
/// uncertain and leaves nothing an approval can settle.
#[test]
fn a_bisect_session_carries_its_own_rule() {
    for command in [
        "git bisect start",
        "git bisect start HEAD HEAD~10",
        "git bisect good",
        "git bisect bad HEAD",
        "git bisect skip",
        "git bisect reset",
        "git bisect terms",
        "git bisect replay /tmp/session.log",
        "git bisect run ./flaky.sh",
    ] {
        let result = observations(command);
        assert_eq!(
            result
                .rule_matches
                .iter()
                .map(|item| item.rule_id)
                .collect::<Vec<_>>(),
            vec!["command.git.bisect"],
            "{command}"
        );
        assert!(
            result.rule_matches.iter().all(|item| !item.uncertainty),
            "{command}"
        );
    }
}

/// `git bisect log` prints the session and writes nothing, and the read it
/// is recognised by is read before any rule is attributed, so naming bisect
/// does not take that silence away.
#[test]
fn printing_a_bisect_session_stays_silent() {
    assert!(observations("git bisect log").rule_matches.is_empty());
}

/// A commit's notes, a replacement ref and a maintenance run each move
/// something the repository keeps, so each has its own owner. Before they had
/// one they fell to the blanket attribution every unnamed subcommand reaches,
/// which reports each git rule as uncertain and leaves nothing an approval
/// can settle.
#[test]
fn the_records_beside_the_history_carry_their_own_rules() {
    for (command, rule) in [
        ("git notes add -m fix HEAD", "command.git.notes"),
        ("git notes edit HEAD", "command.git.notes"),
        ("git notes remove HEAD", "command.git.notes"),
        ("git notes prune", "command.git.notes"),
        ("git replace HEAD~1 HEAD", "command.git.replace"),
        ("git replace --edit HEAD", "command.git.replace"),
        ("git replace -d HEAD", "command.git.replace"),
        ("git maintenance run", "command.git.maintenance"),
        ("git maintenance start", "command.git.maintenance"),
        ("git maintenance register", "command.git.maintenance"),
    ] {
        let result = observations(command);
        assert_eq!(
            result
                .rule_matches
                .iter()
                .map(|item| item.rule_id)
                .collect::<Vec<_>>(),
            vec![rule],
            "{command}"
        );
        assert!(
            result.rule_matches.iter().all(|item| !item.uncertainty),
            "{command}"
        );
    }
}

/// `git replace` with no object prints the replacements the repository has,
/// and that read is recognised before any rule is attributed, so naming
/// replace does not take its silence away.
#[test]
fn printing_the_replacement_refs_stays_silent() {
    for command in [
        "git replace",
        "git replace -l",
        "git replace --list refs/replace/*",
        "git replace --format=long -l",
    ] {
        assert!(observations(command).rule_matches.is_empty(), "{command}");
    }
}

fn settles(command: &str) -> bool {
    let model = crate::parse_command(
        &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
    )
    .unwrap();
    subcommand_settles_uncertainty(&model.segments[0])
}

/// A maintenance run installs scheduler jobs, so an explicit Allow cannot
/// settle it even though it now has a definite owner. Naming it turns an
/// uncertainty floor into a review a contained workspace can carry.
#[test]
fn a_maintenance_run_stays_outside_the_allow_scope() {
    for command in ["git maintenance run", "git maintenance start"] {
        assert!(!settles(command), "{command}");
    }
    for command in ["git notes add -m fix HEAD", "git replace -d HEAD"] {
        assert!(settles(command), "{command}");
    }
}

/// Naming a subcommand narrows only that subcommand. One with no owner still
/// reports every git rule as uncertain, which is what keeps an unmodelled
/// spelling from passing as a modelled one.
#[test]
fn a_subcommand_without_an_owner_still_reaches_every_rule() {
    for command in ["git gc --aggressive", "git repack -ad"] {
        let result = observations(command);
        assert!(result.rule_matches.len() > 1, "{command}");
        assert!(
            result.rule_matches.iter().all(|item| item.uncertainty),
            "{command}"
        );
        assert!(
            result
                .rule_matches
                .iter()
                .any(|item| item.rule_id == "command.git.bisect"),
            "{command}"
        );
    }
}
