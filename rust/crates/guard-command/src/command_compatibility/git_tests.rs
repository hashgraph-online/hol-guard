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
