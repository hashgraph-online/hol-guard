//! Tests for the Git read-after-allow order checks.
use super::{globals_only_route_or_print, preserves_tree, REF_READS};

#[test]
fn working_tree_reads_are_not_ref_reads() {
    for operation in ["status", "diff", "grep", "ls-files", "blame", "check-attr"] {
        assert!(!REF_READS.contains(&operation), "{operation}");
    }
}

fn words(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_read_leaves_a_later_step_running_what_guard_read() {
    for command in [
        "status --short --branch",
        "log --oneline -5",
        "ls-remote --heads origin",
        "diff-tree -r --name-only HEAD",
        "diff-index --cached --name-only HEAD",
        "diff-files --name-only",
    ] {
        assert!(super::writes_nothing(&words(command)), "{command}");
    }
    // Each of these writes somewhere a later step could read.
    for command in [
        "diff --output=hook",
        "diff-tree --output=hook -r HEAD",
        "diff-tree -r --out hook HEAD",
        "diff-index --output=run.sh HEAD",
        "diff-files --outp=hook",
        "archive -o out.tar HEAD",
        "config a.b c",
    ] {
        assert!(!super::writes_nothing(&words(command)), "{command}");
    }
}

#[test]
fn a_step_that_writes_configuration_settles_no_order_check() {
    // The steps a refresh chain puts before a read: each records only
    // `branch.*` keys, or writes nothing at all.
    for command in [
        "fetch origin main",
        "merge --ff-only origin/main",
        "stash pop",
        "checkout -B refresh origin/main",
        "status --short --branch",
        "log --oneline -5",
        "rev-parse HEAD",
    ] {
        assert!(super::preserves_configuration(&words(command)), "{command}");
    }
    // A configuration write names the pager, textconv or filter program
    // the read after it would run, so the Allow on the read cannot answer
    // for it. An unresolvable step is refused for the same reason: an
    // alias runs whatever the configuration says it does.
    for command in [
        "config core.pager sh",
        "-C ../other config core.pager sh",
        "remote add origin https://example.invalid/app.git",
        "submodule update --init",
        "refresh-cache",
        "--unknown-global status",
    ] {
        assert!(
            !super::preserves_configuration(&words(command)),
            "{command}"
        );
    }
}

#[test]
fn an_output_file_that_decides_what_runs_next_is_not_a_read() {
    // Git's diff options reach every verb that shows a diff, and the
    // short form is the output file for the verbs that package a tree.
    // Each of these lands on Git's own tree, climbs out of the workspace
    // or is a value Guard cannot place.
    for command in [
        "log -1 --output=.git/config",
        "show --output .git/hooks/pre-commit HEAD",
        "whatchanged --out=.git/config",
        "rev-list --output=.git/config HEAD",
        "diff --output=.gitattributes",
        "archive -o ../out.tar HEAD",
        "archive -o /tmp/out.tar HEAD",
        "archive -o ~/out.tar HEAD",
        "archive -o $DEST/out.tar HEAD",
        "format-patch -o .git/hooks HEAD~1",
        // Git reads a clustered short flag exactly as the separate
        // spelling, so `-no DIR` writes where `-n -o DIR` would.
        "format-patch -no ../outside HEAD~1",
        "format-patch -sno .git/hooks HEAD~1",
        "format-patch -no../outside HEAD~1",
        "archive --output",
    ] {
        assert!(
            super::points_output_at_a_protected_file(&words(command)),
            "{command}"
        );
    }
    // Packaging a tree into a file the workspace names is the ordinary
    // shape of the option. The same letter means something that writes
    // nothing below, and a long option that merely starts with the same
    // letters names no file.
    for command in [
        "archive -o out.tar HEAD",
        "archive -oout.tar HEAD",
        "archive --output=snapshot.tar HEAD",
        "format-patch -o patches HEAD~1",
        "format-patch -no patches HEAD~1",
        "format-patch -nopatches HEAD~1",
        "diff --output=hook",
        "ls-files -o --exclude-standard",
        "push -o ci.skip origin main",
        "status --short --branch",
        "log --oneline -5",
        "log --one-line",
    ] {
        assert!(
            !super::points_output_at_a_protected_file(&words(command)),
            "{command}"
        );
    }
}

#[test]
fn a_destination_option_outside_the_workspace_is_not_a_read() {
    // These verbs write where the option points, so the same rule that
    // holds `git archive -o ../out.tar` holds them.
    for command in [
        "fast-export --export-marks=../outside/marks --all",
        "fast-export --export-marks ../outside/marks --all",
        "fast-export --export-marks=.git/hooks/pre-commit --all",
        "fast-export --export=/tmp/marks --all",
        "read-tree --index-output=../outside/index HEAD",
        "read-tree --index-output=.git/config HEAD",
        "commit-graph write --object-dir=../outside",
        "commit-graph write --object-dir ../outside",
        "multi-pack-index --object-dir=/tmp/objects write",
        "fast-export --export-marks",
    ] {
        assert!(
            super::points_output_at_a_protected_file(&words(command)),
            "{command}"
        );
    }
    // The ordinary spellings. `git commit-graph` and
    // `git multi-pack-index` write their own fixed names, so a directory
    // inside the repository replaces no hook or configuration file, and
    // the option name belongs to one verb only.
    for command in [
        "fast-export --export-marks=marks --all",
        "fast-export --all",
        "read-tree --index-output=tmp-index HEAD",
        "read-tree -m -u HEAD",
        "commit-graph write",
        "commit-graph write --object-dir=.git/objects",
        "commit-graph write --object-dir .git/objects",
        "multi-pack-index --object-dir=.git/objects write",
        "log --export-marks=../outside/marks",
        "fast-export --reencode=yes --all",
    ] {
        assert!(
            !super::points_output_at_a_protected_file(&words(command)),
            "{command}"
        );
    }
}

#[test]
fn a_step_routed_by_global_options_keeps_its_own_subcommand() {
    for command in [
        "push",
        "-C repo worktree remove wt",
        "-c a.b=c branch -D pr",
    ] {
        assert!(preserves_tree(&words(command)), "{command}");
    }
    // `--attr-source` takes a value, so `push` here is that value and the
    // step is a checkout.
    for command in [
        "checkout main",
        "--attr-source push checkout main",
        "--attr-source=push checkout main",
        "-C repo worktree add wt",
    ] {
        assert!(!preserves_tree(&words(command)), "{command}");
    }
}

#[test]
fn a_directory_option_leaves_a_refresh_able_to_settle_a_later_read() {
    for command in [
        "pull --ff-only origin main",
        "-C /repo pull --ff-only origin main",
        "-C /repo --no-pager merge --ff-only origin/main",
        "--no-optional-locks -C /repo pull --ff-only origin main",
    ] {
        assert!(globals_only_route_or_print(&words(command)), "{command}");
    }
}

#[test]
fn an_inline_setting_or_a_moved_repository_still_settles_nothing() {
    for command in [
        "-c core.pager=sh pull --ff-only origin main",
        "-ccore.pager=sh pull --ff-only origin main",
        "-C/repo pull --ff-only origin main",
        "-c core.pager sh pull --ff-only origin main",
        "--config-env=core.pager=P pull --ff-only origin main",
        "--exec-path=/tmp/x pull --ff-only origin main",
        "--git-dir /other/.git pull --ff-only origin main",
        "--work-tree /other pull --ff-only origin main",
        "--namespace ns pull --ff-only origin main",
        "--bare pull --ff-only origin main",
        "--paginate pull --ff-only origin main",
    ] {
        assert!(!globals_only_route_or_print(&words(command)), "{command}");
    }
}
