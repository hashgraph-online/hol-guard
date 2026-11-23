use super::{segment_runs_helpers, PathContext};
use crate::CommandModelRequestV1;

fn probes(command: &str) -> bool {
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    model
        .segments
        .iter()
        .any(|segment| segment_runs_helpers(segment, PathContext::default()))
}

/// A read admitted only under a cleared helper context has to ask for the
/// configuration probe too. A verb the inspection proof admits while this
/// screen stays silent is never allowed: the probe never runs, so the read
/// falls through to the generic review the admission was meant to remove.
#[test]
fn the_ref_readings_ask_for_the_configuration_probe() {
    for command in [
        "git name-rev --name-only HEAD",
        "git name-rev --all",
        "git show-branch",
        "git check-ref-format --branch main",
        "git symbolic-ref --short HEAD",
        "git symbolic-ref --no-recurse HEAD",
        "git status --short && git name-rev HEAD",
    ] {
        assert!(probes(command), "{command}");
    }
}

/// The two change listings run the same diff drivers `log` and `show` run,
/// and they walk commits as well, so a configured verification program is
/// reachable through them whatever the diff switches say. Both ask for the
/// probe on every spelling.
#[test]
fn the_change_listings_ask_for_the_configuration_probe() {
    for command in [
        "git whatchanged",
        "git whatchanged -3",
        "git whatchanged --oneline -5",
        "git whatchanged --no-ext-diff -3",
        // `log.showSignature`, a `%G` placeholder and a `pretty.*` alias
        // carrying one each start the configured verification program, which
        // neither diff switch touches, so turning both off proves nothing
        // about a commit walk.
        "git whatchanged --no-ext-diff --no-textconv -3",
        "git whatchanged --no-ext-diff --no-textconv --oneline -5",
        "git range-diff main...HEAD",
        "git range-diff --creation-factor=80 main...HEAD",
        "git range-diff --no-textconv main...HEAD",
        // `range-diff` assembles an inner `git log -p` and passes neither
        // switch down to it, so both switches on its own command line leave
        // a configured textconv driver reachable too.
        "git range-diff --no-ext-diff --no-textconv main...HEAD",
        // The walks they are spellings of answer the same way.
        "git log --no-ext-diff --no-textconv -3",
        "git show --no-ext-diff --no-textconv HEAD",
    ] {
        assert!(probes(command), "{command}");
    }
    // A comparison between two trees starts an external driver and a
    // textconv filter and nothing else, so turning both off leaves it no
    // helper to run.
    for command in [
        "git diff --no-ext-diff --no-textconv",
        "git diff-tree --no-ext-diff --no-textconv -r HEAD",
    ] {
        assert!(!probes(command), "{command}");
    }
}
