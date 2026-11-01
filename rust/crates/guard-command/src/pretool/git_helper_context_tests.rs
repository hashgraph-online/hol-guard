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

/// The stdin filters ask for the probe too, on the spelling that only reads.
#[test]
fn the_stdin_filters_ask_for_the_configuration_probe() {
    for command in [
        "git var GIT_COMMITTER_IDENT",
        "git var -l",
        "git patch-id --stable",
        "git stripspace --strip-comments",
        "git check-mailmap --stdin",
        "git interpret-trailers --parse",
        "git interpret-trailers --trailer 'Fixes: #1' --where after",
    ] {
        assert!(probes(command), "{command}");
    }
}

/// The spellings that open a file the caller names never reach the probe.
#[test]
fn the_file_spellings_never_reach_the_probe() {
    for command in [
        "git check-mailmap --mailmap-file /home/user/.ssh/config contact",
        "git check-mailmap --mailmap-blob HEAD:other contact",
        "git interpret-trailers --in-place message.txt",
        "git interpret-trailers message.txt",
    ] {
        assert!(!probes(command), "{command}");
    }
}

/// The write spellings never reach the probe, because the inspection proof
/// refuses them first.
#[test]
fn the_ref_writings_never_reach_the_probe() {
    for command in [
        "git symbolic-ref HEAD refs/heads/other",
        "git symbolic-ref -d HEAD",
        "git symbolic-ref -m reason HEAD refs/heads/other",
    ] {
        assert!(!probes(command), "{command}");
    }
}
