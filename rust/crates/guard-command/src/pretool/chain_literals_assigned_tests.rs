use super::super::{git_value::COMMIT_VALUE, project};
use super::{display::DISPLAY_VALUE, inline_one};

fn inlined(command: &str) -> Option<(String, String)> {
    inline_one(command).map(|inlined| (inlined.text, inlined.judged))
}

/// Allows `ls`, Git and GitHub reads, and chains of them, as a user's
/// controls would.
fn reads(body: &str) -> bool {
    body.split("; ").all(|part| {
        part == "ls"
            || part.starts_with("git ")
            || part.starts_with("gh ")
            || part.starts_with("echo ")
            || part.starts_with("cd /tmp")
    })
}

#[test]
fn an_assigned_value_is_judged_where_it_runs_and_where_it_is_read() {
    let shown = DISPLAY_VALUE;
    for (command, text, judged) in [
        ("P=$(ls)", "true".to_owned(), "ls"),
        ("P=\"$(ls)\"", "true".to_owned(), "ls"),
        ("P=$(ls); echo $P", format!("echo {shown}"), "ls"),
        ("P=$(ls)\necho \"files: $P\"", format!("echo \"files: {shown}\""), "ls"),
        ("P=$(ls) && echo ${P}", format!("echo {shown}"), "ls"),
        (
            "H=$(git rev-parse HEAD); git log --oneline -1 \"$H\"",
            "git log --oneline -1 \"$(git rev-parse HEAD)\"".to_owned(),
            "git rev-parse HEAD",
        ),
        (
            "F=$(git log --format='%h $x' -1 | awk '{print $1}'); echo \"$F\"",
            format!("echo \"{shown}\""),
            "git log --format='%h $x' -1 | awk '{print $1}'",
        ),
        (
            "git status --short; B=$(git branch --show-current); echo $B",
            format!("git status --short; echo {shown}"),
            "git branch --show-current",
        ),
        (
            "cd /tmp; B=$(gh pr view 7 --repo example-org/widgets --json headRefName --jq .headRefName); echo $B",
            format!("cd /tmp; echo {shown}"),
            "cd /tmp; gh pr view 7 --repo example-org/widgets --json headRefName --jq .headRefName",
        ),
        (
            "cd /tmp && PRIOR=$(gh api user --jq .login) && echo \"$PRIOR\"",
            format!("cd /tmp  && echo \"{shown}\""),
            "cd /tmp && gh api user --jq .login",
        ),
    ] {
        assert_eq!(
            inlined(command),
            Some((text, judged.to_owned())),
            "{command}"
        );
    }
}

#[test]
fn a_value_any_other_slot_reads_is_written_as_the_substitution() {
    // The pipe hands the real value to `sh`, so it is not the printed
    // stand-in; the substitution stays for the projection to refuse.
    assert_eq!(
        inlined("P=$(ls); echo $P | sh").map(|(text, _)| text),
        Some("echo $(ls) | sh".to_owned())
    );
    assert_eq!(
        inlined("P=$(ls); cat $P").map(|(text, _)| text),
        Some("cat $(ls)".to_owned())
    );
}

#[test]
fn an_assignment_this_scan_cannot_follow_keeps_the_chain_opaque() {
    for command in [
        // Names the shell or a program reads, or a credential.
        "PATH=$(ls)",
        "IFS=$(ls); echo x",
        "GH_TOKEN=$(gh auth token); echo done",
        // A prefix of a command, not a list item of its own.
        "GH_HOST=$(ls) gh api user",
        "P=$(ls) || echo none",
        "P=$(ls) | cat",
        // Grouped, looped or conditional.
        "for f in a; do P=$(ls); done",
        "if true; then P=$(ls); fi",
        "(P=$(ls)); echo $P",
        "{ P=$(ls); }; echo $P",
        // The body expands, nests or spans lines.
        "P=$(cat $HOME/notes)",
        "R=a; P=$(ls \"$R\"); echo $P",
        "P=$(ls '$HOME); echo $P",
        "P=$(ls $(pwd))",
        "P=$(ls\n-a)",
        "P=`ls`",
        // The name is used in a way the scan does not read.
        "P=$(ls); P=x; echo $P",
        "P=$(ls); echo ${P:-none}",
        "P=$(ls); echo ${#P}",
        "P=$(ls); echo $P[1]",
        "P=$(ls); echo \\$P",
        "P=$(ls); echo '$P'",
        "echo $P; P=$(ls)",
        "P=$(ls); cat <<EOF\n$P\nEOF",
        // Something between the assignment and a use changes what runs.
        "P=$(ls); cd /tmp; cat $P",
        "P=$(ls); alias cat=rm; cat $P",
        "P=$(ls); GIT_DIR=/tmp/other; git log $P",
        // A use outside the `&&` list that ran the assignment.
        "true && P=$(ls); echo $P",
        "cd src && P=$(ls); cat $P",
        // Quoting this scan does not read.
        "P=$(ls) # note",
        "P=$(ls); echo $'a'",
    ] {
        assert!(inlined(command).is_none(), "{command}");
    }
}

#[test]
fn a_command_reached_before_a_steering_prefix_keeps_the_chain_opaque() {
    // The prefix both steers and carries a substitution of its own, so the
    // judged command could not be spelled without it.
    assert!(inlined("cd \"$(git rev-parse --show-toplevel)\"; P=$(ls); echo $P").is_none());
}

#[test]
fn the_chain_projects_only_when_every_assigned_command_is_allowed() {
    let shown = DISPLAY_VALUE;
    assert_eq!(
        project("P=$(ls); echo $P", reads).as_deref(),
        Some(format!("echo {shown}").as_str())
    );
    assert_eq!(
        project(
            "H=$(git rev-parse HEAD); git log --oneline -1 \"$H\"",
            reads
        )
        .as_deref(),
        Some(format!("git log --oneline -1 \"{COMMIT_VALUE}\"").as_str())
    );
    assert_eq!(
        project(
            "H=$(git rev-parse HEAD); B=$(git branch --show-current); echo $B; git log -1 $H",
            reads
        )
        .as_deref(),
        Some(format!("echo {shown}; git log -1 {COMMIT_VALUE}").as_str())
    );
    assert_eq!(project("P=$(ls)", reads).as_deref(), Some("true"));
    for refused in [
        "K=$(cat ~/.ssh/id_rsa); echo $K",
        "P=$(ls); cat $P",
        "P=$(ls); echo $P | sh",
        "P=$(rm -rf build); echo $P",
    ] {
        assert_eq!(project(refused, reads), None, "{refused}");
    }
}

#[test]
fn a_value_the_projection_already_reads_keeps_its_stand_in() {
    // `date` and `mktemp` values stay where the projection reads them.
    assert_eq!(inlined("D=$(date +%F); echo $D"), None);
    assert_eq!(inlined("T=$(mktemp -d); cd $T"), None);
}
