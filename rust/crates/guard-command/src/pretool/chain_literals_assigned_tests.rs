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
        ("P=$(ls)", "ls".to_owned(), "ls"),
        ("P=\"$(ls)\"", "ls".to_owned(), "ls"),
        ("P=$(ls); echo $P", format!("ls; echo {shown}"), "ls"),
        (
            "P=$(ls)\necho \"files: $P\"",
            format!("ls\necho \"files: {shown}\""),
            "ls",
        ),
        ("P=$(ls) && echo ${P}", format!("ls && echo {shown}"), "ls"),
        (
            "H=$(git rev-parse HEAD); git log --oneline -1 \"$H\"",
            "git rev-parse HEAD; git log --oneline -1 \"$(git rev-parse HEAD)\"".to_owned(),
            "git rev-parse HEAD",
        ),
        (
            "F=$(git log --format='%h $x' -1 | awk '{print $1}'); echo \"$F\"",
            format!("git log --format='%h $x' -1 | awk '{{print $1}}'; echo \"{shown}\""),
            "git log --format='%h $x' -1 | awk '{print $1}'",
        ),
        (
            "git status --short; B=$(git branch --show-current); echo $B",
            format!("git status --short; git branch --show-current; echo {shown}"),
            "git branch --show-current",
        ),
        (
            "cd /tmp; B=$(gh pr view 7 --repo example-org/widgets --json headRefName --jq .headRefName); echo $B",
            format!(
                "cd /tmp; gh pr view 7 --repo example-org/widgets --json headRefName --jq .headRefName; echo {shown}"
            ),
            "cd /tmp; gh pr view 7 --repo example-org/widgets --json headRefName --jq .headRefName",
        ),
        (
            "cd /tmp && PRIOR=$(gh api user --jq .login) && echo \"$PRIOR\"",
            format!("cd /tmp && gh api user --jq .login && echo \"{shown}\""),
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
fn a_literal_bound_earlier_is_written_into_the_judged_command() {
    let shown = DISPLAY_VALUE;
    for (command, text, judged) in [
        (
            "R=example-org/widgets; T=$(gh pr view 7 --repo \"$R\" --json title); echo \"$T\"",
            format!(
                "R=example-org/widgets; gh pr view 7 --repo \"$R\" --json title; echo \"{shown}\""
            ),
            "gh pr view 7 --repo example-org/widgets --json title",
        ),
        (
            "N=7 && T=$(gh pr view $N --json headRefOid --jq .headRefOid) && git log -1 $T",
            "N=7 && gh pr view $N --json headRefOid --jq .headRefOid && git log -1 $(gh pr view 7 --json headRefOid --jq .headRefOid)".to_owned(),
            "gh pr view 7 --json headRefOid --jq .headRefOid",
        ),
        (
            "N=7; gh pr view $N; T=$(gh pr diff ${N} --name-only); echo $T",
            format!("N=7; gh pr view $N; gh pr diff ${{N}} --name-only; echo {shown}"),
            "gh pr diff 7 --name-only",
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
fn a_quoted_literal_is_written_bare_only_where_the_shell_reads_it_bare() {
    assert_eq!(
        inlined("REF=HEAD; H=$(git rev-parse \"$REF\"); git log --oneline -1 \"$H\""),
        Some((
            "REF=HEAD; git rev-parse \"$REF\"; git log --oneline -1 \"$(git rev-parse HEAD)\""
                .to_owned(),
            "git rev-parse HEAD".to_owned()
        ))
    );
    for (bound, judged) in [
        ("R='a b'", "ls \"a b\""),
        ("R='*'", "ls \"*\""),
        ("R='~'", "ls \"~\""),
        ("R='x=~'", "ls \"x=~\""),
    ] {
        let command = format!("{bound}; P=$(ls \"$R\"); echo $P");
        let read = inline_one(&command).map(|inlined| inlined.judged);
        assert!(
            read.is_none() || read.as_deref() == Some(judged),
            "{command}"
        );
    }
}

#[test]
fn a_value_any_other_slot_reads_is_written_as_the_substitution() {
    // The pipe hands the real value to `sh`, so it is not the printed
    // stand-in; the substitution stays for the projection to refuse.
    assert_eq!(
        inlined("p=$(ls); echo $p | sh").map(|(text, _)| text),
        Some("ls; echo $(ls) | sh".to_owned())
    );
    assert_eq!(
        inlined("P=$(ls); cat $P").map(|(text, _)| text),
        Some("ls; cat $(ls)".to_owned())
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
        "P=$(ls \"$R\"); echo $P",
        "R=a || true; P=$(ls $R); echo $P",
        "R=a; P=$(ls $R $HOME); echo $P",
        "R=$(pwd); P=$(ls $R); echo $P",
        "P=$(ls '$HOME); echo $P",
        "P=$(ls $(pwd))",
        "P=$(cd /tmp; ls); cat $P",
        "P=$(cd /tmp && ls); echo $P",
        "P=$(ls || true); echo $P",
        "P=$(ls & ); echo $P",
        "P=$( (ls) ); echo $P",
        "P=$(ls # x
); echo $P",
        "P=$(ls\n-a)",
        "P=`ls`",
        // A pattern the shell may expand to a word the body does not show.
        "x=$(echo a | awk ?f prog.awk)",
        "P=$(ls *.md); echo $P",
        "P=$(ls [-]l); echo $P",
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
        // A steering word the shell runs once its quotes are read.
        "P=$(ls); \"cd\" /tmp; cat $P",
        "P=$(ls); 'cd' /tmp; cat $P",
        "P=$(ls); \\cd /tmp; cat $P",
        // A body that changes its own shell, which the parent does not share.
        "p=$(cd ./public) && cat config.txt",
        "p=$(export A=1); echo $p",
        "p=$(x=1); echo $p",
        // A capitalised name, possibly exported, reaches a program that
        // starts hooks or other programs.
        "REF=$(git rev-parse HEAD); git push origin main",
        "REF=$(git rev-parse HEAD); git log -1 \"$REF\"; npm test",
        "REF=$(git rev-parse HEAD); echo $(npm test)",
        "REF=$(git rev-parse HEAD); cat $(make)",
        "REF=$(git rev-parse HEAD); ls > $(npm run x)",
        "REF=$(git rev-parse HEAD); echo $(echo $(npm test))",
        "REF=$(git rev-parse HEAD); echo $(git branch -m old new)",
        "REF=$(git rev-parse HEAD); echo $(git branch --show-current --list)",
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
        Some(format!("ls; echo {shown}").as_str())
    );
    assert_eq!(
        project(
            "H=$(git rev-parse HEAD); git log --oneline -1 \"$H\"",
            reads
        )
        .as_deref(),
        Some(format!("git rev-parse HEAD; git log --oneline -1 \"{COMMIT_VALUE}\"").as_str())
    );
    assert_eq!(
        project(
            "H=$(git rev-parse HEAD); B=$(git branch --show-current); echo $B; git log -1 $H",
            reads
        )
        .as_deref(),
        Some(
            format!(
                "git rev-parse HEAD; git branch --show-current; echo {shown}; git log -1 {COMMIT_VALUE}"
            )
            .as_str()
        )
    );
    assert_eq!(project("P=$(ls)", reads).as_deref(), Some("ls"));
    // The assigned command is written as typed, for the literal pass that
    // follows to fill in, dropping the assignment it no longer needs.
    assert_eq!(
        project(
            "R=example-org/widgets; T=$(gh pr view 7 --repo \"$R\" --json title); echo \"$T\"",
            reads
        )
        .as_deref(),
        Some(
            format!(
                "R=example-org/widgets; gh pr view 7 --repo \"$R\" --json title; echo \"{shown}\""
            )
            .as_str()
        )
    );
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

#[test]
fn a_capitalised_name_before_commands_that_ignore_it_is_still_read() {
    assert!(inlined("REF=$(git rev-parse HEAD); git log -1 \"$REF\"").is_some());
    assert!(inlined("ref=$(git rev-parse HEAD); git log -1 \"$ref\"; npm test").is_some());
}

#[test]
fn a_quoted_tilde_keeps_its_quotes_after_any_separator() {
    for text in ["ls\t\"~\"", "ls;\"~\"", "ls <\"~\"", "ls \"~\""] {
        assert_eq!(super::scan::plain_quotes_dropped(text), text, "{text}");
    }
    assert_eq!(
        super::scan::plain_quotes_dropped("git log \"HEAD\""),
        "git log HEAD"
    );
}
