use super::super::TEMPORARY_VALUE;
use super::{mentions, private_directory, project};

#[test]
fn a_private_directory_entered_by_cd_takes_the_stand_in() {
    let t = TEMPORARY_VALUE;
    for (command, expected) in [
        (
            "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node /w/src/cli.js add Hello world && TODO_FILE=t.json node /w/src/cli.js list".to_owned(),
            format!("node --test 2>&1 | tail -12; cd \"{t}\" && TODO_FILE=t.json node /w/src/cli.js add Hello world && TODO_FILE=t.json node /w/src/cli.js list"),
        ),
        ("cd $(mktemp -d) && ls".to_owned(), format!("cd {t} && ls")),
        ("cd `mktemp -d` && ls".to_owned(), format!("cd {t} && ls")),
        (
            "pushd \"$(mktemp -dq)\"; ls".to_owned(),
            format!("pushd \"{t}\"; ls"),
        ),
        (
            "cd \"$(mktemp -d -t run.XXXXXX)\" || exit 1".to_owned(),
            format!("cd \"{t}\" || exit 1"),
        ),
        (
            "cd \"$(mktemp -qdt run.XXXXXX)\" && ls".to_owned(),
            format!("cd \"{t}\" && ls"),
        ),
    ] {
        assert_eq!(project(&command).as_deref(), Some(expected.as_str()), "{command}");
    }
}

#[test]
fn other_directories_and_positions_keep_the_command_opaque() {
    for command in [
        "cd \"$(mktemp -d)\" && cat ../x",
        "TMPDIR=/etc; cd \"$(mktemp -d)\" && ls",
        "cd \"$(mktemp -d /etc/XXX)\"",
        "cd \"$(mktemp -d -p /)\"",
        "cd \"$(whoami)\"",
        "cd \"$(date +%F)\"",
        // A template without `-t` names a path below the working directory.
        "cd \"$(mktemp -d run.XXXXXX)\"",
        "cd \"$(mktemp)\"",
        // BSD reads `d` as the prefix of `-t`, so no directory is made.
        "cd \"$(mktemp -td run.XXXXXX)\"",
        "cd \"$(mktemp -d -t)\"",
        "cd \"$(mktemp -d -t a.XXX -t)\"",
        "cd \"$(mktemp -d)/sub\"",
        "cd x\"$(mktemp -d)\"",
        "ls \"$(mktemp -d)\"",
        "echo \"cd $(mktemp -d)\"",
        "X=1 cd \"$(mktemp -d)\"",
        "D=$(mktemp -d) && cd $D",
        "cd \"$(mktemp -d)\" | cat",
        "cd \"$(mktemp -d)\" > log",
        "cd \"$(mktemp -d)\" &",
        "(cd \"$(mktemp -d)\" && ls)",
        "cd \"$(mktemp -d)\" \"$(mktemp -d)\"",
        "cd \"$(mktemp -d)\" && echo \"$(date +%F)\"",
        "echo 'cd \"$(mktemp -d)\"'",
        "ls",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn only_the_absent_stand_in_names_a_private_directory() {
    let t = TEMPORARY_VALUE;
    assert!(private_directory(t));
    let below = format!("{t}/sub");
    for target in [
        "/hol-guard-substituted",
        below.as_str(),
        "/tmp",
        "temporary-path",
    ] {
        assert!(!private_directory(target), "{target}");
    }
    assert_eq!(mentions(&format!("cd {t} && ls {t}/x")), 2);
    assert_eq!(mentions("cd /tmp"), 0);
}
