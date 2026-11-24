use super::message_positions;
use crate::pretool::source_reads::sensitive_command_input;

fn positions(command: &str) -> Option<Vec<usize>> {
    let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
    message_positions(&arguments)
}

#[test]
fn message_values_of_each_recording_command_are_found() {
    assert_eq!(positions("commit -m note"), Some(vec![2]));
    assert_eq!(positions("-C repo commit -am note"), Some(vec![4]));
    assert_eq!(positions("commit --message note"), Some(vec![2]));
    assert_eq!(positions("commit --message=note"), Some(vec![1]));
    assert_eq!(positions("commit -mnote -m second"), Some(vec![1, 3]));
    assert_eq!(positions("tag -a v1 -m note"), Some(vec![4]));
    assert_eq!(positions("merge --no-ff topic -m note"), Some(vec![4]));
    assert_eq!(positions("stash push -m note"), Some(vec![3]));
}

#[test]
fn files_pathspecs_and_other_commands_are_not_messages() {
    assert_eq!(positions("commit -F note.txt"), Some(vec![]));
    assert_eq!(positions("commit -m note -- -m"), Some(vec![2]));
    assert_eq!(positions("commit -um note"), Some(vec![]));
    assert_eq!(positions("log -m note"), Some(vec![]));
    assert_eq!(positions("stash list -m note"), Some(vec![]));
    assert_eq!(positions("commit -m"), Some(vec![]));
    assert_eq!(positions("commit -C -m note"), Some(vec![]));
    assert_eq!(positions("commit --author -m note"), Some(vec![]));
    assert_eq!(positions("commit -aC -m note"), Some(vec![]));
    assert_eq!(positions("commit -C HEAD -m note"), Some(vec![4]));
}

#[test]
fn an_abbreviated_or_unknown_long_option_leaves_the_message_unknown() {
    // Git expands `--auth` to `--author`, which takes `-m` as its value.
    assert_eq!(positions("commit --auth -m .env"), None);
    assert_eq!(positions("commit --no-veri -m note"), None);
    assert_eq!(
        positions("commit --amend --no-verify -m note"),
        Some(vec![4])
    );
    assert_eq!(positions("commit --author=someone -m note"), Some(vec![3]));
}

#[test]
fn merge_reads_s_as_a_strategy_that_takes_the_next_token() {
    assert_eq!(positions("merge -s -m note"), Some(vec![]));
    assert_eq!(positions("merge -sm note"), Some(vec![]));
    assert_eq!(positions("merge -s ours -m note"), Some(vec![4]));
    assert_eq!(positions("commit -sm note"), Some(vec![2]));
    assert_eq!(positions("tag -sm note v1"), Some(vec![2]));
}

#[test]
fn a_message_that_can_expand_is_not_set_aside() {
    assert_eq!(positions("commit -m $(cat)"), None);
    assert_eq!(positions("commit -m `cat`"), None);
    assert_eq!(positions("commit --message=$NOTE"), None);
    assert_eq!(positions("commit -m {note,.env}"), None);
    assert_eq!(positions("commit -m .env*"), None);
    assert_eq!(positions("commit -m note?"), None);
    assert_eq!(positions("commit -m [n]ote"), None);
}

#[test]
fn a_credential_word_in_a_literal_message_is_not_a_sensitive_target() {
    for command in [
        "git commit -m \"fix(auth): keep the client secret out of logs\"",
        "git -C ../other commit -am 'docs: explain password rotation' 2>&1 | tail -2",
        "env -u GIT_AUTHOR_EMAIL -u GIT_AUTHOR_NAME git commit -m \"fix: redact the secret field\" 2>&1 | tail -2",
        "git tag -a v1.2.0 -m 'rotate the api key loader'",
        "git add src && git commit -m 'test: cover the private_key parser'",
    ] {
        assert!(!sensitive_command_input(command), "{command}");
    }
}

#[test]
fn everything_outside_the_message_keeps_its_screen() {
    for command in [
        "git commit -m \"$(cat ~/.aws/credentials)\"",
        "git commit -m \"note `cat secret.txt`\"",
        "git commit -F ~/.ssh/id_rsa",
        "git commit -m note ~/.ssh/config",
        "git commit -m note > ~/.ssh/authorized_keys",
        "git commit -m 'rotate the secret' && cat .env",
        "git log -m 'secret'",
        "git commit -C -m ~/.ssh/id_rsa",
        "git commit -m {note,.env}",
        "git commit -m .env*",
        "echo 'commit -m secret'",
    ] {
        assert!(sensitive_command_input(command), "{command}");
    }
}
