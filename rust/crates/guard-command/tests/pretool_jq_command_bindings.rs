#![cfg(unix)]

use crate::pretool_git_session_ops::session;

/// jq reads a value bound on its command line as plainly as one it reads
/// from input. `--arg` and `--argjson` bind text, and `--slurpfile` and
/// `--rawfile` bind a file that clears the same read screen an input file
/// does, so a filter that reads those names back gets the answer the read
/// gets alone.
#[test]
fn jq_may_read_names_its_command_line_binds() {
    let session = session("jq-command-bindings");
    std::fs::write(
        session.primary.join("rows.json"),
        "{\"id\":1}\n{\"id\":2}\n",
    )
    .unwrap();
    std::fs::write(session.primary.join("after.json"), "{\"id\":2}\n").unwrap();
    for command in [
        "jq -rn --slurpfile h rows.json '$h | length'",
        "jq -n --slurpfile h rows.json --slurpfile a after.json '($h | map(.id)) as $ids | $a | map(select(.id as $x | $ids | index($x)))'",
        "jq --arg want 2 'select((.id | tostring) == $want)' rows.json",
        "jq -c --argjson n 1 'select(.id > $n)' rows.json",
        "jq -rn --rawfile body rows.json '$body | length'",
        "cat rows.json | jq --arg want 2 'select((.id | tostring) == $want)'",
        "cat rows.json | jq -c --slurpfile a after.json 'select(.id == $a[0].id)'",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A binding that reads a credential, a filter that reads a name nothing
/// bound or the environment, and options that load filter code stay
/// reviewed.
#[test]
fn other_jq_bindings_keep_their_review() {
    let session = session("jq-command-bindings-negative");
    std::fs::write(session.primary.join("rows.json"), "{\"id\":1}\n").unwrap();
    for command in [
        "jq -rn --rawfile key ~/.ssh/id_rsa '$key'",
        "jq -rn --slurpfile c ~/.aws/credentials '$c'",
        "cat rows.json | jq --rawfile key ~/.ssh/id_rsa '$key'",
        "jq --arg want 2 '$other' rows.json",
        "jq --arg ENV x '$ENV' rows.json",
        "jq -n '$ENV.HOME'",
        "jq --argfile r rows.json '$r' rows.json",
        "jq -n -f rows.json",
        "jq -L . 'import \"rows\" as r; r' rows.json",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
