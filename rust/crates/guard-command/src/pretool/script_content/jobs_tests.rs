use super::{background_moves_shell, sequential_jobs};

#[test]
fn a_job_followed_by_a_command_reads_as_a_list() {
    assert_eq!(
        sequential_jobs("node server.js & echo started").as_deref(),
        Some("node server.js ; echo started")
    );
    assert_eq!(
        sequential_jobs("python3 app.py & sleep 2 && echo ready").as_deref(),
        Some("python3 app.py ; sleep 2 && echo ready")
    );
}

#[test]
fn a_trailing_job_drops_its_ampersand() {
    assert_eq!(
        sequential_jobs("node server.js &").as_deref(),
        Some("node server.js")
    );
}

#[test]
fn lists_redirects_and_quotes_keep_their_ampersands() {
    assert_eq!(sequential_jobs("make && make test"), None);
    assert_eq!(sequential_jobs("echo 'a & b'"), None);
    // A redirect is outside what the split reads, so the text stays uncertain
    // rather than losing the `&` of `2>&1`.
    assert_eq!(
        sequential_jobs("node server.js > out.log 2>&1 & echo started"),
        None
    );
}

#[test]
fn a_background_job_that_moves_the_shell_stays_uncertain() {
    assert!(background_moves_shell("cd app && npm start & ls"));
    assert!(background_moves_shell("PORT=1 & node server.js"));
    assert!(background_moves_shell("export PORT=1 & node server.js"));
    // The last job moves nothing the shell runs afterwards.
    assert!(!background_moves_shell("node server.js & cd app"));
    assert!(!background_moves_shell("cd app && node server.js &"));
    assert!(!background_moves_shell(
        "node server.js --port=3000 & echo started"
    ));
}

#[test]
fn a_quoted_or_escaped_builtin_stays_uncertain() {
    // Either the split refuses the text or the prefix is read as moving the shell.
    let uncertain = |text: &str| sequential_jobs(text).is_none() || background_moves_shell(text);
    assert!(uncertain("'cd' sub && node server.js & node ../worker.js"));
    assert!(uncertain(
        "\"cd\" sub && node server.js & node ../worker.js"
    ));
    assert!(uncertain("c\\d sub && node server.js & node ../worker.js"));
    assert!(uncertain(
        "$(echo cd) sub && node server.js & node ../worker.js"
    ));
    assert!(uncertain(
        "command cd sub && node server.js & node ../worker.js"
    ));
    assert!(uncertain("if true; then cd sub; fi & node ../worker.js"));
}

#[test]
fn a_wrapped_builtin_with_options_still_moves_the_shell() {
    assert!(background_moves_shell(
        "command -p cd sub && node server.js & node ../worker.js"
    ));
    assert!(background_moves_shell(
        "time -p cd sub && node server.js & node ../worker.js"
    ));
    assert!(background_moves_shell(
        "builtin -- cd sub && node server.js & node ../worker.js"
    ));
}

#[test]
fn a_builtin_name_as_an_argument_moves_nothing() {
    assert!(!background_moves_shell("echo cd & node server.js"));
    assert!(!background_moves_shell(
        "node server.js --port $PORT --env export & echo started"
    ));
}
