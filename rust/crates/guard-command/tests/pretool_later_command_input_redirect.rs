#![cfg(unix)]

//! An input redirect on a command after the first one.
//!
//! Agents check a log after printing a label, as in
//! `tail -5 run.log; echo "---size:"; wc -c < run.log`. `wc -c < run.log`
//! alone was allowed, because `cmd < file` is read as `cat file | cmd`, but
//! the same redirect after `;` or `&&` went to review. The redirect now gets
//! that reading in the place of the command that carries it, so the file's
//! read keeps every check `cat` gets, and the reader keeps its own.

use crate::pretool_home_layout_reads::{layout, write};
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_later_command_may_read_a_project_file_through_an_input_redirect() {
    let layout = layout("later-input-redirect");
    let app = layout.org.join("app-portal");
    write(app.join("run.log"), "line one\nline two\n");
    write(app.join(".env"), "FIXTURE_VALUE=1\n");
    write(layout.home.join(".ssh/id_ed25519"), "fixture\n");
    let home = layout.home.to_str().unwrap();
    let cwd = app.to_str().unwrap();
    let log = app.join("run.log");
    let log = log.to_str().unwrap();
    for harness in ["zcode", "codex", "claude-code"] {
        for (command, allowed) in [
            ("wc -c < run.log".to_owned(), true),
            ("echo x; wc -c < run.log".to_owned(), true),
            (
                "tail -5 run.log 2>/dev/null; echo \"---size:\"; wc -c < run.log".to_owned(),
                true,
            ),
            (
                format!("tail -5 {log}; echo \"---size:\"; wc -c < {log}"),
                true,
            ),
            ("ls src && wc -l < src/main.rs".to_owned(), true),
            (
                "echo x; sort < run.log | head -1; echo done".to_owned(),
                true,
            ),
            // The file read keeps the checks `cat` gets.
            ("echo x; wc -c < .env".to_owned(), false),
            ("echo x; wc -c < ~/.ssh/id_ed25519".to_owned(), false),
            // The program reading it keeps its own.
            ("echo x; sh < run.log".to_owned(), false),
            ("echo x; cd /etc < run.log; cat passwd".to_owned(), false),
            // A pipe, group or substitution before the redirect, or a second
            // input redirect, leaves which command reads the file unclear.
            ("ls | wc -l < run.log".to_owned(), false),
            // An escaped twin is a literal: these are a pipe and a
            // background `&`, not `||` and `&&`.
            (r"echo \|| wc -c < run.log".to_owned(), false),
            (r"echo \&& wc -c < run.log".to_owned(), false),
            ("echo $(id); wc -l < run.log".to_owned(), false),
            ("(echo x); wc -l < run.log".to_owned(), false),
            ("echo x; wc -l < run.log < src/main.rs".to_owned(), false),
            ("wc -l < run.log; wc -l < src/main.rs".to_owned(), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
                None,
                None,
                Some(home),
                Some(cwd),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} => {} / {}",
                result.minimum_action,
                result.reason_code
            );
        }
    }
}
