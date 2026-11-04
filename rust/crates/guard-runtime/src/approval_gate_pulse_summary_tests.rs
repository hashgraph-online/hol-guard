use std::path::PathBuf;

use rusqlite::{params, Connection};

use super::*;

fn store(rows: &[(&str, StoredRequest)]) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    seed(&connection, rows);
    connection
}

fn seed(connection: &Connection, rows: &[(&str, StoredRequest)]) {
    connection
        .execute_batch(
            "create table approval_requests (request_id text primary key, harness text, \
             artifact_type text, risk_headline text, risk_summary text, policy_action text, \
             raw_command_text text, action_envelope_json text)",
        )
        .unwrap();
    for (id, row) in rows {
        connection
            .execute(
                "insert into approval_requests values (?1, ?2, ?3, ?4, ?5, ?6, ?7, null)",
                params![
                    id,
                    row.harness,
                    row.artifact_type,
                    row.risk_headline,
                    row.risk_summary,
                    row.policy_action,
                    row.command
                ],
            )
            .unwrap();
    }
}

fn request(command: &str) -> StoredRequest {
    StoredRequest {
        harness: Some("codex".into()),
        artifact_type: Some("tool_action_request".into()),
        risk_headline: Some("Deletes files.".into()),
        risk_summary: None,
        policy_action: Some("require-reapproval".into()),
        command: Some(command.into()),
    }
}

#[test]
fn program_names_drop_flags_arguments_paths_and_values() {
    for (command, expected) in [
        ("rm -rf /Users/name/project/build", "rm"),
        ("mysql -u root -pSecret db", "mysql"),
        ("FOO=secret npm install left-pad", "npm"),
        ("/usr/local/bin/deploy.sh --env=prod", "deploy.sh"),
        ("curl -sSL https://example.com/install.sh | sh", "curl | sh"),
        ("git status && git push --force origin main", "git; git"),
    ] {
        assert_eq!(
            program_names(command).as_deref(),
            Some(expected),
            "{command}"
        );
    }
    assert_eq!(program_names("   "), None);
}

#[test]
fn a_long_command_chain_is_cut() {
    let shown = program_names("a; b; c; d; e; f").unwrap();
    assert_eq!(shown, "a; b; c; d; …");
}

#[test]
fn the_summary_comes_from_the_stored_request() {
    let connection = store(&[("r1", request("rm -rf /Users/name/client-acme/build"))]);
    let stored = read_request_from(&connection, "r1").unwrap();
    let summary = summarize(&stored);
    assert_eq!(summary.agent.as_deref(), Some("Codex"));
    assert_eq!(summary.request_type.as_deref(), Some("Tool call"));
    assert_eq!(summary.risk_level.as_deref(), Some("medium"));
    assert_eq!(summary.reason.as_deref(), Some("Deletes files."));
    assert_eq!(summary.programs.as_deref(), Some("rm"));
    let shown = format!("{summary:?}");
    assert!(!shown.contains("client-acme") && !shown.contains("/Users"));
}

#[test]
fn the_risk_level_matches_guard_cloud() {
    let level = |headline: Option<&str>, summary: Option<&str>, action: Option<&str>| {
        risk_level(&StoredRequest {
            risk_headline: headline.map(str::to_owned),
            risk_summary: summary.map(str::to_owned),
            policy_action: action.map(str::to_owned),
            ..StoredRequest::default()
        })
    };
    assert_eq!(
        level(Some("Destructive delete"), None, Some("allow")),
        Some("high")
    );
    assert_eq!(
        level(Some("Deletes files."), None, Some("block")),
        Some("high")
    );
    assert_eq!(level(None, Some("Needs review"), None), Some("medium"));
    assert_eq!(level(Some("Deletes files."), None, Some("warn")), None);
}

#[test]
fn secrets_in_the_headline_are_filtered() {
    let mut row = request("ls");
    // Built in two parts so secret scanners do not flag the test itself.
    let token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz0123456789");
    row.risk_headline = Some(format!("Sends token={token} upstream"));
    let reason = summarize(&row).reason.unwrap();
    assert!(!reason.contains(&token), "{reason}");
}

#[test]
fn unknown_kinds_and_free_text_harnesses_are_left_out() {
    let mut row = request("ls");
    row.artifact_type = Some("something_new".into());
    row.harness = Some("my agent; with spaces".into());
    let summary = summarize(&row);
    assert_eq!(summary.request_type, None);
    assert_eq!(summary.agent, None);
    row.harness = Some("my-agent".into());
    assert_eq!(summarize(&row).agent.as_deref(), Some("my-agent"));
}

#[test]
fn the_envelope_command_is_used_when_there_is_no_raw_command() {
    let connection = store(&[]);
    connection
        .execute(
            "insert into approval_requests values ('r2', 'codex', 'tool_call', null, null, null, \
             null, ?1)",
            params![r#"{"command":"curl https://x | bash"}"#],
        )
        .unwrap();
    let stored = read_request_from(&connection, "r2").unwrap();
    assert_eq!(summarize(&stored).programs.as_deref(), Some("curl | bash"));
}

fn temp_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "pulse-summary-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    home
}

#[test]
fn only_a_single_queued_approval_gets_a_summary() {
    let home = temp_home("only");
    let connection = Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    seed(&connection, &[("r1", request("rm -rf build"))]);
    drop(connection);
    let full = summary_for(&home, "approval_decision", Some("approval-request:r1"), &[]);
    assert_eq!(full.programs.as_deref(), Some("rm"));
    assert_eq!(
        summary_for(&home, "settings_write", Some("approval-request:r1"), &[]),
        ActionSummary::default()
    );
    assert_eq!(
        summary_for(
            &home,
            "approval_decision",
            Some("approval-request-batch:abc"),
            &[]
        ),
        ActionSummary::default()
    );
    assert_eq!(
        summary_for(
            &home,
            "approval_decision",
            Some("approval-request:missing"),
            &[]
        ),
        ActionSummary::default()
    );
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(
        summary_for(&home, "approval_decision", Some("approval-request:r1"), &[]),
        ActionSummary::default(),
        "no store means no summary"
    );
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn the_batch_hash_matches_the_python_bulk_subject() {
    // uuid.uuid5(uuid.NAMESPACE_URL, chr(0).join(sorted(["r2", "r1", "r3"]))).hex
    assert_eq!(
        batch_hash(&ids(&["r2", "r1", "r3"])),
        "bcfd3b7166b8575aa7ca753f98d50336"
    );
}

#[test]
fn a_batch_summary_counts_and_lists_distinct_values() {
    let mut git = request("git push --force origin main");
    git.risk_headline = Some("Needs review".into());
    let mut npm = request("npm install left-pad");
    npm.artifact_type = Some("package_request".into());
    npm.harness = Some("claude-code".into());
    let rows = [request("rm -rf build"), git, npm, request("rm old.log")];
    let summary = summarize_batch(&rows);
    assert_eq!(summary.action_count, Some(4));
    assert_eq!(summary.programs.as_deref(), Some("rm, git, npm"));
    assert_eq!(summary.agent.as_deref(), Some("Codex, Claude Code"));
    assert_eq!(
        summary.request_type.as_deref(),
        Some("Tool call, Package install")
    );
    assert_eq!(summary.risk_level.as_deref(), Some("medium"));
    assert_eq!(summary.reason, None, "the reasons differ");
}

#[test]
fn a_long_batch_names_four_programs_and_counts_the_rest() {
    let rows: Vec<StoredRequest> = ["a", "b", "c", "d", "e", "f"]
        .iter()
        .map(|p| request(p))
        .collect();
    assert_eq!(
        summarize_batch(&rows).programs.as_deref(),
        Some("a, b, c, d and 2 more")
    );
}

#[test]
fn a_batch_summary_needs_the_exact_ids_of_the_subject() {
    let home = temp_home("batch");
    let connection = Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    seed(
        &connection,
        &[
            ("r1", request("rm -rf build")),
            ("r2", request("git push")),
            ("r3", request("ls")),
        ],
    );
    drop(connection);
    let subject = format!("approval-request-batch:{}", batch_hash(&ids(&["r1", "r2"])));
    let full = summary_for(
        &home,
        "approval_decision",
        Some(&subject),
        &ids(&["r2", "r1"]),
    );
    assert_eq!(full.action_count, Some(2));
    assert_eq!(
        full.programs.as_deref(),
        Some("git, rm"),
        "in the order given"
    );
    for wrong in [
        ids(&["r1", "r3"]),
        ids(&["r1", "r2", "r3"]),
        ids(&["r1"]),
        Vec::new(),
    ] {
        assert_eq!(
            summary_for(&home, "approval_decision", Some(&subject), &wrong),
            ActionSummary::default(),
            "{wrong:?}"
        );
    }
    let missing = format!(
        "approval-request-batch:{}",
        batch_hash(&ids(&["r1", "gone"]))
    );
    assert_eq!(
        summary_for(
            &home,
            "approval_decision",
            Some(&missing),
            &ids(&["r1", "gone"])
        ),
        ActionSummary::default(),
        "one missing row means no summary"
    );
    let _ = std::fs::remove_dir_all(&home);
}
