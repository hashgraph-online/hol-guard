//! A credential a command line carries as an argument is still the credential.

use super::super::{scan_secret_text, secret_rule_catalog, SecretFinding};
use super::{AUTHORIZATION_HEADER_REASON, CREDENTIAL_OPTION_REASON};

/// Assembled from pieces so no file in this repository holds a whole value of
/// a shape a credential scanner recognises.
fn issued_value() -> String {
    format!("{}{}", "hq8NdPvK2rTw", "Q5mZxL7Bc4Jy")
}

fn second_issued_value() -> String {
    format!("{}{}", "Rr4mWq9Z", "tB6kPx2L")
}

fn github_token() -> String {
    format!("{}{}{}", "ghp_", "3Vd8RmQc5Tn", "L6Jk2WbY9Xz4")
}

fn scan(text: &str, path: &str) -> Vec<SecretFinding> {
    scan_secret_text(text, path, "text", None, 200).findings
}

/// Only the findings this pass contributed.
fn on_a_command_line(findings: &[SecretFinding]) -> Vec<&SecretFinding> {
    findings
        .iter()
        .filter(|finding| {
            finding
                .context_reasons
                .contains(&AUTHORIZATION_HEADER_REASON)
                || finding.context_reasons.contains(&CREDENTIAL_OPTION_REASON)
        })
        .collect()
}

#[test]
fn a_bearer_header_in_a_workflow_is_read() {
    let value = issued_value();
    let workflow = format!(
        "jobs:\n  publish:\n    steps:\n      - run: curl -sS -H \"Authorization: Bearer {value}\" https://registry.internal/v1/publish\n"
    );
    let findings = scan(&workflow, ".github/workflows/publish.yml");
    let read = on_a_command_line(&findings);
    assert_eq!(read.len(), 1, "{findings:#?}");
    assert_eq!(read[0].rule_id, "credential-command");
    assert_eq!(read[0].candidate, value);
    assert_eq!(read[0].line, 4);
    assert!(read[0]
        .context_reasons
        .contains(&AUTHORIZATION_HEADER_REASON));
}

#[test]
fn a_proxy_authorization_header_is_read_the_same_way() {
    let value = issued_value();
    let script =
        format!("curl -H 'Proxy-Authorization: Token {value}' https://registry.internal\n");
    let read = scan(&script, "deploy/fetch.yaml");
    let read = on_a_command_line(&read);
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].candidate, value);
}

#[test]
fn a_password_option_on_a_login_command_is_read() {
    let value = issued_value();
    let script =
        format!("docker login registry.internal --username ci-publisher --password {value}\n");
    let findings = scan(&script, "deploy/publish.sh");
    let read = on_a_command_line(&findings);
    assert_eq!(read.len(), 1, "{findings:#?}");
    assert_eq!(read[0].rule_id, "credential-command");
    assert_eq!(read[0].candidate, value);
    assert!(read[0].context_reasons.contains(&CREDENTIAL_OPTION_REASON));
}

#[test]
fn a_shorter_option_value_outside_code_is_read() {
    let value = second_issued_value();
    let compose = format!("    command: psql --host db.internal --password {value}\n");
    let read = scan(&compose, "deploy/bootstrap.yaml");
    let read = on_a_command_line(&read);
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].candidate, value);
}

#[test]
fn an_option_naming_where_the_credential_lives_is_not_one() {
    // `--password-stdin` and `--password-file` both say where to read the
    // credential from. The character after the option name is a hyphen rather
    // than the space the rule requires, so neither is read as carrying it.
    let script = concat!(
        "docker login registry.internal --password-stdin < /run/secrets/registry\n",
        "mysql --user ci --password-file /run/secrets/database/password\n",
    );
    assert!(on_a_command_line(&scan(script, "deploy/publish.sh")).is_empty());
}

#[test]
fn an_option_handed_a_variable_is_a_reference_not_a_credential() {
    let script = concat!(
        "gh auth login --token $GITHUB_TOKEN\n",
        "helm registry login --password ${REGISTRY_PASSWORD}\n",
    );
    assert!(on_a_command_line(&scan(script, "deploy/publish.sh")).is_empty());
}

#[test]
fn a_header_written_out_in_documentation_is_not_reported() {
    let value = issued_value();
    let guide = format!("Call the registry:\n\n    curl -H \"Authorization: Bearer {value}\" https://registry.internal/v1/publish\n");
    assert!(on_a_command_line(&scan(&guide, "docs/publishing.md")).is_empty());
}

#[test]
fn a_basic_header_is_left_to_the_pass_that_reads_encodings() {
    // `Basic` carries `user:password` base64-encoded. What reads a payload is
    // the encoded pass, which applies provider formats; this rule has no line
    // of the file to score a decoded value against, so it does not claim one.
    let script = format!(
        "curl -H 'Authorization: Basic {}' https://registry.internal\n",
        "Y2ktcHVibGlzaGVyOmhxOE5kUHZLMnJUd1E1bVp4TDdCYzRKeQ=="
    );
    assert!(on_a_command_line(&scan(&script, "deploy/publish.sh")).is_empty());
}

#[test]
fn a_provider_token_in_a_header_is_reported_once_under_its_own_rule() {
    let token = github_token();
    let script = format!("curl -H \"Authorization: Bearer {token}\" https://api.github.com/user\n");
    let findings = scan(&script, "deploy/publish.sh");
    let named: Vec<&str> = findings.iter().map(|finding| finding.rule_id).collect();
    assert_eq!(named, vec!["github-token"], "{findings:#?}");
    assert!(on_a_command_line(&findings).is_empty());
}

#[test]
fn an_option_spelled_as_an_assignment_stays_with_the_assignment_rule() {
    let value = issued_value();
    let script = format!("docker login registry.internal --password={value}\n");
    let findings = scan(&script, "deploy/publish.sh");
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].rule_id, "credential-assignment");
    assert!(on_a_command_line(&findings).is_empty());
}

#[test]
fn an_option_that_does_not_say_what_it_carries_is_left_alone() {
    // `-u user:password` is the common shape with no credential word of its
    // own. Contextual scoring has nothing to read, so the rule does not guess.
    // Assembled rather than written out: a user and a value either side of a
    // colon is itself a shape a scanner names, and this file holds no such
    // literal.
    let pair = format!("ci-publisher:{}", issued_value());
    let script = format!("curl -u {pair} https://registry.internal/v1/publish\n");
    assert!(on_a_command_line(&scan(&script, "deploy/publish.sh")).is_empty());
}

#[test]
fn the_catalog_names_the_command_rule_before_the_entry_python_published() {
    // The secrets CLI vectors pin Python's own contextual entry as the last
    // row the `rules` command prints, so this rule takes the place before it.
    let catalog = secret_rule_catalog();
    assert_eq!(
        catalog.last().expect("the catalog is never empty").rule_id,
        "credential-assignment"
    );
    let added = &catalog[catalog.len() - 2];
    assert_eq!(added.rule_id, "credential-command");
    assert_eq!(added.severity, "high");
    assert!(!added.strong_format);
}
