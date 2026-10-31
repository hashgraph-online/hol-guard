//! A credential hidden by an encoding is still the credential.

use base64ct::{Base64, Encoding};

use super::super::{scan_secret_text, SecretFinding};
use super::ENCODED_REASON;

/// Assembled from pieces so no file in this repository holds a whole token of
/// a shape a credential scanner recognises.
fn aws_key() -> String {
    format!("{}{}{}", "AKIA", "QYLPT3K7", "R4FXM2WD")
}

fn github_token() -> String {
    format!("{}{}{}", "ghp_", "7Qk2TzVx9Lm", "R4Hb8Nd3PwYs6")
}

fn encode(plain: &str) -> String {
    Base64::encode_string(plain.as_bytes())
}

fn scan(text: &str, path: &str) -> Vec<SecretFinding> {
    scan_secret_text(text, path, "text", None, 200).findings
}

/// Only the findings the encoded pass contributed. A manifest line names its
/// value, so the generic assignment rule reports the payload as an opaque
/// high-entropy value as well; that reading is older than this pass and is not
/// what these tests are about.
fn decoded(findings: &[SecretFinding]) -> Vec<&SecretFinding> {
    findings
        .iter()
        .filter(|finding| finding.context_reasons.contains(&ENCODED_REASON))
        .collect()
}

#[test]
fn a_manifest_value_is_read_through_its_encoding() {
    let manifest = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: deploy\ndata:\n  AWS_ACCESS_KEY_ID: {}\n",
        encode(&aws_key())
    );

    let findings = scan(&manifest, "k8s/deploy-secret.yaml");
    let decoded = decoded(&findings);

    assert_eq!(decoded.len(), 1, "{findings:?}");
    assert_eq!(decoded[0].rule_id, "aws-access-key");
}

#[test]
fn a_finding_is_reported_at_the_run_a_reader_has_to_remove() {
    let manifest = format!(
        "apiVersion: v1\nkind: Secret\ndata:\n  deploy: {}\n",
        encode(&github_token())
    );

    let findings = scan(&manifest, "k8s/deploy-secret.yaml");
    let decoded = decoded(&findings);

    assert_eq!(decoded.len(), 1, "{findings:?}");
    assert_eq!(decoded[0].rule_id, "github-token");
    // The encoded run stands on the fourth line. The decoded bytes have no
    // line of their own in the file, so there is no other line to name.
    assert_eq!(decoded[0].line, 4);
}

#[test]
fn a_wrapped_dump_is_joined_before_it_is_read() {
    let dump = format!(
        "AWS_ACCESS_KEY_ID={}\nAWS_DEFAULT_REGION=eu-west-1\nAWS_ROLE=deployer\nAWS_SESSION_NAME=deploy-bot\n",
        aws_key()
    );
    let encoded = encode(&dump);
    // Two full 64-column lines and a short last one: a single line would be
    // read by the run pass instead, and the joining would never be exercised.
    assert!(
        encoded.len() > 128,
        "the dump has to be long enough to wrap"
    );
    let wrapped: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect();
    let text = format!("# env.b64\n{}\n", wrapped.join("\n"));

    let findings = scan(&text, "backup/env.b64");
    let decoded = decoded(&findings);

    assert_eq!(decoded.len(), 1, "{findings:?}");
    assert_eq!(decoded[0].rule_id, "aws-access-key");
    // The wrap starts on the second line, which is where the removal starts.
    assert_eq!(decoded[0].line, 2);
}

#[test]
fn a_single_encoded_line_is_read_once() {
    // One line is already a run. Joining it as a block as well would report
    // the same credential from the same place twice.
    let text = format!("{}\n", encode(&aws_key()));

    let findings = scan(&text, "backup/env.b64");

    assert_eq!(decoded(&findings).len(), 1, "{findings:?}");
}

#[test]
fn a_run_in_neither_alphabet_is_not_guessed_at() {
    // Valid base64 in neither the standard nor the URL-safe alphabet, so there
    // is no single reading of it to report.
    let text = "signature = AAAA+AAAAAAAA-AAAAAAAAAAAAAAAAAA\n";

    assert!(scan(text, "notes.txt").is_empty());
}

#[test]
fn bytes_that_are_not_text_are_left_alone() {
    let payload: Vec<u8> = (0u8..32).map(|byte| 0x80 | byte).collect();
    let text = format!("blob: {}\n", Base64::encode_string(&payload));

    assert!(decoded(&scan(&text, "notes.txt")).is_empty());
}

#[test]
fn ordinary_prose_decodes_to_nothing_worth_reporting() {
    let text = format!(
        "note: {}\n",
        encode("the quick brown fox jumps over the lazy dog, twice over")
    );

    assert!(decoded(&scan(&text, "notes.txt")).is_empty());
}

#[test]
fn a_credential_on_the_page_is_not_reported_a_second_time() {
    let text = format!("AWS_ACCESS_KEY_ID={}\n", aws_key());

    let findings = scan(&text, "deploy/notes.txt");

    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule_id, "aws-access-key");
    assert!(decoded(&findings).is_empty());
}

#[test]
fn a_credential_written_both_ways_is_reported_from_both_places() {
    // The same token on the page and in a payload is two places to remove it,
    // so the reader is shown both rather than only the one a scan reaches
    // first.
    let text = format!(
        "AWS_ACCESS_KEY_ID={}\nbackup: {}\n",
        aws_key(),
        encode(&aws_key())
    );

    let findings = scan(&text, "deploy/notes.txt");

    assert_eq!(findings.len(), 2, "{findings:?}");
    assert_eq!(findings[0].line, 1);
    assert!(!findings[0].context_reasons.contains(&ENCODED_REASON));
    assert_eq!(findings[1].line, 2);
    assert!(findings[1].context_reasons.contains(&ENCODED_REASON));
}

#[test]
fn the_callers_finding_bound_still_holds() {
    let mut text = String::from("data:\n");
    for index in 0..12 {
        text.push_str(&format!("  deploy_{index}: {}\n", encode(&aws_key())));
    }

    let findings = scan_secret_text(&text, "k8s/many.yaml", "text", None, 3).findings;

    assert_eq!(findings.len(), 3, "{findings:?}");
}
