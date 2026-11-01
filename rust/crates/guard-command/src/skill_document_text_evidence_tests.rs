use std::path::PathBuf;

use serde_json::Value;

use super::{analyze_skill_document_text, is_remote_url, EXPLICIT_HTTP_CLIENT};

fn parity_vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/fixtures/skill-document-text-evidence-parity.v1.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {path:?}: {err}"));
    serde_json::from_slice(&bytes).expect("parity vectors parse")
}

#[test]
fn the_analyzer_matches_every_recorded_vector() {
    let document = parity_vectors();
    let cases = document["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "the parity fixture lost its cases");
    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let evidence = analyze_skill_document_text(case["text"].as_str().expect("case text"));
        assert_eq!(
            evidence.line_count,
            case["lineCount"].as_u64().expect("lineCount") as usize,
            "{id}: lineCount"
        );
        assert_eq!(
            evidence.heading_count,
            case["headingCount"].as_u64().expect("headingCount") as usize,
            "{id}: headingCount"
        );
        assert_eq!(
            evidence.frontmatter_present,
            case["frontmatterPresent"]
                .as_bool()
                .expect("frontmatterPresent"),
            "{id}: frontmatterPresent"
        );
        assert_eq!(
            evidence.documented_network_capability,
            case["documentedNetworkCapability"].as_str(),
            "{id}: documentedNetworkCapability"
        );
    }
}

#[test]
fn the_vectors_cover_both_evidence_codes_and_a_quiet_document() {
    let document = parity_vectors();
    let codes: Vec<Option<&str>> = document["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .map(|case| case["documentedNetworkCapability"].as_str())
        .collect();
    for expected in [
        Some("explicit_http_client"),
        Some("explicit_remote_api_statement"),
        None,
    ] {
        assert!(
            codes.contains(&expected),
            "the parity fixture stopped covering {expected:?}"
        );
    }
}

#[test]
fn an_unbalanced_ipv6_bracket_is_not_a_remote_host() {
    // `urlsplit` raises for this, and the Python scanner answered false.
    assert!(!is_remote_url("https://[::1/items"));
    assert!(!is_remote_url("https://]::1/items"));
}

#[test]
fn a_bracketed_host_that_is_not_an_address_is_not_a_remote_host() {
    // `urlsplit` checks what the brackets hold, so a name in them raises
    // there too and never reaches the scanner as a host.
    assert!(!is_remote_url("https://[api.example.com]/items"));
    assert!(!is_remote_url("https://[127.0.0.1]/items"));
    assert!(!is_remote_url("https://[]/items"));
    // An IPv6 literal and an IPvFuture address are what brackets are for.
    assert!(is_remote_url("https://[2606:4700::1111]/items"));
    assert!(is_remote_url("https://[v7.host]/items"));
    assert!(!is_remote_url("https://[::1]:8080/items"));
}

/// `urlsplit` validates the bracket in the hostname, which is what stands
/// after the last `@`, and allows nothing in front of the bracket or between
/// its close and the port delimiter. Reading the first bracket anywhere in the
/// netloc let a name keep an address as its host:
/// `api.example.com[2606:4700::1111]` answered with the address and earned
/// remote-network evidence for a URL Python refuses outright.
#[test]
fn a_bracket_that_does_not_start_the_hostname_is_not_a_remote_host() {
    assert!(!is_remote_url(
        "https://api.example.com[2606:4700::1111]/items"
    ));
    assert!(!is_remote_url(
        "https://user@api.example.com[2606:4700::1111]/items"
    ));
    // Only a port delimiter may follow the closing bracket.
    assert!(!is_remote_url("https://[2606:4700::1111]x:8080/items"));
    // A bracket standing only in the credentials leaves the hostname
    // unbracketed, and a name there is not an address.
    assert!(!is_remote_url("https://user[1]@api.example.com/items"));
    // The hostname is what stands after the last `@`, so a bracket in the
    // credentials never decides the one that does.
    assert!(is_remote_url("https://user[1]@[2606:4700::1111]/items"));
}

#[test]
fn a_bare_host_without_a_path_still_reads_as_remote() {
    assert!(is_remote_url("https://api.example.com"));
    assert!(is_remote_url("https://api.example.com:8443"));
    assert!(!is_remote_url("http://LOCALHOST:9000"));
}

#[test]
fn only_the_first_documented_capability_is_reported() {
    let text = concat!(
        "The skill calls the Example API to resolve names.\n",
        "Run curl https://api.example.com/v1/items for the list.\n",
    );
    assert_eq!(
        analyze_skill_document_text(text).documented_network_capability,
        Some("explicit_remote_api_statement"),
    );
}

#[test]
fn a_localhost_url_beside_a_remote_one_still_counts() {
    let text = "Run curl http://127.0.0.1:1 then curl https://api.example.com/v1\n";
    assert_eq!(
        analyze_skill_document_text(text).documented_network_capability,
        Some(EXPLICIT_HTTP_CLIENT),
    );
}
