use std::collections::BTreeMap;

use serde_json::json;

use guard_contracts::EgressOutcomeV1;

use super::{answer, dispatch, failure_code, search_url, valid_query};

fn json_headers(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("content-type".to_owned(), value.to_owned())])
}

fn page() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "metadata": { "count": 1 },
        "servers": [{
            "server": {
                "name": "example/server",
                "version": "1.0.0",
                "remotes": [{ "type": "streamable-http", "url": "https://mcp.example.test/mcp" }],
            },
            "_meta": { "io.modelcontextprotocol.registry/official": { "status": "active" } },
        }],
    }))
    .expect("fixture encodes")
}

#[test]
fn a_query_must_be_two_to_eighty_characters_with_no_control_character() {
    for query in ["", "x", " x ", "bad\nheader", "tab\there"] {
        assert_eq!(valid_query(query), None, "{query:?}");
    }
    assert_eq!(valid_query(&"a".repeat(81)), None);
    assert_eq!(valid_query(&"é".repeat(80)), Some("é".repeat(80).as_str()));
    assert_eq!(valid_query("  Composio  "), Some("Composio"));
}

#[test]
fn an_invalid_query_is_answered_without_a_fetch() {
    let answer = dispatch(&json!({ "query": "x" })).expect("well-formed request");
    assert_eq!(answer, json!({ "error": "invalid_registry_search" }));
    assert!(dispatch(&json!({})).is_err());
    assert!(dispatch(&json!({ "query": 3 })).is_err());
}

#[test]
fn the_search_reaches_only_the_fixed_registry_origin() {
    assert_eq!(
        search_url("Composio cloud&x=1"),
        "https://registry.modelcontextprotocol.io/v0.1/servers?search=Composio+cloud%26x%3D1&version=latest&limit=20"
    );
}

#[test]
fn a_json_page_becomes_the_listing() {
    let answer = answer(
        200,
        &json_headers("application/json; charset=utf-8"),
        &page(),
    );
    let listing = &answer["listing"];
    assert_eq!(listing["count"], json!(1));
    assert_eq!(listing["coverage"], json!("search-page"));
    assert_eq!(listing["results"][0]["name"], json!("example/server"));
    assert_eq!(listing["results"][0]["installed"], json!(false));
}

#[test]
fn a_failed_status_or_another_media_type_is_unavailable() {
    let unavailable = json!({ "error": "registry_unavailable" });
    assert_eq!(
        answer(503, &json_headers("application/json"), &page()),
        unavailable
    );
    assert_eq!(
        answer(200, &json_headers("text/html"), &page()),
        unavailable
    );
    assert_eq!(answer(200, &BTreeMap::new(), &page()), unavailable);
}

#[test]
fn an_oversize_or_malformed_body_is_refused() {
    let headers = json_headers("application/json");
    assert_eq!(
        answer(200, &headers, &vec![b' '; 512_001]),
        json!({ "error": "registry_response_too_large" })
    );
    let invalid = json!({ "error": "registry_response_invalid" });
    assert_eq!(
        answer(
            200,
            &headers,
            br#"{"servers":[],"servers":[],"metadata":{}}"#
        ),
        invalid
    );
    assert_eq!(
        answer(200, &headers, br#"{"metadata":{},"servers":[{}]}"#),
        invalid
    );
}

#[test]
fn an_oversize_exchange_keeps_its_code_and_other_failures_are_outages() {
    let oversize = EgressOutcomeV1::Error {
        message: "response too large".to_owned(),
    };
    assert_eq!(failure_code(&oversize), "registry_response_too_large");
    let transport = EgressOutcomeV1::Error {
        message: "transport".to_owned(),
    };
    assert_eq!(failure_code(&transport), "registry_unavailable");
    assert_eq!(
        failure_code(&EgressOutcomeV1::Timeout),
        "registry_unavailable"
    );
}
