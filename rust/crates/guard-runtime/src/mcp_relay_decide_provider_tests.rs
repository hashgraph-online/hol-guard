//! The provider lookups read from a seeded local CLI store.

use super::{answer, PROVIDER_INVALID};
use crate::guard_store_observed_mcp::marker_source;
use crate::local_store_read::{schema_checksum, SUPPORTED_SCHEMA_VERSION};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The harness a marker spells is canonicalized on read, the way
/// `store_mcp_provider_permissions._source` canonicalizes it, so the
/// selector this store answers with names `claude-code`.
const MARKER: &str = "observed-mcp:claude:mcp__composio__";

fn identity() -> String {
    marker_source(MARKER)
        .expect("the marker names a connector")
        .identity_hash()
}

/// A store at the schema the resident reads, with the two provider tables and
/// the observation and grant rows they join against.
fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("in-memory store");
    connection
        .execute_batch(
            "create table local_cli_schema_migration (singleton integer primary key, \
                 version integer not null, checksum text not null);\
             create table local_cli_observation (cli_id text primary key, identity_hash text, \
                 surface text, server_command text);\
             create table local_cli_grant (cli_id text, identity_hash text, state text);\
             create table local_mcp_provider_grant (cli_id text, identity_hash text, \
                 tool_slug text, state text);\
             create table local_mcp_provider_authority (cli_id text, identity_hash text, \
                 digest text);",
        )
        .expect("the schema");
    connection
        .execute(
            "insert into local_cli_schema_migration (singleton, version, checksum) \
             values (1, ?1, ?2)",
            rusqlite::params![
                SUPPORTED_SCHEMA_VERSION,
                schema_checksum(SUPPORTED_SCHEMA_VERSION)
            ],
        )
        .expect("the marker");
    connection
}

/// One observed connector the operator has answered for.
fn observe(connection: &Connection, cli_id: &str, identity_hash: &str, marker: &str, state: &str) {
    connection
        .execute(
            "insert into local_cli_observation (cli_id, identity_hash, surface, server_command) \
             values (?1, ?2, 'mcp', ?3)",
            rusqlite::params![cli_id, identity_hash, marker],
        )
        .expect("the observation");
    connection
        .execute(
            "insert into local_cli_grant (cli_id, identity_hash, state) values (?1, ?2, ?3)",
            rusqlite::params![cli_id, identity_hash, state],
        )
        .expect("the grant");
}

fn block(connection: &Connection, cli_id: &str, identity_hash: &str, slug: &str) {
    connection
        .execute(
            "insert into local_mcp_provider_grant (cli_id, identity_hash, tool_slug, state) \
             values (?1, ?2, ?3, 'block')",
            rusqlite::params![cli_id, identity_hash, slug],
        )
        .expect("the provider grant");
}

fn choices(connection: &Connection) -> Result<Value, &'static str> {
    answer(Some(connection), &json!({"kind": "provider_choices"})).expect("a provider lookup")
}

fn authority(connection: &Connection) -> Result<Value, &'static str> {
    answer(
        Some(connection),
        &json!({"kind": "provider_authority_hash"}),
    )
    .expect("a provider lookup")
}

#[test]
fn another_lookup_is_not_a_provider_lookup() {
    assert!(answer(None, &json!({"kind": "grant_lookup"})).is_none());
    assert!(answer(None, &json!({"phase": "initial"})).is_none());
}

#[test]
fn a_blocked_provider_action_is_read_as_its_selector() {
    let connection = store();
    let identity = identity();
    observe(&connection, "local-cli.one", &identity, MARKER, "allowed");
    block(&connection, "local-cli.one", &identity, "GMAIL_SEND_EMAIL");
    assert_eq!(
        choices(&connection),
        Ok(json!({
            "claude-code:mcp__composio__:composio:all-accounts:GMAIL_SEND_EMAIL": "block"
        }))
    );
}

#[test]
fn a_connector_the_operator_has_not_answered_for_steers_nothing() {
    let connection = store();
    let identity = identity();
    observe(&connection, "local-cli.one", &identity, MARKER, "pending");
    block(&connection, "local-cli.one", &identity, "GMAIL_SEND_EMAIL");
    assert_eq!(choices(&connection), Ok(json!({})));
}

#[test]
fn a_marker_that_does_not_name_its_identity_is_left_to_the_proxy() {
    let connection = store();
    observe(
        &connection,
        "local-cli.one",
        "not-the-identity",
        MARKER,
        "allowed",
    );
    block(
        &connection,
        "local-cli.one",
        "not-the-identity",
        "GMAIL_SEND_EMAIL",
    );
    assert_eq!(choices(&connection), Err(PROVIDER_INVALID));

    let connection = store();
    let identity = identity();
    observe(
        &connection,
        "local-cli.two",
        &identity,
        "observed-mcp:claude",
        "allowed",
    );
    block(&connection, "local-cli.two", &identity, "GMAIL_SEND_EMAIL");
    assert_eq!(choices(&connection), Err(PROVIDER_INVALID));
}

#[test]
fn an_action_a_selector_cannot_carry_is_left_to_the_proxy() {
    let long = "a".repeat(129);
    for slug in ["", "_leading", "has space", long.as_str()] {
        let connection = store();
        let identity = identity();
        observe(&connection, "local-cli.one", &identity, MARKER, "blocked");
        block(&connection, "local-cli.one", &identity, slug);
        assert_eq!(choices(&connection), Err(PROVIDER_INVALID), "{slug:?}");
    }
}

#[test]
fn the_authority_hash_covers_the_rows_in_order() {
    let connection = store();
    let identity = identity();
    observe(&connection, "local-cli.b", &identity, MARKER, "allowed");
    observe(&connection, "local-cli.a", &identity, MARKER, "allowed");
    for cli_id in ["local-cli.b", "local-cli.a"] {
        connection
            .execute(
                "insert into local_mcp_provider_authority (cli_id, identity_hash, digest) \
                 values (?1, ?2, ?3)",
                rusqlite::params![cli_id, identity, format!("digest-{cli_id}")],
            )
            .expect("the authority row");
    }
    let covered = format!(
        "[[\"local-cli.a\",\"{identity}\",\"digest-local-cli.a\"],\
          [\"local-cli.b\",\"{identity}\",\"digest-local-cli.b\"]]"
    );
    assert_eq!(
        authority(&connection),
        Ok(json!({"hash": hex::encode(Sha256::digest(covered.as_bytes()))}))
    );
}

#[test]
fn a_store_with_no_provider_row_answers_as_the_empty_store() {
    let connection = store();
    assert_eq!(choices(&connection), Ok(json!({})));
    assert_eq!(authority(&connection), Ok(json!({"hash": Value::Null})));
    assert_eq!(
        answer(None, &json!({"kind": "provider_choices"})),
        Some(Ok(json!({})))
    );
    assert_eq!(
        answer(None, &json!({"kind": "provider_authority_hash"})),
        Some(Ok(json!({"hash": Value::Null})))
    );
}

#[test]
fn a_store_without_the_local_schema_answers_as_the_empty_store() {
    let connection = Connection::open_in_memory().expect("in-memory store");
    assert_eq!(choices(&connection), Ok(json!({})));
    assert_eq!(authority(&connection), Ok(json!({"hash": Value::Null})));
}

#[test]
fn a_schema_the_resident_would_have_to_migrate_is_left_to_the_proxy() {
    let connection = store();
    connection
        .execute(
            "update local_cli_schema_migration set checksum = 'damaged'",
            [],
        )
        .expect("the damaged marker");
    assert!(choices(&connection).is_err());
    assert!(authority(&connection).is_err());
}

#[test]
fn a_hashed_cell_the_proxy_would_escape_is_left_to_it() {
    let connection = store();
    let identity = identity();
    observe(&connection, "local-cli.one", &identity, MARKER, "allowed");
    connection
        .execute(
            "insert into local_mcp_provider_authority (cli_id, identity_hash, digest) \
             values ('local-cli.one', ?1, 'dïgest')",
            rusqlite::params![identity],
        )
        .expect("the authority row");
    assert_eq!(authority(&connection), Err(PROVIDER_INVALID));
}
