use super::*;

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null, updated_at text not null);
             create table guard_supply_chain_bundle_cache (workspace_id text primary key, response_json text not null, cached_at text not null);",
        )
        .unwrap();
    connection
}

#[test]
fn no_cloud_workspace_reads_no_bundle() {
    assert_eq!(cached_bundle(&connection()).unwrap(), Value::Null);
}

#[test]
fn a_blank_workspace_id_reads_no_bundle() {
    let connection = connection();
    connection
        .execute(
            "insert into sync_state values ('oauth_local_credentials', '{\"workspace_id\":\"  \"}', 'now')",
            [],
        )
        .unwrap();
    assert_eq!(cached_bundle(&connection).unwrap(), Value::Null);
}

#[test]
fn the_workspace_bundle_is_read_from_its_cached_response() {
    let connection = connection();
    connection
        .execute_batch(
            "insert into sync_state values ('oauth_local_credentials', '{\"workspace_id\":\"ws-1\"}', 'now');
             insert into guard_supply_chain_bundle_cache values ('ws-1', '{\"bundle\":{\"rules\":[1]}}', 'then');
             insert into guard_supply_chain_bundle_cache values ('ws-2', '{\"bundle\":{\"rules\":[2]}}', 'then');",
        )
        .unwrap();
    assert_eq!(
        cached_bundle(&connection).unwrap(),
        serde_json::json!({"rules": [1]})
    );
}

#[test]
fn a_cached_response_without_a_bundle_reads_null() {
    let connection = connection();
    connection
        .execute_batch(
            "insert into sync_state values ('oauth_local_credentials', '{\"workspace_id\":\"ws-1\"}', 'now');
             insert into guard_supply_chain_bundle_cache values ('ws-1', '[]', 'then');",
        )
        .unwrap();
    assert_eq!(cached_bundle(&connection).unwrap(), Value::Null);
}
