//! Every diagnostic probe must be served by its named index in index order,
//! with no temp sort and no scan: that is what bounds the diagnostic on a
//! store holding many unrelated rows.

use rusqlite::Connection;
use serde_json::Value;

use super::{local_groups, policy_groups, Group};
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/diag_vectors.json.gz");

fn plan_details(
    connection: &Connection,
    groups: &[Group],
    table: &str,
    order: &str,
) -> Vec<String> {
    let mut details = Vec::new();
    for probe in groups.iter().flatten() {
        let sql = format!(
            "explain query plan select * from {table} indexed by {} where {} \
             order by {order} limit ?",
            probe.index, probe.predicate
        );
        let mut parameters = probe.parameters.clone();
        parameters.push(rusqlite::types::Value::Integer(32));
        let mut statement = connection.prepare(&sql).expect("probe must prepare");
        let rows = statement
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                row.get::<_, String>(3)
            })
            .expect("plan rows");
        for row in rows {
            details.push(format!("{} => {}", probe.index, row.expect("plan detail")));
        }
    }
    details
}

fn empty_store() -> Connection {
    let document: Value = gunzip_json(VECTORS);
    let connection = Connection::open_in_memory().expect("in-memory store");
    for statement in document["schema_sql"].as_array().expect("schema array") {
        connection
            .execute_batch(statement.as_str().expect("schema statement"))
            .expect("schema statement must apply");
    }
    connection
}

#[test]
fn probes_are_index_ordered_without_temp_sort() {
    let connection = empty_store();
    let local = local_groups(
        "codex",
        "codex:project:tool-action:diagnostic-plan",
        Some("family:tool-action"),
        Some("sha256:current"),
    );
    let policy = policy_groups(
        "codex",
        "codex:project:tool-action:diagnostic-plan",
        Some("family:tool-action"),
        Some("sha256:current"),
        Some("publisher-current"),
    );
    let local_details = plan_details(
        &connection,
        &local,
        "guard_local_once_approvals",
        "created_at desc, approval_id desc",
    );
    let policy_details = plan_details(
        &connection,
        &policy,
        "policy_decisions",
        "updated_at desc, decision_id desc",
    );
    assert!(!local_details.is_empty() && !policy_details.is_empty());
    for detail in &local_details {
        assert!(
            detail.contains("SEARCH guard_local_once_approvals USING INDEX"),
            "{detail}"
        );
    }
    for detail in &policy_details {
        assert!(
            detail.contains("SEARCH policy_decisions USING INDEX"),
            "{detail}"
        );
    }
    for detail in local_details.iter().chain(&policy_details) {
        assert!(!detail.contains("USE TEMP B-TREE"), "{detail}");
    }
}
