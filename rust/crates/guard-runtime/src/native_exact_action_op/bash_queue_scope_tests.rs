//! Queue resolutions retain the resident owner used by ordinary queue reads.
use super::*;

fn complete_queue_schema(connection: &Connection) {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../testdata/guard_store/approval_queue_result_vectors.json"
    ))
    .unwrap();
    let schema = Connection::open_in_memory().unwrap();
    for ddl in vectors["schema_sql"].as_array().unwrap() {
        schema.execute_batch(ddl.as_str().unwrap()).unwrap();
    }
    let mut statement = schema
        .prepare("PRAGMA table_info(approval_requests)")
        .unwrap();
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .unwrap();
    let existing: Vec<String> = connection
        .prepare("PRAGMA table_info(approval_requests)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    for column in columns {
        let (name, kind, default) = column.unwrap();
        if !existing.contains(&name) {
            let default = default
                .map(|value| format!(" DEFAULT {value}"))
                .unwrap_or_default();
            connection
                .execute_batch(&format!(
                    "ALTER TABLE approval_requests ADD COLUMN \"{name}\" {kind}{default}"
                ))
                .unwrap();
        }
    }
    for ddl in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(
                &ddl.as_str()
                    .unwrap()
                    .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
                    .replacen("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)
                    .replacen(
                        "CREATE UNIQUE INDEX ",
                        "CREATE UNIQUE INDEX IF NOT EXISTS ",
                        1,
                    )
                    .replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1),
            )
            .unwrap();
    }
}

#[test]
fn bash_queue_resolution_uses_the_current_native_owner() {
    let (_root, request) = tests::fixture();
    let (store, _) = policy_store(&request);
    let claim = once(&request, &store, "2999-01-01T00:00:00+00:00");
    let operation = "queue-scope-resolution-0001";
    seed_once_review(&request, &store, &claim, operation);
    let id = claim.decisions[0]["request_id"].as_str().unwrap();
    let connection = Connection::open(&claim.store_path).unwrap();
    complete_queue_schema(&connection);
    connection
        .execute(
        "UPDATE approval_requests SET status='pending', created_at='2026-10-19T12:00:00+00:00',
         resolution_action=NULL, resolved_at=NULL, resolution_scope=NULL, artifact_type='native_bash_request',
         artifact_name='bash', raw_command_text=?1, policy_action='review',
         config_path=?2, source_scope='project', recommended_scope='artifact' WHERE request_id=?3",
            params![request.command, request.workspace, id],
        )
        .unwrap();
    let wire = guard_contracts::GuardStoreRequestV1 {
        schema: guard_contracts::GUARD_STORE_REQUEST_SCHEMA.into(),
        request_id: "queue-scope-test".into(),
        store_path: claim.store_path.clone(),
        guard_home: request.guard_home.clone(),
        method: "resolve_request_with_queue_result".into(),
        source: "guard".into(),
        busy_timeout_ms: 5000,
        args: json!({"request_id":id, "resolution_action":"allow", "resolution_scope":"artifact",
            "reason":"Native fixture consent", "resolved_at":"2026-10-19T12:00:00+00:00",
            "cwd":request.cwd})
        .as_object()
        .unwrap()
        .clone(),
    };
    let reply: Value = serde_json::from_slice(
        &crate::guard_store_op::evaluate_guard_store_request_with_owner(&wire, Some(&store))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["resolved"], true, "{reply}");
    assert_eq!(
        reply["payload"]["resolved_request"]["resolution_action"],
        "allow"
    );
    assert_eq!(
        reply["payload"]["resolved_request"]["exact_action_persistence_eligible"], true,
        "{reply}"
    );
}
