use super::*;
use rusqlite::params;

fn database() -> (tempfile::TempDir, Connection) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("guard.db");
    crate::policy_decision_lookup_op::tests::seed_store(&path);
    let connection = Connection::open(path).unwrap();
    (root, connection)
}

fn block(connection: &Connection, artifact: Option<&str>) {
    connection.execute(
        "INSERT INTO policy_decisions(harness,scope,artifact_id,action,source,created_at,updated_at)
         VALUES('omp','global',?1,'block','approval-gate','2026-01-01','2026-01-01')",
        [artifact],
    ).unwrap();
}

#[test]
fn quiet_admission_reuses_selector_without_creating_or_consuming_consent() {
    let (_root, connection) = database();
    block(&connection, Some("unrelated-artifact"));
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    require_no_saved_decision(&connection, "current-token", "omp", "/project").unwrap();
    connection.execute_batch("COMMIT").unwrap();
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM policy_decisions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn final_admission_sees_block_inserted_after_an_empty_preview() {
    let (_root, connection) = database();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    require_no_saved_decision(&connection, "current-token", "omp", "/project").unwrap();
    connection.execute_batch("COMMIT").unwrap();
    block(&connection, Some(guard_contracts::NATIVE_BASH_ARTIFACT_ID));
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(require_no_saved_decision(&connection, "current-token", "omp", "/project").is_err());
    connection.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn global_block_and_unverifiable_saved_allow_cannot_take_quiet_path() {
    let (_root, connection) = database();
    block(&connection, None);
    for action in ["block", "allow"] {
        connection
            .execute("UPDATE policy_decisions SET action=?1", [action])
            .unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(
            require_no_saved_decision(&connection, "current-token", "omp", "/project").is_err()
        );
        connection.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn missing_schema_revision_or_write_transaction_fails_closed() {
    let (_root, connection) = database();
    assert!(require_no_saved_decision(&connection, "current-token", "omp", "/project").is_err());
    connection
        .execute("DELETE FROM guard_approval_authority_revision", [])
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(require_no_saved_decision(&connection, "current-token", "omp", "/project").is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    connection
        .execute(
            "INSERT INTO guard_approval_authority_revision VALUES(1,5)",
            [],
        )
        .unwrap();
    connection
        .execute_batch("DROP TABLE guard_local_once_approvals; BEGIN IMMEDIATE")
        .unwrap();
    assert!(require_no_saved_decision(&connection, "current-token", "omp", "/project").is_err());
    connection.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn reservation_transaction_serializes_a_concurrent_saved_block() {
    let (root, connection) = database();
    let competing = Connection::open(root.path().join("guard.db")).unwrap();
    competing.busy_timeout(std::time::Duration::ZERO).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    require_no_saved_decision(&connection, "current-token", "omp", "/project").unwrap();
    let insert = || {
        competing.execute(
            "INSERT INTO policy_decisions(harness,scope,action,source,created_at,updated_at)
         VALUES(?1,'global','block','approval-gate','2026-01-01','2026-01-01')",
            params!["omp"],
        )
    };
    assert!(matches!(
        insert().unwrap_err().sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy)
    ));
    connection.execute_batch("COMMIT").unwrap();
    insert().unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(require_no_saved_decision(&connection, "current-token", "omp", "/project").is_err());
    connection.execute_batch("ROLLBACK").unwrap();
}
