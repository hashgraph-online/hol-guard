use crate::cloud_pack_sql::{classify, SqlKind};

fn kind(sql: &str) -> SqlKind {
    classify(sql).kind
}

fn unscoped(sql: &str) -> bool {
    classify(sql).unscoped
}

#[test]
fn queries_are_reads() {
    for sql in [
        "SELECT * FROM users WHERE id = 1",
        "select count(*) from orders",
        "WITH recent AS (SELECT * FROM orders WHERE created_at > now() - interval '1 day') SELECT * FROM recent",
        "SHOW TABLES",
        "EXPLAIN SELECT * FROM t",
        "DESCRIBE users",
        "VALUES (1), (2)",
        "TABLE users",
        "-- the latest orders\nSELECT id FROM orders /* newest first */ ORDER BY id DESC LIMIT 5;",
        "SELECT 'DROP TABLE users; DELETE FROM x' AS text",
        "SELECT \"delete\" FROM \"drop\"",
        "SELECT $$DROP TABLE t$$",
        "SELECT $body$ DELETE FROM t $body$",
        "SELECT * FROM t WHERE id = $1",
        "BEGIN; SELECT 1; COMMIT;",
        "START TRANSACTION READ ONLY",
        "SET search_path TO app",
        "SELECT 'it''s'",
    ] {
        assert_eq!(kind(sql), SqlKind::Read, "{sql}");
    }
}

#[test]
fn scoped_changes_are_writes() {
    for sql in [
        "INSERT INTO users (name) VALUES ('a')",
        "UPDATE users SET name = 'a' WHERE id = 1",
        "DELETE FROM sessions WHERE expires_at < now()",
        "delete from t where id in (select id from u)",
        "CREATE TABLE notes (id int)",
        "CREATE INDEX notes_id ON notes (id)",
        "ALTER TABLE notes ADD COLUMN body text",
        "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET v = 2",
        "INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE v = 2",
        "SELECT * FROM t FOR UPDATE",
        "SELECT * INTO backup FROM t",
        "SELECT nextval('ids')",
        "WITH gone AS (DELETE FROM t WHERE id = 1 RETURNING *) SELECT * FROM gone",
        "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET v = s.v",
        "DELETE FROM t WHERE 1 = 2",
    ] {
        assert_eq!(kind(sql), SqlKind::Write, "{sql}");
        assert!(!unscoped(sql), "{sql}");
    }
}

#[test]
fn unscoped_changes_and_drops_are_destructive() {
    for sql in [
        "DELETE FROM users",
        "delete from users;",
        "UPDATE users SET admin = true",
        "DELETE FROM users WHERE TRUE",
        "DELETE FROM users WHERE 1=1",
        "DELETE FROM users WHERE id = id",
        "UPDATE users SET a = 1 WHERE 1 = 1 RETURNING *",
        "DROP TABLE users",
        "drop database prod",
        "TRUNCATE orders",
        "WITH x AS (SELECT 1) DELETE FROM t",
        "WITH gone AS (DELETE FROM t RETURNING *) SELECT * FROM gone",
        "UPDATE t SET a = (SELECT max(a) FROM u WHERE u.id = 1)",
        "INSERT OVERWRITE TABLE t SELECT * FROM s",
    ] {
        assert_eq!(kind(sql), SqlKind::Destructive, "{sql}");
        assert!(unscoped(sql), "{sql}");
    }
    for sql in [
        "ALTER TABLE users DROP COLUMN email",
        "ALTER TABLE users RENAME TO old_users",
        "CREATE OR REPLACE TABLE t AS SELECT 1",
        "SELECT pg_terminate_backend(42)",
        "SELECT dblink_exec('host=x', 'drop table t')",
        "SELECT SYSTEM$CANCEL_ALL_QUERIES(1)",
        "SELECT * FROM t INTO OUTFILE '/tmp/x'",
        "MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED BY SOURCE THEN DELETE",
    ] {
        assert_eq!(kind(sql), SqlKind::Destructive, "{sql}");
    }
}

#[test]
fn every_statement_counts() {
    assert_eq!(kind("SELECT 1; DROP TABLE users"), SqlKind::Destructive);
    assert_eq!(kind("SELECT 1;\nDELETE FROM users"), SqlKind::Destructive);
    assert_eq!(
        kind("BEGIN; DELETE FROM users; COMMIT"),
        SqlKind::Destructive
    );
    assert_eq!(kind("BEGIN DELETE FROM users; END"), SqlKind::Destructive);
    assert_eq!(kind("SELECT 1; GRANT ALL ON t TO bob"), SqlKind::Admin);
    assert_eq!(
        kind("EXPLAIN ANALYZE DELETE FROM users"),
        SqlKind::Destructive
    );
    assert_eq!(
        kind("EXPLAIN (ANALYZE, BUFFERS) DELETE FROM users"),
        SqlKind::Destructive
    );
    assert_eq!(kind("EXPLAIN ANALYZE SELECT * FROM users"), SqlKind::Write);
}

#[test]
fn privilege_changes_are_admin() {
    for sql in [
        "GRANT SELECT ON t TO analyst",
        "REVOKE ALL ON t FROM analyst",
        "CREATE USER bob WITH PASSWORD 'x'",
        "CREATE OR REPLACE ROLE reader",
        "ALTER ROLE bob SUPERUSER",
        "DROP USER bob",
        "SET ROLE admin",
        "SET GLOBAL read_only = 0",
    ] {
        assert_eq!(kind(sql), SqlKind::Admin, "{sql}");
    }
    assert_eq!(kind("CREATE TABLE login (id int)"), SqlKind::Write);
}

#[test]
fn text_dialects_read_differently_is_destructive() {
    for sql in [
        "",
        "   ",
        ";;",
        "-- only a comment",
        "SELECT 'unclosed",
        "SELECT \"unclosed",
        "SELECT /* unclosed",
        "SELECT /* outer /* inner */ DROP TABLE t */ 1",
        "SELECT 1 /*!50000 DROP TABLE t */",
        "SELECT 1 # comment\n; DROP TABLE t",
        "SELECT 1--1; DROP TABLE t",
        "SELECT 'it\\'s; DROP TABLE t; '",
        "SELECT E'\\x41'",
        "SELECT $tag$ never closed",
        "CALL cleanup()",
        "DO $$ BEGIN DELETE FROM t; END $$",
        "EXECUTE purge",
        "COPY t TO PROGRAM 'rm -rf /'",
        "VACCUM t",
        "PRAGMA writable_schema = 1",
    ] {
        assert_eq!(kind(sql), SqlKind::Destructive, "{sql:?}");
    }
}

#[test]
fn statement_count_is_bounded() {
    let many = "SELECT 1;".repeat(65);
    assert_eq!(kind(&many), SqlKind::Destructive);
    let enough = "SELECT 1;".repeat(64);
    assert_eq!(kind(&enough), SqlKind::Read);
}

#[test]
fn non_ascii_text_is_read() {
    assert_eq!(kind("SELECT naïve, '日本' FROM café"), SqlKind::Read);
    assert_eq!(kind("DELETE FROM café"), SqlKind::Destructive);
}

#[test]
fn dollar_inside_a_word_never_opens_a_quote() {
    let hidden = "SELECT 1 AS x$a$; DROP TABLE users; SELECT 1 AS y$a$";
    assert_ne!(kind(hidden), SqlKind::Read, "{hidden}");
    assert_eq!(kind("SELECT 1 AS x$a$"), SqlKind::Read);
    assert_eq!(kind("SELECT $tag$ DROP TABLE users $tag$"), SqlKind::Read);
}

#[test]
fn quoted_function_names_are_still_checked() {
    for sql in [
        "SELECT \"pg_terminate_backend\"(42)",
        "SELECT \"PG_TERMINATE_BACKEND\"(42)",
        "SELECT \"dblink_exec\"('host=x', 'drop table t')",
    ] {
        assert_eq!(kind(sql), SqlKind::Destructive, "{sql}");
    }
    assert_eq!(
        kind("SELECT \"pg_terminate_backend\" FROM t"),
        SqlKind::Read
    );
}

#[test]
fn bigquery_expiry_options_are_destructive() {
    for sql in [
        "ALTER TABLE web_events.sessions_2026 SET OPTIONS (expiration_timestamp = CURRENT_TIMESTAMP())",
        "ALTER TABLE t SET OPTIONS (partition_expiration_days = 1)",
        "ALTER SCHEMA s SET OPTIONS (default_table_expiration_days = 1)",
        "ALTER SCHEMA s SET OPTIONS (default_partition_expiration_days = 1)",
    ] {
        assert_eq!(kind(sql), SqlKind::Destructive, "{sql}");
    }
    assert_eq!(
        kind("ALTER TABLE t SET OPTIONS (description = 'x')"),
        SqlKind::Write
    );
}
