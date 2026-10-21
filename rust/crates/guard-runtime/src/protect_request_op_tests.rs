use std::path::PathBuf;

use super::*;

struct Workspace(PathBuf);

impl Workspace {
    fn new(name: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-protect-request-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn home(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }

    fn store(&self) -> String {
        self.0.join("guard.db").to_string_lossy().into_owned()
    }

    fn write_cache(&self, rows: &[(&str, &str, &str)]) {
        let connection = rusqlite::Connection::open(self.0.join("guard.db")).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE publisher_cache (publisher_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL)",
            )
            .unwrap();
        for (key, payload, updated_at) in rows {
            connection
                .execute(
                    "INSERT INTO publisher_cache VALUES (?1, ?2, ?3)",
                    rusqlite::params![key, payload, updated_at],
                )
                .unwrap();
        }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(
    workspace: &Workspace,
    store_path: Option<String>,
    command: &[&str],
) -> ProtectRequestRequestV1 {
    ProtectRequestRequestV1 {
        schema: PROTECT_REQUEST_REQUEST_SCHEMA.to_owned(),
        request_id: "protect-1".to_owned(),
        guard_home: workspace.home(),
        store_path,
        command: command.iter().map(|item| (*item).to_owned()).collect(),
        cwd: None,
    }
}

fn run(request: &ProtectRequestRequestV1) -> ProtectRequestResultV1 {
    let bytes = evaluate_protect_request_op(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn parses_without_a_store_and_allows_a_registry_install() {
    let workspace = Workspace::new("no-store");
    let result = run(&request(&workspace, None, &["npm", "install", "lodash@4"]));
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    assert_eq!(result.request_id, "protect-1");
    assert!(result.request_sha256.starts_with("sha256:"));
    let parsed = result.request.unwrap();
    assert_eq!(parsed.install_kind, "package_install");
    assert_eq!(parsed.package_manager.as_deref(), Some("npm"));
    assert_eq!(parsed.targets[0].artifact_id, "install:npm:lodash");
    assert_eq!(parsed.targets[0].version.as_deref(), Some("4"));
    let verdict = result.verdict.unwrap();
    assert_eq!(verdict.action, "allow");
    assert!(verdict.matched_advisories.is_empty());
}

#[test]
fn matches_cached_advisories_and_returns_the_raw_rows_by_severity() {
    let workspace = Workspace::new("cache");
    let low = r#"{"ecosystem": "npm", "package": "lodash", "severity": "low"}"#;
    let critical = r#"{"artifact_id":"install:npm:lodash","severity":"critical","headline":"Lodash is compromised."}"#;
    workspace.write_cache(&[
        ("low", low, "2026-10-02"),
        ("list", "[1, 2]", "2026-10-03"),
        (
            "other",
            r#"{"ecosystem": "npm", "package": "zod"}"#,
            "2026-10-04",
        ),
        ("critical", critical, "2026-10-01"),
    ]);
    let result = run(&request(
        &workspace,
        Some(workspace.store()),
        &["npm", "install", "lodash"],
    ));
    let verdict = result.verdict.unwrap();
    assert_eq!(verdict.action, "block");
    assert_eq!(
        verdict.reason,
        "Lodash is compromised. Guard blocked the install before the artifact landed locally."
    );
    assert_eq!(
        verdict.matched_advisories,
        vec![
            ProtectCachedAdvisoryV1 {
                cache_key: "critical".to_owned(),
                updated_at: "2026-10-01".to_owned(),
                payload_json: critical.to_owned(),
            },
            ProtectCachedAdvisoryV1 {
                cache_key: "low".to_owned(),
                updated_at: "2026-10-02".to_owned(),
                payload_json: low.to_owned(),
            },
        ]
    );
}

#[test]
fn a_missing_store_or_cache_table_has_no_advisories() {
    let workspace = Workspace::new("missing");
    let missing = run(&request(
        &workspace,
        Some(workspace.store()),
        &["pip", "install", "requests"],
    ));
    assert_eq!(missing.verdict.unwrap().action, "allow");
    rusqlite::Connection::open(workspace.store())
        .unwrap()
        .execute_batch("CREATE TABLE unrelated (id INTEGER)")
        .unwrap();
    let empty = run(&request(
        &workspace,
        Some(workspace.store()),
        &["pip", "install", "requests"],
    ));
    assert_eq!(empty.verdict.unwrap().action, "allow");
}

#[test]
fn a_store_outside_the_guard_home_is_refused() {
    let workspace = Workspace::new("outside");
    let other = Workspace::new("outside-other");
    let result = run(&request(
        &workspace,
        Some(other.store()),
        &["npm", "install", "lodash"],
    ));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_protect_request_store_path_invalid");
    assert!(result.request.is_none() && result.verdict.is_none());
}

#[test]
fn a_non_finite_unrelated_cache_row_still_allows_the_install() {
    let workspace = Workspace::new("nan-unrelated");
    workspace.write_cache(&[
        (
            "leftpad",
            r#"{"ecosystem":"npm","package":"leftpad","score":NaN}"#,
            "2026-10-01",
        ),
        (
            "infinite",
            r#"{"ecosystem":"npm","package":"leftpad","score":Infinity,"alt":-Infinity,"plus":+Infinity}"#,
            "2026-10-02",
        ),
        (
            "huge",
            r#"{"ecosystem":"npm","package":"leftpad","score":1e400}"#,
            "2026-10-03",
        ),
    ]);
    let result = run(&request(
        &workspace,
        Some(workspace.store()),
        &["npm", "install", "lodash"],
    ));
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let verdict = result.verdict.unwrap();
    assert_eq!(verdict.action, "allow");
    assert!(verdict.matched_advisories.is_empty());
}

#[test]
fn a_non_finite_critical_advisory_still_blocks() {
    let workspace = Workspace::new("nan-critical");
    let critical = r#"{"artifact_id":"install:npm:lodash","severity":"critical","headline":"Lodash score was NaN.","score":NaN}"#;
    workspace.write_cache(&[("critical", critical, "2026-10-01")]);
    let result = run(&request(
        &workspace,
        Some(workspace.store()),
        &["npm", "install", "lodash"],
    ));
    assert_eq!(result.code, "ok");
    let verdict = result.verdict.unwrap();
    assert_eq!(verdict.action, "block");
    assert_eq!(
        verdict.reason,
        "Lodash score was NaN. Guard blocked the install before the artifact landed locally."
    );
    assert_eq!(verdict.matched_advisories.len(), 1);
    assert_eq!(verdict.matched_advisories[0].payload_json, critical);
}

#[test]
fn matches_over_the_response_budget_fail_closed() {
    let workspace = Workspace::new("oversize-matches");
    let headline = "x".repeat(400 * 1024);
    let payloads: Vec<String> = (0..3)
        .map(|_| {
            format!(r#"{{"artifact_id":"install:npm:lodash","severity":"critical","headline":"{headline}"}}"#)
        })
        .collect();
    workspace.write_cache(&[
        ("a", &payloads[0], "2026-10-01"),
        ("b", &payloads[1], "2026-10-02"),
        ("c", &payloads[2], "2026-10-03"),
    ]);
    let result = run(&request(
        &workspace,
        Some(workspace.store()),
        &["npm", "install", "lodash"],
    ));
    assert_eq!(result.code, "native_protect_request_matches_too_large");
    assert!(result.verdict.is_none());
}

#[test]
fn an_unparseable_cache_row_fails_closed() {
    let workspace = Workspace::new("corrupt");
    workspace.write_cache(&[("bad", "{not json", "2026-10-01")]);
    let result = run(&request(
        &workspace,
        Some(workspace.store()),
        &["npm", "install", "lodash"],
    ));
    assert_eq!(result.code, "native_protect_request_cache_invalid");
}

#[test]
fn invalid_urls_carry_the_parser_message() {
    let workspace = Workspace::new("url");
    let result = run(&request(
        &workspace,
        None,
        &["npm", "install", "https://[::1/pkg"],
    ));
    assert_eq!(result.code, "native_protect_request_invalid_url");
    assert_eq!(result.detail.as_deref(), Some("Invalid IPv6 URL"));
}

#[test]
fn schema_and_empty_commands_are_typed_errors() {
    let workspace = Workspace::new("schema");
    let mut wrong = request(&workspace, None, &["npm"]);
    wrong.schema = "guard-protect-request-request.v0".to_owned();
    assert_eq!(run(&wrong).code, "native_protect_request_schema_mismatch");
    assert_eq!(
        run(&request(&workspace, None, &[])).code,
        "native_protect_request_command_empty"
    );
}

#[test]
fn oversized_requests_have_no_digest() {
    let workspace = Workspace::new("large");
    let big = "a".repeat(PROTECT_REQUEST_MAX_BYTES);
    let error = evaluate_protect_request_op(&request(&workspace, None, &["npm", &big]));
    assert_eq!(error.unwrap_err(), "native_protect_request_too_large");
}

#[test]
fn a_response_over_the_resident_limit_is_a_typed_match_error() {
    let workspace = Workspace::new("response-limit");
    let name = format!("w{}", "p".repeat(200_000));
    let headline = "h".repeat(700_000);
    let payload = format!(
        r#"{{"artifact_id":"install:npm:{name}","severity":"critical","headline":"{headline}"}}"#
    );
    workspace.write_cache(&[("wide", &payload, "2026-10-01")]);
    let bytes = evaluate_protect_request_op(&request(
        &workspace,
        Some(workspace.store()),
        &["npm", "install", &name],
    ))
    .expect("oversized success body becomes a typed error");
    assert!(bytes.len() <= crate::MAX_NATIVE_RESPONSE_BYTES);
    let result: ProtectRequestResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.code, "native_protect_request_matches_too_large");
    assert_eq!(result.status, "error");
    assert!(result.verdict.is_none());
    assert!(result.request.is_none());
}
