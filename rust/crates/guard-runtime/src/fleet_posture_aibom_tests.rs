use serde_json::{json, Value};

use super::dispatch;

const HASH: &str = "sha256:bbbb";

fn item(item_id: &str, kind: &str, name: &str, artifact_type: &str, config_path: &str) -> Value {
    json!({
        "item_id": item_id,
        "item_kind": kind,
        "artifact_type": artifact_type,
        "name": name,
        "content_hash": HASH,
        "config_path": config_path,
    })
}

fn skill(item_id: &str, name: &str) -> Value {
    item(
        item_id,
        "skill",
        name,
        "",
        &format!("{{home}}/.codex/{name}"),
    )
}

fn snapshot(harness: &str, generated_at: &str, items: &[Value]) -> Value {
    json!({"harness": harness, "generated_at": generated_at, "items": [items]})
}

fn remember(
    snapshots: &[Value],
    previous: &[Value],
    home: Option<&str>,
    workspace: Option<&str>,
) -> Value {
    dispatch(&json!({
        "op": "remember",
        "snapshots": snapshots,
        "previous": [previous],
        "home": home,
        "workspace": workspace,
    }))
    .unwrap()
}

/// The stored rows a collection leaves: its new rows, then the kept previous rows.
fn stored(
    snapshots: &[Value],
    previous: &[Value],
    home: Option<&str>,
    workspace: Option<&str>,
) -> Vec<Value> {
    let result = remember(snapshots, previous, home, workspace);
    let mut rows: Vec<Value> = result["rows"].as_array().unwrap().clone();
    for index in result["kept"].as_array().unwrap() {
        rows.push(previous[usize::try_from(index.as_u64().unwrap()).unwrap()].clone());
    }
    rows
}

fn names(rows: &[Value]) -> Vec<String> {
    let mut names: Vec<String> = rows
        .iter()
        .map(|row| row["artifact_name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

fn union(table: &[Value], stored: &[Value]) -> Vec<u64> {
    dispatch(&json!({"op": "union", "table": [table], "stored": [stored]})).unwrap()["kept"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect()
}

#[test]
fn unreported_kinds_and_harnesses_stay_out() {
    let rows = stored(
        &[
            snapshot(
                "codex",
                "2026-10-20T11:00:00Z",
                &[
                    item(
                        "codex:global:chrome-devtools",
                        "mcp_server",
                        "chrome-devtools",
                        "",
                        "{home}/.codex/c",
                    ),
                    item(
                        "codex:project:review",
                        "skill",
                        "review",
                        "skill_file",
                        "{home}/.codex/r",
                    ),
                    item(
                        "codex:global:agents",
                        "prompt_pack",
                        "AGENTS.md",
                        "",
                        "{home}/AGENTS.md",
                    ),
                    // An explicit type fleet posture does not report never falls back to the item kind.
                    item(
                        "codex:global:host",
                        "plugin",
                        "Host",
                        "harness_host",
                        "{home}/h",
                    ),
                ],
            ),
            snapshot(
                "not-a-harness",
                "2026-10-20T11:00:00Z",
                &[skill("x:global:y", "y")],
            ),
        ],
        &[],
        Some("/home/u"),
        None,
    );
    assert_eq!(names(&rows), ["chrome-devtools", "review"]);
    let review = rows
        .iter()
        .find(|row| row["artifact_name"] == "review")
        .unwrap();
    assert_eq!(review["artifact_type"], "skill_file");
    assert_eq!(review["source_scope"], "project");
    assert_eq!(review["config_path"], "/home/u/.codex/r");
    assert_eq!(review["last_seen_at"], "2026-10-20T11:00:00Z");
    assert_eq!(review["collection_workspace"], Value::Null);
    assert_eq!(
        (review["snapshot"].as_u64(), review["item"].as_u64()),
        (Some(0), Some(1))
    );
}

#[test]
fn source_scope_comes_from_the_id_or_where_the_file_lives() {
    let cases = [
        (
            "codex",
            "codex:project:review",
            None,
            "{home}/x/review",
            "project",
        ),
        (
            "omp",
            "omp:omp-global:review",
            None,
            "{home}/.omp/review",
            "global",
        ),
        (
            "hermes",
            "hermes:skill:review",
            Some("/home/u/code/app"),
            "{home}/code/app/.hermes/review",
            "project",
        ),
        (
            "openclaw",
            "openclaw:plugin:review",
            Some("/home/u/code/app"),
            "{home}/.openclaw/review",
            "global",
        ),
        (
            "openclaw",
            "openclaw:plugin:review",
            None,
            "{home}/.openclaw/review",
            "global",
        ),
    ];
    for (harness, item_id, workspace, path, expected) in cases {
        let rows = stored(
            &[snapshot(
                harness,
                "2026-10-20T00:00:00Z",
                &[item(item_id, "skill", "review", "", path)],
            )],
            &[],
            Some("/home/u"),
            workspace,
        );
        assert_eq!(rows[0]["source_scope"], expected, "{item_id} {path}");
    }
    // A path that cannot be restored to an absolute one has no scope.
    let rows = stored(
        &[snapshot(
            "codex",
            "2026-10-20T00:00:00Z",
            &[item("codex:review", "skill", "review", "", "{home}/r")],
        )],
        &[],
        None,
        None,
    );
    assert_eq!(rows[0]["config_path"], "{home}/r");
    assert_eq!(rows[0]["source_scope"], Value::Null);
}

#[test]
fn a_later_collection_keeps_first_seen_and_drops_items_it_no_longer_finds() {
    let first = stored(
        &[snapshot(
            "codex",
            "2026-10-19T00:00:00Z",
            &[
                skill("codex:global:one", "one"),
                skill("codex:global:two", "two"),
            ],
        )],
        &[],
        None,
        None,
    );
    let second = stored(
        &[snapshot(
            "codex",
            "2026-10-20T00:00:00+00:00",
            &[skill("codex:global:one", "one")],
        )],
        &first,
        None,
        None,
    );
    assert_eq!(names(&second), ["one"]);
    assert_eq!(second[0]["first_seen_at"], "2026-10-19T00:00:00Z");
    assert_eq!(second[0]["last_seen_at"], "2026-10-20T00:00:00Z");
}

#[test]
fn a_workspace_scan_keeps_the_project_items_of_other_workspaces() {
    let alpha = Some("/home/u/code/alpha");
    let beta = Some("/home/u/code/beta");
    let user_skill = skill("codex:global:shared", "shared");
    let alpha_skill = skill("codex:project:alpha-skill", "alpha-skill");
    let beta_skill = skill("codex:project:beta-skill", "beta-skill");
    let scan = |previous: &[Value], workspace: Option<&str>, at: &str, items: &[Value]| {
        stored(
            &[snapshot("codex", at, items)],
            previous,
            Some("/home/u"),
            workspace,
        )
    };
    let rows = scan(
        &[],
        alpha,
        "2026-10-18T00:00:00Z",
        &[user_skill.clone(), alpha_skill],
    );
    assert_eq!(names(&rows), ["alpha-skill", "shared"]);
    // A scan of another workspace, or of none, does not mean alpha's items were removed.
    let rows = scan(
        &rows,
        beta,
        "2026-10-19T00:00:00Z",
        &[user_skill.clone(), beta_skill],
    );
    assert_eq!(names(&rows), ["alpha-skill", "beta-skill", "shared"]);
    let rows = scan(&rows, None, "2026-10-20T00:00:00Z", &[user_skill.clone()]);
    assert_eq!(names(&rows), ["alpha-skill", "beta-skill", "shared"]);
    // Rescanning alpha is what removes an alpha item.
    let rows = scan(&rows, alpha, "2026-10-21T00:00:00Z", &[user_skill]);
    assert_eq!(names(&rows), ["beta-skill", "shared"]);
}

#[test]
fn duplicate_items_store_once_and_unparseable_snapshots_are_skipped() {
    let rows = stored(
        &[
            snapshot(
                "codex",
                "2026-10-20T00:00:00Z",
                &[
                    item("codex:global:one", "skill", " one ", "", "{home}/one"),
                    item("codex:global:one", "skill", "one", "", "{home}/one"),
                ],
            ),
            snapshot("codex", "not a time", &[skill("codex:global:two", "two")]),
        ],
        &[],
        Some("/home/u"),
        None,
    );
    assert_eq!(names(&rows), ["one"]);
}

#[test]
fn table_rows_win_over_the_same_stored_item_unless_removed() {
    let stored_rows = [
        json!({"artifact_type": "mcp_server", "harness": "codex", "artifact_name": "chrome-devtools", "config_path": "/nonexistent-hg/.codex/c"}),
        json!({"artifact_type": "mcp_server", "harness": "codex", "artifact_name": "other", "config_path": "/nonexistent-hg/.codex/o"}),
    ];
    let table = json!({"artifact_type": "mcp_server", "harness": "codex", "artifact_name": " chrome-devtools", "config_path": "/nonexistent-hg/.codex/c"});
    assert_eq!(union(&[table.clone()], &stored_rows), [1]);
    for (key, value) in [
        ("present", json!(0)),
        ("present", json!(false)),
        ("present", json!("0")),
        ("present", json!(0.0)),
        ("removed_at", json!("2026-10-05T00:00:00Z")),
    ] {
        let mut removed = table.clone();
        removed[key] = value;
        assert_eq!(union(&[removed], &stored_rows), [0, 1], "{key}");
    }
    let mut present = table;
    present["present"] = json!(1);
    assert_eq!(union(&[present], &stored_rows), [1]);
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        json!({"op": "other"}),
        json!({"op": "union", "table": {}, "stored": []}),
        json!({"op": "remember", "snapshots": [], "previous": [], "home": 1}),
        json!({"op": "remember", "snapshots": [{"generated_at": "2026-10-20T00:00:00Z", "items": []}], "previous": []}),
    ] {
        assert!(dispatch(&args).is_err(), "{args}");
    }
}
