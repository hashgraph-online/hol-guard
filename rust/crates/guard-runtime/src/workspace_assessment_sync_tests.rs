use serde_json::{json, Value};

use super::*;

// Oracles below are what the Python build answered for the same rows.
const KEY: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
const NOW: &str = "2026-10-24T12:00:00Z";

fn worktree() -> Value {
    json!({
        "codebase_key": "c".repeat(64),
        "worktree_key": "w".repeat(64),
        "dirty_generation": 3,
        "last_completed_generation": 2,
        "stale": true,
        "paused": false,
    })
}

fn run() -> Value {
    json!({
        "run_id": "r1",
        "kind": "full",
        "trigger_kind": "workspace_open",
        "state": "partial",
        "snapshot_digest": "s".repeat(64),
        "coverage": {
            "status": "partial",
            "reasons": ["lockfile_missing", 7],
            "detectors": {"supply_chain": "complete", "secrets": "partial"},
        },
        "started_at_ms": 1_729_771_200_123_u64,
        "finished_at_ms": 1_729_771_201_000_u64,
        "findings": [
            {
                "finding_id": "f1",
                "source_kind": "agent_inventory",
                "detector": "d",
                "severity": "high",
                "package_name": "pkg\u{e9}\u{1F600}\u{7f}",
                "path": "/home/u/.codex/config.toml",
                "rule_ids": ["r"],
                "advisory_ids": [],
            },
            {"finding_id": "f2", "source_kind": "supply_chain", "carried_from_run_id": "r0"},
            {"source_kind": "supply_chain", "decision": 5},
        ],
    })
}

fn build_with(worktrees: Value, latest: Value, assessed: Value, extra: Value) -> Value {
    let mut args = json!({
        "worktrees": worktrees,
        "latest_runs": latest,
        "assessed_runs": assessed,
        "hash_key": KEY,
        "now": NOW,
        "max_bytes": 131_072,
        "delivery": null,
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    dispatch("workspace_assessment_build", &args).unwrap()
}

fn built() -> Value {
    build_with(
        json!([worktree()]),
        json!([{"state": "completed"}]),
        json!([run()]),
        json!({}),
    )
}

fn finding_row(id: &str, null_fields: &[&str]) -> Value {
    let mut row = json!({"advisoryIds": [], "findingKey": id, "ruleIds": []});
    for field in null_fields {
        row[*field] = Value::Null;
    }
    row
}

#[test]
fn entry_digest_and_size_match_the_python_build() {
    let answer = built();
    let nulls = [
        "decision",
        "ecosystem",
        "fixVersion",
        "lifecycleState",
        "packageVersion",
        "validationState",
    ];
    let mut first = finding_row(
        "sha256:5aa7e695bb6f21fa82fac0923b9ac33227c4b285c994bc6668dcdbf37cb391f3",
        &nulls,
    );
    first["detector"] = json!("d");
    first["severity"] = json!("high");
    first["sourceKind"] = json!("agent_inventory");
    first["packageName"] = json!("pkg\u{e9}\u{1F600}\u{7f}");
    first["ruleIds"] = json!(["r"]);
    first["locationHash"] =
        json!("sha256:23ff79d8c5818249bcaa6a966a7f7f20bd83d0570e89e8cbd51c275c33b870c3");
    let mut second = finding_row(
        "sha256:0be87fb98734001956f3fa390fd5c72e104bcab9ce596e89f5335a642cf95533",
        &[&nulls[..], &["detector", "severity", "packageName"][..]].concat(),
    );
    second["sourceKind"] = json!("supply_chain");
    let expected = json!({
        "assessment": {
            "coverage": {
                "detectors": {"secrets": "partial", "supply_chain": "complete"},
                "reasons": ["lockfile_missing", "7"],
                "status": "partial",
            },
            "finishedAt": "2024-10-24T12:00:01Z",
            "kind": "full",
            "runKey": "sha256:30e431e1522e2ec3abbee55bc8a7bb19a812f21c18ee71ff2f3888ab0383dcd1",
            "snapshotDigest": "76d9767edaa04971e0add291537a06acc05a30e1c7cafd602300a9a2c0c22e76",
            "startedAt": "2024-10-24T12:00:00.123000Z",
            "state": "partial",
            "trigger": "workspace_open",
        },
        "codebaseKey": "sha256:36d12c5043102c0cd2d02442b7b8d1bfa6fc5ce78627f9732629e13a78a2c9df",
        "dirtyGeneration": 3,
        "findings": [first, second],
        "findingsTruncated": false,
        "lastCompletedGeneration": 2,
        "status": "stale",
        "worktreeKey": "sha256:56242cf261fdcabe399b481a8a5ea1ca17385aa2b61095540d1aef9313cc0741",
    });
    assert_eq!(answer["payload"]["worktrees"], json!([expected]));
    assert_eq!(
        answer["payload"]["schemaVersion"],
        "guard.workspace-assessment-sync.v1"
    );
    assert_eq!(answer["payload"]["generatedAt"], NOW);
    assert_eq!(
        answer["digest"],
        "9e0517450f59f532b4194ae428fefcd640282c227d2cfd0b81f90ceb0b666f75"
    );
    assert_eq!(dumps_len(&answer["payload"]), 1683);
}

#[test]
fn a_worktree_without_an_assessed_run_is_pending() {
    let answer = build_with(json!([worktree()]), json!([null]), json!([null]), json!({}));
    let entry = &answer["payload"]["worktrees"][0];
    assert_eq!(entry["status"], "pending");
    assert_eq!(entry["assessment"], Value::Null);
    assert_eq!(entry["findings"], json!([]));
    assert_eq!(
        answer["digest"],
        "653602deedaaf102f74a5ee3ecf50f66b6252cc06ab1f9585dbfc58a8661c73d"
    );
    assert_eq!(dumps_len(&answer["payload"]), 428);
}

#[test]
fn status_follows_pause_then_the_newest_run_then_the_assessment() {
    let assessed = json!({"run_id": "r", "state": "completed"});
    let cases = [
        (
            json!({"paused": true}),
            json!({"state": "running"}),
            assessed.clone(),
            "paused",
        ),
        (
            json!({}),
            json!({"state": "running"}),
            assessed.clone(),
            "running",
        ),
        (
            json!({}),
            json!({"state": "queued"}),
            assessed.clone(),
            "queued",
        ),
        (
            json!({}),
            json!({"state": "failed"}),
            assessed.clone(),
            "failed",
        ),
        (
            json!({"stale": true}),
            json!({"state": "completed"}),
            Value::Null,
            "pending",
        ),
        (json!({"stale": 1}), Value::Null, assessed.clone(), "stale"),
        (
            json!({}),
            Value::Null,
            json!({"state": "partial"}),
            "partial",
        ),
        (json!({"stale": 0}), json!({}), assessed, "fresh"),
    ];
    for (worktree, latest, assessed, expected) in cases {
        assert_eq!(status(&worktree, &latest, &assessed), expected);
    }
}

#[test]
fn findings_are_capped_and_a_capped_scan_is_flagged() {
    let mut capped = run();
    capped["findings"] = (0..105)
        .map(|index| json!({"finding_id": format!("{index:032x}"), "source_kind": "supply_chain"}))
        .collect();
    let answer = build_with(
        json!([worktree()]),
        json!([null]),
        json!([capped]),
        json!({}),
    );
    let entry = &answer["payload"]["worktrees"][0];
    assert_eq!(entry["findings"].as_array().unwrap().len(), 100);
    assert_eq!(entry["findingsTruncated"], true);

    let mut scan = run();
    scan["coverage"]["reasons"] = json!(["finding_cap"]);
    let answer = build_with(json!([worktree()]), json!([null]), json!([scan]), json!({}));
    assert_eq!(answer["payload"]["worktrees"][0]["findingsTruncated"], true);
}

fn fit_payload() -> Value {
    let entry = |count: usize, tree: &str| {
        let mut row = run();
        row["findings"] = (0..count)
            .map(|index| {
                json!({
                    "finding_id": format!("{tree}-{index}"),
                    "source_kind": "supply_chain",
                    "package_name": "p".repeat(40),
                })
            })
            .collect();
        row["coverage"] = json!({
            "status": "complete",
            "reasons": (0..8).map(|index| format!("reason-{index:02}")).collect::<Vec<_>>(),
            "detectors": {"det0": "complete", "det1": "complete", "det2": "complete", "det3": "complete"},
        });
        let mut tree_row = worktree();
        tree_row["worktree_key"] = json!(tree);
        (tree_row, row)
    };
    let (first_tree, first) = entry(10, "a");
    let (second_tree, second) = entry(20, "b");
    build_with(
        json!([first_tree, second_tree]),
        json!([null, null]),
        json!([first, second]),
        json!({}),
    )["payload"]
        .clone()
}

fn fitted(payload: &Value, limit: i64) -> Value {
    dispatch(
        "workspace_assessment_fit",
        &json!({"payload": payload, "max_bytes": limit}),
    )
    .unwrap()
}

fn shape(answer: &Value) -> Vec<(usize, bool, usize, usize)> {
    answer["payload"]["worktrees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let coverage = &entry["assessment"]["coverage"];
            (
                entry["findings"].as_array().unwrap().len(),
                entry["findingsTruncated"].as_bool().unwrap(),
                coverage["reasons"].as_array().unwrap().len(),
                coverage["detectors"].as_object().unwrap().len(),
            )
        })
        .collect()
}

#[test]
fn request_fit_trims_like_the_python_build() {
    let payload = fit_payload();
    assert_eq!(dumps_len(&payload), 13263);
    let cases: [(i64, &[(usize, bool, usize, usize)], &str, usize); 5] = [
        (
            13263,
            &[(10, false, 8, 4), (20, false, 8, 4)],
            "63c03009aae8fcb92f35155edc03cc3c7d403f294efb14d216fc1406fae21e12",
            13263,
        ),
        (
            13262,
            &[(10, false, 8, 4), (15, true, 8, 4)],
            "128320eb0c5733638387feedcd9b3d6b10931307dae54913cbfdb23ceef503af",
            11362,
        ),
        (
            6631,
            &[(6, true, 8, 4), (6, true, 8, 4)],
            "6a5127102cb809a5a9ea20009ba9b5cc8f403c337ca1ec948f51110b3922433b",
            6421,
        ),
        (
            1400,
            &[(0, true, 0, 0)],
            "25d55004524892e8a9a7b5e8692f8967d5e47b0efc7e943b4ed97dd9b5373179",
            807,
        ),
        (
            900,
            &[(0, true, 0, 0)],
            "25d55004524892e8a9a7b5e8692f8967d5e47b0efc7e943b4ed97dd9b5373179",
            807,
        ),
    ];
    for (limit, expected, digest, size) in cases {
        let answer = fitted(&payload, limit);
        assert_eq!(shape(&answer), expected, "limit {limit}");
        assert_eq!(answer["digest"], digest, "limit {limit}");
        assert_eq!(dumps_len(&answer["payload"]), size, "limit {limit}");
    }
    for limit in [600, 10, -5] {
        assert_eq!(fitted(&payload, limit), json!({"payload": null}));
    }
    assert_eq!(
        fitted(&json!({"worktrees": "x"}), 1000),
        json!({"payload": null})
    );
}

#[test]
fn the_built_summary_fits_its_own_budget() {
    let tree = |key: &str| {
        let mut row = worktree();
        row["worktree_key"] = json!(key);
        row
    };
    let answer = build_with(
        json!([tree("a"), tree("b")]),
        json!([null, null]),
        fit_payload_runs(),
        json!({"max_bytes": 1200}),
    );
    let entries = answer["payload"]["worktrees"].as_array().unwrap();
    assert!(!entries.is_empty());
    assert!(entries
        .iter()
        .all(|entry| entry["findingsTruncated"] == true));
    assert!(dumps_len(&answer["payload"]) <= 1200);
    let none = build_with(
        json!([tree("a")]),
        json!([null]),
        json!([run()]),
        json!({"max_bytes": 50}),
    );
    assert_eq!(none, json!({"payload": null}));
}

fn fit_payload_runs() -> Value {
    (0..2)
        .map(|index| {
            let mut row = run();
            row["findings"] = json!([]);
            row["coverage"] = json!({
                "status": "complete",
                "reasons": (0..8).map(|reason| format!("{index}-reason-{reason:02}")).collect::<Vec<_>>(),
                "detectors": {"det0": "complete", "det1": "complete"},
            });
            row
        })
        .collect()
}

#[test]
fn an_unchanged_summary_waits_a_day() {
    let digest = built()["digest"].clone();
    let delivered = |sent_at: &str| {
        build_with(
            json!([worktree()]),
            json!([{"state": "completed"}]),
            json!([run()]),
            json!({"delivery": {"digest": digest, "sent_at": sent_at}}),
        )
    };
    assert_eq!(delivered("2026-10-23T12:00:01Z"), json!({"payload": null}));
    assert_eq!(
        delivered("2026-10-23T12:00:01+00:00"),
        json!({"payload": null})
    );
    // A naive time is UTC.
    assert_eq!(delivered("2026-10-23T12:00:01"), json!({"payload": null}));
    assert!(delivered("2026-10-23T12:00:00Z")["payload"].is_object());
    assert!(delivered("not a time")["payload"].is_object());
    let changed = build_with(
        json!([worktree()]),
        json!([{"state": "completed"}]),
        json!([run()]),
        json!({"delivery": {"digest": "other", "sent_at": NOW}}),
    );
    assert!(changed["payload"].is_object());
}

#[test]
fn timestamps_convert_only_from_non_negative_integers() {
    assert_eq!(iso(Some(&json!(0))).unwrap(), "1970-01-01T00:00:00Z");
    assert_eq!(iso(Some(&json!(-1))).unwrap(), Value::Null);
    assert_eq!(iso(Some(&json!(1.0))).unwrap(), Value::Null);
    assert_eq!(iso(Some(&json!(true))).unwrap(), Value::Null);
    assert_eq!(iso(None).unwrap(), Value::Null);
    assert!(iso(Some(&json!(u64::MAX))).is_err());
    assert!(iso(Some(&json!(300_000_000_000_000_u64))).is_err());
}

#[test]
fn json_text_escapes_like_cpython() {
    let mut out = String::new();
    write_json(
        &json!({"b": [1, 2.5, 1e16, null], "a": "\"\\\n\u{1}\u{7f}\u{e9}\u{1F600}"}),
        (",", ":"),
        &mut out,
    );
    assert_eq!(
        out,
        r#"{"a":"\"\\\n\u0001\u007fé😀","b":[1,2.5,1e+16,null]}"#
    );
    assert_eq!(dumps_len(&json!({"a": [1, 2], "b": {}})), 22);
}

#[test]
fn malformed_requests_are_refused() {
    let base = json!({
        "worktrees": [worktree()],
        "latest_runs": [null],
        "assessed_runs": [null],
        "hash_key": KEY,
        "now": NOW,
        "max_bytes": 1000,
    });
    let broken = [
        ("hash_key", json!("short")),
        ("latest_runs", json!([])),
        ("assessed_runs", json!([null, null])),
        ("now", json!(1)),
        ("max_bytes", json!("big")),
        ("worktrees", json!([{"worktree_key": "w"}])),
    ];
    for (key, value) in broken {
        let mut args = base.clone();
        args[key] = value;
        assert!(
            dispatch("workspace_assessment_build", &args).is_err(),
            "{key}"
        );
    }
    let mut no_run_id = base.clone();
    no_run_id["assessed_runs"] = json!([{"state": "completed"}]);
    assert!(dispatch("workspace_assessment_build", &no_run_id).is_err());
    assert!(dispatch("workspace_assessment_other", &base).is_err());
}
