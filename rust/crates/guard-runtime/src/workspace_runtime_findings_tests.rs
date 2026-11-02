use serde_json::{json, Value};

use super::*;

fn node() -> Value {
    json!({
        "location_id": "path:node",
        "path": "/home/dev/.nvm/versions/node/v20.11.1/bin/node",
        "location_state": "present",
        "artifact_id": "rt-node",
        "family": "node",
        "version": "20.11.1",
        "executable_sha256": "a".repeat(64),
    })
}

fn upgraded() -> Value {
    let mut row = node();
    row["artifact_id"] = json!("rt-node-new");
    row["version"] = json!("20.11.2");
    row["executable_sha256"] = json!("b".repeat(64));
    row
}

fn posture(extra: Value) -> Value {
    let mut posture = json!({
        "status": "ok",
        "coverage": {"advisories_available": true},
        "runtimes": [node()],
        "advisories": [],
        "unresolved_launches": [],
        "skipped_harnesses": [],
    });
    for (key, value) in extra.as_object().unwrap() {
        posture[key] = value.clone();
    }
    posture
}

fn advisory(verdict: Value, extra: Value) -> Value {
    let mut advisory = json!({
        "advisory_id": "GHSA-node-0001",
        "verdict": verdict,
        "affected_artifact_ids": ["rt-node"],
        "severity": "HIGH",
        "known_exploited": true,
        "title": "Path traversal in node",
    });
    for (key, value) in extra.as_object().unwrap() {
        advisory[key] = value.clone();
    }
    advisory
}

fn old_process(state: &str) -> Value {
    json!({
        "instance_id": "i:old",
        "location_id": "path:node",
        "state": state,
        "artifact_id": "rt-node",
        "version": "20.11.1",
    })
}

fn digest(posture: Value) -> Value {
    dispatch(&json!({"op": "identity_digest", "posture": posture})).unwrap()["digest"].clone()
}

fn findings(posture: Value) -> (Vec<Value>, bool) {
    let answer =
        dispatch(&json!({"op": "findings", "worktree_key": "wt-1", "posture": posture})).unwrap();
    (
        answer["findings"].as_array().unwrap().clone(),
        answer["truncated"].as_bool().unwrap(),
    )
}

fn coverage(posture: Value) -> Value {
    let base =
        json!({"status": "complete", "reasons": [], "detectors": {"supply_chain": "complete"}});
    dispatch(&json!({"op": "coverage", "coverage": base, "posture": posture})).unwrap()["coverage"]
        .clone()
}

#[test]
fn identity_digests_match_the_python_encoding() {
    // Pinned against `runtime_identity_digest` before the port.
    assert_eq!(
        digest(posture(json!({}))),
        "678ec64006c49312598b2af43d32421c2e4d15e39118af1910f57cb2bde21d2d"
    );
    let mut odd = node();
    odd["path"] = json!("/opt/n\u{e9}de/node");
    odd["version"] = json!(20);
    let odd = posture(json!({
        "status": "partial",
        "candidate_limit_reached": true,
        "runtimes": [odd],
        "unresolved_launches": [{"harness": "codex", "server": "t", "command": "node"}],
        "skipped_harnesses": ["zed", "cursor", null],
    }));
    assert_eq!(
        digest(odd),
        "c690598a498ab261320b5a6481c5dce8aa48c54bee3d5dc18f1f274f9feb59af"
    );
    let left = posture(json!({
        "runtimes": [upgraded()],
        "instances": {"enumerated": true, "rows": [old_process("running")]},
    }));
    assert_eq!(
        digest(left),
        "72a3e2a5cd4359502b01edc7bafd294c61e6a9ae54fd7be412cb6ed0317e0670"
    );
    assert_eq!(digest(json!({"status": "unavailable"})), Value::Null);
}

#[test]
fn the_digest_follows_identity_and_stale_processes_only() {
    let first = digest(posture(json!({})));
    let advised = posture(json!({"advisories": [advisory(json!("affected"), json!({}))]}));
    assert_eq!(digest(advised), first);
    let current = posture(json!({"runtimes": [upgraded()]}));
    let mut on_disk = old_process("running");
    on_disk["artifact_id"] = json!("rt-node-new");
    let running_current = posture(json!({
        "runtimes": [upgraded()],
        "instances": {"enumerated": true, "rows": [on_disk]},
    }));
    assert_eq!(digest(running_current), digest(current.clone()));
    let exited = posture(json!({
        "runtimes": [upgraded()],
        "instances": {"enumerated": true, "rows": [old_process("exited")]},
    }));
    assert_eq!(digest(exited), digest(current));
}

#[test]
fn a_matched_advisory_is_one_observation_finding() {
    let mut advised = advisory(json!("affected"), json!({"advisory_id": " GHSA-1 "}));
    advised["severity"] = json!("HIGH");
    let (findings, truncated) = findings(posture(json!({"advisories": [advised]})));
    assert!(!truncated);
    let [finding] = findings.as_slice() else {
        panic!("one finding")
    };
    assert_eq!(
        *finding,
        json!({
            "finding_id": "33746b014587948125c473a6da0b7821",
            "source_kind": "agent_inventory",
            "detector": "runtime_identity_v1",
            "severity": "high",
            "decision": "warn",
            "ecosystem": null,
            "package_name": null,
            "runtime_family": "node",
            "runtime_version": "20.11.1",
            "path": "/home/dev/.nvm/versions/node/v20.11.1/bin/node",
            "rule_ids": ["affected"],
            "advisory_ids": ["GHSA-1"],
            "title": "Path traversal in node",
            "known_exploited": true,
            "validation_state": "confirmed",
            "lifecycle_state": "open",
        })
    );
}

#[test]
fn settled_or_malformed_verdicts_are_not_findings() {
    for verdict in [
        json!("fixed_verified"),
        json!("not_affected"),
        json!("unknown"),
        json!(["affected"]),
        Value::Null,
    ] {
        let advised = posture(json!({"advisories": [advisory(verdict.clone(), json!({}))]}));
        assert_eq!(findings(advised), (vec![], false), "{verdict}");
    }
    let unnamed = advisory(json!("affected"), json!({"advisory_id": "  "}));
    assert_eq!(
        findings(posture(json!({"advisories": [unnamed]}))),
        (vec![], false)
    );
}

#[test]
fn findings_sort_like_the_python_key_and_are_capped() {
    let ids = ["a!", "a", "b'", "c\"", "a\\"];
    let advisories: Vec<Value> = ids
        .iter()
        .map(|id| {
            advisory(
                json!("affected"),
                json!({"advisory_id": id, "known_exploited": false, "severity": "low"}),
            )
        })
        .collect();
    let (ordered, _) = findings(posture(json!({"advisories": advisories})));
    let order: Vec<&str> = ordered
        .iter()
        .map(|finding| finding["advisory_ids"][0].as_str().unwrap())
        .collect();
    assert_eq!(order, ["b'", "a!", "a", "a\\", "c\""]);

    let mut many: Vec<Value> = (0..MAX_FINDINGS)
        .map(|index| {
            advisory(
                json!("affected"),
                json!({"advisory_id": format!("GHSA-{index:04}"), "known_exploited": false, "severity": "LOW"}),
            )
        })
        .collect();
    many.push(advisory(
        json!("affected"),
        json!({"advisory_id": "GHSA-late", "severity": "CRITICAL"}),
    ));
    let (capped, truncated) = findings(posture(json!({"advisories": many})));
    assert!(truncated);
    assert_eq!(capped.len(), MAX_FINDINGS);
    assert_eq!(capped[0]["advisory_ids"], json!(["GHSA-late"]));
    assert_eq!(capped[1]["severity"], "low");
}

#[test]
fn a_process_left_on_a_replaced_build_keeps_its_finding() {
    let (before, _) = findings(posture(
        json!({"advisories": [advisory(json!("affected"), json!({}))]}),
    ));
    let left = |state: &str| {
        posture(json!({
            "runtimes": [upgraded()],
            "instances": {"enumerated": true, "rows": [old_process(state)]},
            "advisories": [advisory(
                json!("restart_required"),
                json!({"affected_artifact_ids": [], "affected_instance_ids": ["i:old"]}),
            )],
        }))
    };
    let (after, _) = findings(left("running"));
    assert_eq!(after[0]["finding_id"], before[0]["finding_id"]);
    assert_eq!(after[0]["runtime_version"], "20.11.1");
    assert_eq!(after[0]["rule_ids"], json!(["restart_required"]));

    let mut unplaced = left("running");
    unplaced["instances"]["rows"][0]["location_id"] = json!("path:elsewhere");
    assert_eq!(findings(unplaced), (vec![], false));
    let mut unknown = left("running");
    unknown["instances"]["rows"] = json!([]);
    assert_eq!(findings(unknown), (vec![], false));
}

#[test]
fn every_path_of_a_matched_runtime_is_a_finding() {
    let mut copy = node();
    copy["path"] = json!("/opt/tools/bin/node");
    let both = posture(json!({
        "runtimes": [node(), copy],
        "advisories": [advisory(json!("affected"), json!({}))],
    }));
    let (found, _) = findings(both);
    assert_eq!(found.len(), 2);
    assert_ne!(found[0]["finding_id"], found[1]["finding_id"]);
}

#[test]
fn coverage_never_claims_runtimes_were_checked_without_advisories() {
    let checked = coverage(posture(json!({})));
    assert_eq!(checked["status"], "complete");
    assert_eq!(checked["reasons"], json!([]));
    assert_eq!(checked["detectors"]["runtime_identity_v1"], "complete");
    assert_eq!(checked["detectors"]["supply_chain"], "complete");
    assert_eq!(
        checked["runtimes"],
        json!({"digest": digest(posture(json!({}))), "runtime_count": 1})
    );

    let unchecked = coverage(posture(
        json!({"coverage": {"advisories_available": false}}),
    ));
    assert_eq!(unchecked["status"], "partial");
    assert_eq!(
        unchecked["reasons"],
        json!(["runtime_advisories_unavailable"])
    );
    assert_eq!(unchecked["detectors"]["runtime_identity_v1"], "incomplete");

    let unknown = coverage(posture(
        json!({"advisories": [advisory(json!("unknown"), json!({}))]}),
    ));
    assert_eq!(unknown["reasons"], json!(["runtimes_incomplete"]));

    let nothing = coverage(posture(
        json!({"runtimes": [], "coverage": {"advisories_available": false}}),
    ));
    assert_eq!(nothing["status"], "complete");
    assert_eq!(nothing["detectors"]["runtime_identity_v1"], "no_inputs");

    for missing in [
        Value::Null,
        json!({"status": "unavailable", "runtimes": [node()]}),
    ] {
        let not_run = coverage(missing.clone());
        assert_eq!(not_run["status"], "partial");
        assert_eq!(
            not_run["reasons"],
            json!(["detector_not_run:runtime_identity_v1"])
        );
        assert_eq!(not_run["detectors"]["runtime_identity_v1"], "not_run");
        assert_eq!(not_run["runtimes"]["digest"], Value::Null);
        let count = usize::from(!missing.is_null());
        assert_eq!(not_run["runtimes"]["runtime_count"], count);
    }
}

#[test]
fn unresolved_unidentified_or_unnamed_launches_leave_runtimes_incomplete() {
    let launch = json!({"harness": "codex", "server": "tools", "command": "node"});
    let unresolved = coverage(posture(
        json!({"runtimes": [], "unresolved_launches": [launch]}),
    ));
    assert_eq!(unresolved["reasons"], json!(["runtimes_incomplete"]));
    let mut unreadable = node();
    unreadable["artifact_id"] = Value::Null;
    unreadable["family"] = Value::Null;
    let unidentified = coverage(posture(json!({"runtimes": [unreadable]})));
    assert_eq!(unidentified["reasons"], json!(["runtimes_incomplete"]));

    let named = coverage(posture(json!({
        "instances": {"enumerated": true, "limit_reached": false, "unbound_processes": 0, "rows": []},
    })));
    assert_eq!(named["status"], "complete");
    for gap in [
        json!({"unbound_processes": 1}),
        json!({"limit_reached": true}),
        json!({"assessed": false}),
    ] {
        let mut instances = json!({"enumerated": true, "rows": []});
        for (key, value) in gap.as_object().unwrap() {
            instances[key] = value.clone();
        }
        let partial = coverage(posture(json!({ "instances": instances })));
        assert_eq!(
            partial["reasons"],
            json!(["runtime_instances_incomplete"]),
            "{gap}"
        );
    }
    let not_enumerated = coverage(posture(
        json!({"instances": {"enumerated": false, "limit_reached": true}}),
    ));
    assert_eq!(not_enumerated["reasons"], json!([]));
}

#[test]
fn malformed_arguments_are_refused() {
    let good = posture(json!({}));
    for args in [
        json!([]),
        json!({}),
        json!({"op": "identity_digest"}),
        json!({"op": "identity_digest", "posture": null}),
        json!({"op": "identity_digest", "posture": []}),
        json!({"op": "findings", "posture": good}),
        json!({"op": "findings", "worktree_key": 1, "posture": good}),
        json!({"op": "coverage", "posture": good}),
        json!({"op": "coverage", "coverage": [], "posture": good}),
        json!({"op": "other", "posture": good}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
