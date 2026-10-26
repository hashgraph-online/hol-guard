use super::*;
use crate::policy_decision_lookup_op::tests::{seed_store, tmp_store};
use serde_json::{json, Value};

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_tool_policy/lookup_compose_vectors.json");
const PARITY: &str = include_str!("../../../../tests/fixtures/mcp_tool_policy/parity_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("lookup vectors parse")
}

#[test]
fn most_restrictive_replays_every_python_recorded_vector() {
    let doc = vectors();
    let all = doc["most_restrictive"].as_array().expect("vectors");
    assert!(all.len() >= 400);
    for (index, vector) in all.iter().enumerate() {
        let input = vector["input"].as_array().expect("lookups");
        assert_eq!(
            most_restrictive(input).expect("non-empty"),
            vector["expected"],
            "vector {index}"
        );
    }
}

#[test]
fn portable_selectors_replay_every_python_recorded_vector() {
    let doc = vectors();
    let all = doc["without_permission_elevation"]
        .as_array()
        .expect("vectors");
    assert!(all.len() >= 15);
    for (index, vector) in all.iter().enumerate() {
        assert_eq!(
            without_permission_elevation(vector["input"].clone()),
            vector["expected"],
            "vector {index}"
        );
    }
}

#[test]
fn no_candidate_has_no_composition() {
    assert!(most_restrictive(&[]).is_none());
}

fn subject() -> McpToolPolicySubjectV1 {
    let doc: Value = serde_json::from_str(PARITY).expect("parity vectors parse");
    let (_, first) = doc["subjects"]
        .as_object()
        .and_then(|subjects| subjects.iter().next())
        .expect("a subject");
    let mut subject = first.clone();
    subject["artifact_id"] = json!("npm:lodash");
    subject["artifact_hash"] = json!("sha256:abc");
    subject["harness"] = json!("codex");
    subject["workspace"] = Value::Null;
    subject["publisher"] = Value::Null;
    serde_json::from_value(subject).expect("subject parses")
}

fn input(store: &std::path::Path) -> McpPolicyLookupInputV1 {
    McpPolicyLookupInputV1 {
        store_path: store.to_string_lossy().into_owned(),
        guard_home: store
            .parent()
            .expect("store dir")
            .to_string_lossy()
            .into_owned(),
        now: "2030-01-01T00:00:00+00:00".to_owned(),
        portable_workspace: None,
        integrity_state: Some(json!({
            "backend": "encrypted-file",
            "mode": "protected",
            "generation": 1,
            "enforcement": "enforce",
            "degraded_reasons": [],
        })),
        integrity_key_b64: None,
        integrity_key_id: None,
        local_once_integrity_key_b64: None,
        local_once_integrity_key_id: None,
        policy_bundle_decision_identities: None,
        degraded_trust_status: None,
        diagnostic_empty: false,
    }
}

fn lookup_ids(lookup: &McpPolicyLookupInputV1, ids: &[&str]) -> Result<Value, Stop> {
    let ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    policy_lookup_candidates(lookup, &subject(), &ids, None)
}

fn insert_remote_row(store: &std::path::Path, artifact_id: &str, action: &str, id: i64) {
    let conn = rusqlite::Connection::open(store).expect("open");
    conn.execute(
        "insert into policy_decisions values
         (?1,'codex','artifact',?2,?3,'sha256:abc',NULL,NULL,
          'cloud-signed-memory','policy',NULL,'2029-01-01T00:00:00+00:00','2030-01-01T00:00:00+00:00',
          '2031-01-01T00:00:00+00:00',1,NULL,'h','m','k','s')",
        rusqlite::params![id, artifact_id, action],
    )
    .expect("insert");
}

#[test]
fn an_empty_store_reads_as_no_decision_and_asks_for_a_diagnostic_only_when_empty() {
    let store = tmp_store("mcp-lookup-empty");
    seed_store(&store);
    let mut lookup = input(&store);
    let ids = ["npm:lodash", "exact:codex:abc"];
    let observed = lookup_ids(&lookup, &ids).expect("lookup");
    assert_eq!(
        observed,
        json!({"decision": null, "ignored_local_integrity": false})
    );
    lookup.diagnostic_empty = true;
    let observed = lookup_ids(&lookup, &ids).expect("lookup");
    assert_eq!(observed["reuse_diagnostic"], json!({"reason": null}));
}

#[test]
fn the_most_restrictive_candidate_wins_in_one_pass() {
    let store = tmp_store("mcp-lookup-restrictive");
    seed_store(&store);
    insert_remote_row(&store, "npm:lodash", "allow", 1);
    insert_remote_row(&store, "memory:codex:shell:abc", "block", 2);
    let lookup = input(&store);
    let observed = lookup_ids(&lookup, &["npm:lodash", "memory:codex:shell:abc"]).expect("lookup");
    assert_eq!(observed["decision"]["action"], "block");
    assert_eq!(
        observed["decision"]["artifact_id"],
        "memory:codex:shell:abc"
    );
    assert_eq!(observed["decision"]["_approval_authority_revision"], 5);
    assert_eq!(observed["ignored_local_integrity"], false);
    assert!(observed.get("reuse_diagnostic").is_none());
}

#[test]
fn a_degraded_home_reads_nothing_and_never_opens_the_store() {
    let store = tmp_store("mcp-lookup-degraded");
    // No store file exists: a degraded probe must not need one.
    let mut lookup = input(&store);
    lookup.degraded_trust_status = Some(json!({"status": "degraded"}));
    let observed = policy_lookup(&lookup, &subject(), None).expect("lookup");
    assert_eq!(
        observed,
        json!({"decision": null, "ignored_local_integrity": false})
    );
}

#[test]
fn candidate_lists_must_lead_with_the_subject_and_stay_bounded() {
    let store = tmp_store("mcp-lookup-bounds");
    seed_store(&store);
    for ids in [
        vec![],
        vec!["other:artifact"],
        vec!["npm:lodash"; MAX_CANDIDATES + 1],
    ] {
        let lookup = input(&store);
        assert!(matches!(
            lookup_ids(&lookup, &ids),
            Err(Stop::Fail(ERR_LOOKUP))
        ));
    }
}

#[test]
fn a_store_outside_the_guard_home_is_refused() {
    let store = tmp_store("mcp-lookup-outside");
    seed_store(&store);
    let mut lookup = input(&store);
    lookup.guard_home = "/nonexistent-guard-home".to_owned();
    assert!(matches!(
        policy_lookup(&lookup, &subject(), None),
        Err(Stop::Fail(ERR_LOOKUP))
    ));
}

#[test]
fn candidates_lead_with_the_subject_then_its_remembered_ids() {
    let mut subject = subject();
    subject.artifact.command = Some("git status".to_owned());
    let remembered = memory_pattern::verdict(&MemoryRequest {
        command: Some("git status"),
        artifact_type: Some(&subject.artifact_type),
        artifact_id: Some("npm:lodash"),
        artifact_name: Some(&subject.artifact.name),
        harness: Some("codex"),
    });
    let mut expected = vec!["npm:lodash".to_owned()];
    expected.extend(remembered.exact_artifact_ids);
    expected.extend(remembered.memory_artifact_id);
    assert_eq!(candidate_ids(&subject), expected);
    assert!(candidate_ids(&subject).len() <= MAX_CANDIDATES);
}
