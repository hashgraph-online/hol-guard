use std::fs;
use std::path::Path;

use guard_contracts::{
    InventorySourceEvidenceRequestV1, InventorySourceEvidenceResultV1,
    INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES, INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
    INVENTORY_SOURCE_EVIDENCE_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{evaluate_inventory_source_evidence_request, evaluate_request, refusal};

fn write(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directory");
    }
    fs::write(path, body).expect("write");
}

fn expected_hash(body: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(body.as_bytes())))
}

fn entry(artifact_type: &str, config_path: &Path) -> Value {
    json!({
        "harness": "codex",
        "item_kind": "skill",
        "artifact_type": artifact_type,
        "config_path": config_path.to_string_lossy(),
    })
}

fn request(home: &Path, workspace: Option<&Path>, entries: Vec<Value>) -> Value {
    let mut wire = json!({
        "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "inventory-source-evidence-test",
        "home_dir": home.to_string_lossy(),
        "include_symlinks": true,
        "follow_unsafe_symlinks": false,
        "entries": entries,
    });
    if let Some(workspace) = workspace {
        wire["workspace_dir"] = json!(workspace.to_string_lossy());
    }
    wire
}

fn parse(wire: &Value) -> InventorySourceEvidenceRequestV1 {
    serde_json::from_value(wire.clone()).expect("request")
}

fn evidence(wire: &Value) -> Vec<Value> {
    evaluate_request(&parse(wire))["evidence"]
        .as_array()
        .expect("evidence")
        .clone()
}

#[test]
fn a_request_round_trips_to_the_bytes_the_caller_sent() {
    // The result is bound to the digest of the request as re-serialized here,
    // so an omitted optional field must not come back as an explicit null.
    let home = Path::new("/home/example");
    let full = request(
        home,
        Some(Path::new("/home/example/code")),
        vec![entry(
            "skill",
            Path::new("/home/example/skills/demo/SKILL.md"),
        )],
    );
    let sparse = json!({
        "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "",
        "home_dir": "/home/example",
        "include_symlinks": false,
        "follow_unsafe_symlinks": false,
        "entries": [{
            "harness": "claude",
            "item_kind": "instruction",
            "artifact_type": "instruction",
        }],
    });
    // The current caller leaves the kind to the resident and sends no key.
    let current = json!({
        "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "",
        "home_dir": "/home/example",
        "include_symlinks": false,
        "follow_unsafe_symlinks": false,
        "entries": [{"harness": "claude", "artifact_type": "instruction"}],
    });

    for wire in [full, sparse, current] {
        assert_eq!(serde_json::to_value(parse(&wire)).expect("value"), wire);
    }
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let mut wire = request(Path::new("/home/example"), None, Vec::new());
    wire["schema"] = json!("guard-other-request.v1");

    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_source_evidence_schema_mismatch")
    );
}

#[test]
fn a_request_without_a_home_directory_is_refused() {
    let wire = request(Path::new("   "), None, Vec::new());

    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_source_evidence_home_required")
    );
}

#[test]
fn a_request_over_the_entry_cap_is_refused() {
    let path = Path::new("/home/example/skills/demo/SKILL.md");
    let entries = vec![entry("skill", path); INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES + 1];
    let wire = request(Path::new("/home/example"), None, entries);

    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_source_evidence_too_many_entries")
    );
}

#[test]
fn the_answer_is_bound_to_the_request_that_asked_for_it() {
    let home = TempDir::new().expect("home");
    let wire = request(home.path(), None, Vec::new());

    let encoded = evaluate_inventory_source_evidence_request(&parse(&wire)).expect("response");
    let result: InventorySourceEvidenceResultV1 = serde_json::from_slice(&encoded).expect("result");

    assert_eq!(result.schema, INVENTORY_SOURCE_EVIDENCE_RESULT_SCHEMA);
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert_eq!(result.request_id, "inventory-source-evidence-test");
    // `_payload` binds the reply by `"sha256:" + _canonical_request_sha256`,
    // so the digest carries its prefix or the bridge drops the answer.
    let digest = result
        .request_sha256
        .strip_prefix("sha256:")
        .expect("prefixed digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|char| char.is_ascii_hexdigit()));
    assert_eq!(result.payload, Some(json!({ "evidence": [] })));
}

#[test]
fn a_skill_document_under_a_skills_root_is_hashed() {
    let home = TempDir::new().expect("home");
    let document = home.path().join("skills/demo/SKILL.md");
    write(&document, "alpha");
    let wire = request(home.path(), None, vec![entry("skill", &document)]);

    let answers = evidence(&wire);

    assert_eq!(answers.len(), 1);
    assert_eq!(
        answers[0]["primary_content_hash"],
        json!(expected_hash("alpha"))
    );
    assert_eq!(answers[0]["source_of_truth"], Value::Null);
}

#[test]
fn a_skill_document_naming_no_skill_directory_has_no_hash() {
    let home = TempDir::new().expect("home");
    let document = home.path().join("skills/SKILL.md");
    write(&document, "alpha");
    let wire = request(home.path(), None, vec![entry("skill", &document)]);

    assert_eq!(evidence(&wire)[0]["primary_content_hash"], Value::Null);
}

#[test]
fn an_instruction_is_hashed_only_inside_a_workspace() {
    let home = TempDir::new().expect("home");
    let workspace = home.path().join("code");
    let document = workspace.join("AGENTS.md");
    write(&document, "beta");

    let without = request(home.path(), None, vec![entry("instruction", &document)]);
    assert_eq!(evidence(&without)[0]["primary_content_hash"], Value::Null);

    let with = request(
        home.path(),
        Some(&workspace),
        vec![entry("instruction", &document)],
    );
    assert_eq!(
        evidence(&with)[0]["primary_content_hash"],
        json!(expected_hash("beta"))
    );
}

#[test]
fn an_instruction_with_an_unreadable_suffix_has_no_hash() {
    let home = TempDir::new().expect("home");
    let workspace = home.path().join("code");
    let document = workspace.join("notes.txt");
    write(&document, "beta");
    let wire = request(
        home.path(),
        Some(&workspace),
        vec![entry("instruction", &document)],
    );

    assert_eq!(evidence(&wire)[0]["primary_content_hash"], Value::Null);
}

#[test]
fn an_artifact_type_with_no_primary_document_has_no_hash() {
    let home = TempDir::new().expect("home");
    let document = home.path().join("skills/demo/SKILL.md");
    write(&document, "alpha");
    let wire = request(home.path(), None, vec![entry("hook", &document)]);

    assert_eq!(evidence(&wire)[0]["primary_content_hash"], Value::Null);
}

#[test]
fn the_answers_keep_the_order_the_request_asked_in() {
    let home = TempDir::new().expect("home");
    let first = home.path().join("skills/one/SKILL.md");
    let second = home.path().join("skills/two/SKILL.md");
    write(&first, "alpha");
    write(&second, "beta");
    let wire = request(
        home.path(),
        None,
        vec![entry("skill", &second), entry("skill", &first)],
    );

    let answers = evidence(&wire);

    assert_eq!(
        answers[0]["primary_content_hash"],
        json!(expected_hash("beta"))
    );
    assert_eq!(
        answers[1]["primary_content_hash"],
        json!(expected_hash("alpha"))
    );
}

#[cfg(unix)]
mod links {
    use super::*;

    fn link(target: &Path, at: &Path) {
        if let Some(parent) = at.parent() {
            fs::create_dir_all(parent).expect("parent directory");
        }
        std::os::unix::fs::symlink(target, at).expect("symlink");
    }

    #[test]
    fn a_symlinked_config_path_carries_its_source_of_truth() {
        let home = TempDir::new().expect("home");
        let real = home.path().join("real/demo/SKILL.md");
        write(&real, "alpha");
        let document = home.path().join("skills/demo/SKILL.md");
        link(&real, &document);
        let wire = request(home.path(), None, vec![entry("skill", &document)]);

        let answers = evidence(&wire);
        let source = &answers[0]["source_of_truth"];

        assert_eq!(source["linkKind"], json!("symlink"));
        assert_eq!(source["validationState"], json!("valid"));
        assert_eq!(source["redactionSummary"]["rawPathsIncluded"], json!(false));
        let link_id = source["sourceLinkId"].as_str().expect("source link id");
        assert!(link_id.starts_with("codex:skill:"), "{link_id}");
        assert_eq!(link_id.len(), "codex:skill:".len() + 24);
        // The document is reached through a link, so its hash is withheld
        // rather than read through a path the allowed root cannot vouch for.
        assert_eq!(answers[0]["primary_content_hash"], Value::Null);
    }

    #[test]
    fn a_caller_that_asks_for_no_symlink_metadata_gets_none() {
        let home = TempDir::new().expect("home");
        let real = home.path().join("real/demo/SKILL.md");
        write(&real, "alpha");
        let document = home.path().join("skills/demo/SKILL.md");
        link(&real, &document);
        let mut wire = request(home.path(), None, vec![entry("skill", &document)]);
        wire["include_symlinks"] = json!(false);

        assert_eq!(evidence(&wire)[0]["source_of_truth"], Value::Null);
    }
}

#[test]
fn answers_the_item_kind_the_artifact_type_maps_onto() {
    let wire = json!({
        "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "",
        "home_dir": "/home/example",
        "include_symlinks": false,
        "follow_unsafe_symlinks": false,
        "entries": [
            {"harness": "claude", "artifact_type": "instruction"},
            {"harness": "claude", "artifact_type": "gateway_config"},
        ],
    });
    let answers = evidence(&wire);
    let kinds: Vec<&str> = answers
        .iter()
        .map(|answer| answer["item_kind"].as_str().expect("item_kind"))
        .collect();
    assert_eq!(kinds, vec!["overlay", "agent"]);
}

#[test]
fn accepts_an_entry_that_leaves_the_item_kind_to_the_resident() {
    let wire = json!({
        "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "",
        "home_dir": "/home/example",
        "include_symlinks": false,
        "follow_unsafe_symlinks": false,
        "entries": [{"harness": "claude", "artifact_type": "skill"}],
    });
    assert_eq!(parse(&wire).entries[0].item_kind, None);
    assert_eq!(evidence(&wire)[0]["item_kind"], json!("skill"));
}

#[test]
fn every_entry_shape_is_advertised() {
    // v3 is this resident: it derives the kind and the instruction role. v2
    // and v1 stay advertised because a client built before either change
    // still speaks this wire schema and this op still answers it.
    let features = crate::resident_op_features::RESIDENT_OP_FEATURES;
    assert!(features.contains(&guard_contracts::INVENTORY_SOURCE_EVIDENCE_FEATURE));
    assert!(features.contains(&guard_contracts::INVENTORY_SOURCE_EVIDENCE_PREVIOUS_FEATURE));
    assert!(features.contains(&guard_contracts::INVENTORY_SOURCE_EVIDENCE_FIRST_FEATURE));
}

fn instruction_role(artifact_type: &str, config_path: &str) -> Value {
    let wire = json!({
        "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
        "request_id": "",
        "home_dir": "/home/example",
        "include_symlinks": false,
        "follow_unsafe_symlinks": false,
        "entries": [{
            "harness": "claude",
            "artifact_type": artifact_type,
            "config_path": config_path,
        }],
    });
    evidence(&wire)[0]["instruction_role"].clone()
}

#[test]
fn reads_the_instruction_role_an_overlay_path_names() {
    // The same grammar the discovery walk applies: the file's own name first,
    // then the directory an instruction document sits under.
    assert_eq!(
        instruction_role("instruction", "/home/example/code/AGENTS.md"),
        json!("agents_md")
    );
    assert_eq!(
        instruction_role("instruction", "/home/example/code/docs/product/brief.md"),
        json!("product_md")
    );
    assert_eq!(
        instruction_role("instruction", "/home/example/code/.cursor/rules/style.mdc"),
        json!("cursor_rules")
    );
}

#[test]
fn leaves_the_instruction_role_unanswered_when_the_path_names_none() {
    // An ordinary document under no recognized directory is still an overlay;
    // it just has no role to record, and inventing one would be a guess.
    assert_eq!(
        instruction_role("instruction", "/home/example/code/notes/scratch.md"),
        Value::Null
    );
    // A `rules` directory is a cursor rule only under `.cursor`; an ordinary
    // one named the same way is not.
    assert_eq!(
        instruction_role("instruction", "/home/example/code/src/rules/guide.md"),
        Value::Null
    );
    assert_eq!(instruction_role("instruction", ""), Value::Null);
}

#[test]
fn reads_the_role_from_the_path_the_harness_configured() {
    // The caller anchors a relative config path so the resident has something
    // to resolve, and the directory it anchors to is wherever the scan ran.
    // The role has to keep reading the configured path: `notes.md` names no
    // role, however many role-shaped components the working directory has.
    let wire = |config_path: &str, configured_path: &str| {
        json!({
            "schema": INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
            "request_id": "",
            "home_dir": "/home/example",
            "include_symlinks": false,
            "follow_unsafe_symlinks": false,
            "entries": [{
                "harness": "claude",
                "artifact_type": "instruction",
                "config_path": config_path,
                "configured_path": configured_path,
            }],
        })
    };
    assert_eq!(
        evidence(&wire(
            "/home/example/code/docs/security/notes.md",
            "notes.md"
        ))[0]["instruction_role"],
        Value::Null
    );
    assert_eq!(
        evidence(&wire(
            "/home/example/code/.cursor/rules/notes.md",
            "notes.md"
        ))[0]["instruction_role"],
        Value::Null
    );
    // A configured path that does name a role keeps it, anchored or not.
    assert_eq!(
        evidence(&wire(
            "/home/example/code/docs/security/notes.md",
            "docs/security/notes.md"
        ))[0]["instruction_role"],
        json!("security_md")
    );
}

#[test]
fn reads_no_instruction_role_for_an_artifact_that_is_not_an_overlay() {
    // A skill's config path can be a Markdown document too. The role names
    // what an instruction overlay is, so a skill never carries one however
    // its path is spelled.
    assert_eq!(
        instruction_role("skill", "/home/example/code/AGENTS.md"),
        Value::Null
    );
}
