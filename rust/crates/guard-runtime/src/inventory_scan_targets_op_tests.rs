use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::{
    InventoryScanTargetsRequestV1, InventoryScanTargetsResultV1,
    INVENTORY_SCAN_TARGETS_MAX_ARTIFACTS, INVENTORY_SCAN_TARGETS_MAX_VISITED_ENTRIES,
    INVENTORY_SCAN_TARGETS_REQUEST_SCHEMA, INVENTORY_SCAN_TARGETS_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use super::{
    evaluate_inventory_scan_targets_request, evaluate_request, refusal, skill_dirs_under, Scan,
};

/// A workspace and a home under one temporary root, with the root resolved the
/// way the op resolves it. On macOS the system temporary directory is reached
/// through a symlink, so an unresolved root would never match what the op
/// reports.
struct Fixture {
    _root: TempDir,
    workspace: PathBuf,
    home: PathBuf,
}

fn fixture() -> Fixture {
    let root = TempDir::new().expect("temp root");
    let resolved = fs::canonicalize(root.path()).expect("canonical root");
    let workspace = resolved.join("workspace");
    let home = resolved.join("home");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::create_dir_all(&home).expect("home");
    Fixture {
        _root: root,
        workspace,
        home,
    }
}

fn write(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent");
    }
    fs::write(path, body).expect("write");
}

fn artifact(artifact_type: &str, config_path: Option<&str>, skill_root: Option<&str>) -> Value {
    let mut value = json!({ "artifact_type": artifact_type });
    if let Some(config_path) = config_path {
        value["config_path"] = json!(config_path);
    }
    if let Some(skill_root) = skill_root {
        value["skill_root"] = json!(skill_root);
    }
    value
}

fn request(fixture: &Fixture, harness: &str, artifacts: Vec<Value>) -> Value {
    json!({
        "schema": INVENTORY_SCAN_TARGETS_REQUEST_SCHEMA,
        "request_id": "inventory-scan-targets-test",
        "harness": harness,
        "cwd": fixture.workspace.to_string_lossy(),
        "home_dir": fixture.home.to_string_lossy(),
        "workspace_dir": fixture.workspace.to_string_lossy(),
        "artifacts": artifacts,
    })
}

fn parse(wire: &Value) -> InventoryScanTargetsRequestV1 {
    serde_json::from_value(wire.clone()).expect("request")
}

fn payload(wire: &Value) -> Value {
    evaluate_request(&parse(wire)).expect("payload")
}

fn mcp_targets(wire: &Value) -> Vec<Value> {
    payload(wire)["mcp_targets"]
        .as_array()
        .expect("mcp_targets")
        .clone()
}

fn skill_roots(wire: &Value) -> Vec<String> {
    payload(wire)["skill_roots"]
        .as_array()
        .expect("skill_roots")
        .iter()
        .map(|value| value.as_str().expect("root").to_owned())
        .collect()
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let fixture = fixture();
    let mut wire = request(&fixture, "claude_code", Vec::new());
    wire["schema"] = json!("guard-something-else.v1");
    assert_eq!(
        refusal(&parse(&wire)),
        Some("native_inventory_scan_targets_schema_mismatch"),
    );
}

#[test]
fn more_artifacts_than_the_bound_are_refused() {
    let fixture = fixture();
    let artifacts =
        vec![artifact("mcp_server", Some("/nowhere"), None); INVENTORY_SCAN_TARGETS_MAX_ARTIFACTS];
    assert_eq!(
        refusal(&parse(&request(&fixture, "claude_code", artifacts))),
        None
    );

    let artifacts = vec![
        artifact("mcp_server", Some("/nowhere"), None);
        INVENTORY_SCAN_TARGETS_MAX_ARTIFACTS + 1
    ];
    assert_eq!(
        refusal(&parse(&request(&fixture, "claude_code", artifacts))),
        Some("native_inventory_scan_targets_too_many_artifacts"),
    );
}

#[test]
fn the_workspace_and_the_home_contribute_their_own_configurations() {
    let fixture = fixture();
    write(&fixture.workspace.join(".mcp.json"), "{}");
    write(&fixture.home.join(".mcp.json"), "{}");

    let targets = mcp_targets(&request(&fixture, "claude_code", Vec::new()));
    assert_eq!(targets.len(), 2);
    assert_eq!(
        targets[0]["root"],
        json!(fixture.workspace.to_string_lossy())
    );
    assert_eq!(targets[0]["label"], json!(".mcp.json"));
    assert_eq!(targets[1]["root"], json!(fixture.home.to_string_lossy()));
}

#[test]
fn a_missing_configuration_contributes_nothing() {
    let fixture = fixture();
    assert!(mcp_targets(&request(&fixture, "claude_code", Vec::new())).is_empty());
}

#[test]
fn a_configuration_inside_the_workspace_is_scanned_under_the_whole_workspace() {
    let fixture = fixture();
    let config = fixture.workspace.join("tools").join("servers.json");
    write(&config, "{}");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact(
            "mcp_server",
            Some(&config.to_string_lossy()),
            None,
        )],
    );
    let targets = mcp_targets(&wire);
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0]["root"],
        json!(fixture.workspace.to_string_lossy())
    );
    assert_eq!(targets[0]["label"], json!("tools/servers.json"));
}

#[test]
fn a_configuration_outside_the_workspace_is_scanned_only_under_its_own_directory() {
    let fixture = fixture();
    let config = fixture.home.join("elsewhere").join("servers.json");
    write(&config, "{}");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact(
            "mcp_server",
            Some(&config.to_string_lossy()),
            None,
        )],
    );
    let targets = mcp_targets(&wire);
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0]["root"],
        json!(config.parent().expect("parent").to_string_lossy()),
    );
    assert_eq!(targets[0]["label"], json!("servers.json"));
}

#[test]
fn a_sibling_directory_sharing_a_name_prefix_is_not_inside_the_workspace() {
    let fixture = fixture();
    let outside = fixture
        .workspace
        .parent()
        .expect("root")
        .join("workspace-notes");
    let config = outside.join("servers.json");
    write(&config, "{}");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact(
            "mcp_server",
            Some(&config.to_string_lossy()),
            None,
        )],
    );
    let targets = mcp_targets(&wire);
    assert_eq!(targets[0]["root"], json!(outside.to_string_lossy()));
    assert_eq!(targets[0]["label"], json!("servers.json"));
}

#[test]
fn two_spellings_of_one_configuration_are_scanned_once() {
    let fixture = fixture();
    let config = fixture.workspace.join(".mcp.json");
    write(&config, "{}");
    let indirect = format!("{}/./.mcp.json", fixture.workspace.to_string_lossy());

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("mcp_server", Some(&indirect), None)],
    );
    assert_eq!(mcp_targets(&wire).len(), 1);
}

#[test]
fn an_artifact_without_a_usable_configuration_contributes_nothing() {
    let fixture = fixture();
    let wire = request(
        &fixture,
        "claude_code",
        vec![
            artifact("mcp_server", None, None),
            artifact("mcp_server", Some("   "), None),
            artifact("mcp_server", Some("/does/not/exist.json"), None),
            artifact("skill", Some(&fixture.workspace.to_string_lossy()), None),
        ],
    );
    assert!(mcp_targets(&wire).is_empty());
}

#[test]
fn a_relative_configuration_is_resolved_against_the_callers_directory() {
    let fixture = fixture();
    write(&fixture.workspace.join("servers.json"), "{}");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("mcp_server", Some("servers.json"), None)],
    );
    let targets = mcp_targets(&wire);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["config_path"], json!("servers.json"));
    assert_eq!(targets[0]["label"], json!("servers.json"));
}

#[test]
fn a_recorded_skill_root_holding_skills_is_the_collection() {
    let fixture = fixture();
    write(
        &fixture
            .workspace
            .join("skills")
            .join("alpha")
            .join("SKILL.md"),
        "# alpha",
    );

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("skill", None, Some("skills"))],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![fixture
            .workspace
            .join("skills")
            .to_string_lossy()
            .into_owned()],
    );
}

#[test]
fn a_recorded_skill_root_is_tried_under_the_home_when_the_workspace_has_none() {
    let fixture = fixture();
    write(&fixture.home.join("packs").join("SKILL.md"), "# pack");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("skill", None, Some("packs"))],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![fixture.home.join("packs").to_string_lossy().into_owned()],
    );
}

#[test]
fn a_recorded_skill_root_holding_no_skills_falls_back_to_the_artifacts_own_path() {
    let fixture = fixture();
    fs::create_dir_all(fixture.workspace.join("empty")).expect("empty");
    let skill = fixture.workspace.join("solo").join("SKILL.md");
    write(&skill, "# solo");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact(
            "skill_file",
            Some(&skill.to_string_lossy()),
            Some("empty"),
        )],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![fixture
            .workspace
            .join("solo")
            .to_string_lossy()
            .into_owned()],
    );
}

/// A directory beside the workspace and the home, holding a skill a contained
/// walk must never reach, and the skill inside the workspace that the artifact
/// itself names.
fn escape_fixture(fixture: &Fixture) -> (PathBuf, PathBuf, String) {
    let outside = fixture
        .workspace
        .parent()
        .expect("root")
        .join("outside")
        .join("skills");
    write(&outside.join("stolen").join("SKILL.md"), "# stolen");
    let skill = fixture.workspace.join("solo").join("SKILL.md");
    write(&skill, "# solo");
    (
        outside,
        fixture.workspace.join("solo"),
        skill.to_string_lossy().into_owned(),
    )
}

#[test]
fn a_recorded_skill_root_climbing_out_of_its_base_is_left_unused() {
    let fixture = fixture();
    let (_outside, own, skill) = escape_fixture(&fixture);

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact(
            "skill_file",
            Some(&skill),
            Some("../outside/skills"),
        )],
    );
    assert_eq!(skill_roots(&wire), vec![own.to_string_lossy().into_owned()]);
}

#[test]
fn an_absolute_recorded_skill_root_is_left_unused() {
    let fixture = fixture();
    let (outside, own, skill) = escape_fixture(&fixture);

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact(
            "skill_file",
            Some(&skill),
            Some(&outside.to_string_lossy()),
        )],
    );
    assert_eq!(skill_roots(&wire), vec![own.to_string_lossy().into_owned()]);
}

#[cfg(unix)]
#[test]
fn a_recorded_skill_root_reached_through_a_symlink_out_of_its_base_is_left_unused() {
    let fixture = fixture();
    let (outside, own, skill) = escape_fixture(&fixture);
    std::os::unix::fs::symlink(&outside, fixture.workspace.join("linked")).expect("symlink");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("skill_file", Some(&skill), Some("linked"))],
    );
    assert_eq!(skill_roots(&wire), vec![own.to_string_lossy().into_owned()]);
}

#[test]
fn the_nearest_skills_directory_holding_skills_wins_over_the_skills_own_directory() {
    let fixture = fixture();
    let skill = fixture
        .workspace
        .join("skills")
        .join("alpha")
        .join("SKILL.md");
    write(&skill, "# alpha");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("skill_file", Some(&skill.to_string_lossy()), None)],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![fixture
            .workspace
            .join("skills")
            .to_string_lossy()
            .into_owned()],
    );
}

#[test]
fn a_skills_directory_holding_its_own_skill_document_is_the_collection() {
    let fixture = fixture();
    let skill = fixture.workspace.join("skills").join("SKILL.md");
    write(&skill, "# bare");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("skill_file", Some(&skill.to_string_lossy()), None)],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![fixture
            .workspace
            .join("skills")
            .to_string_lossy()
            .into_owned()],
    );
}

#[test]
fn a_directory_holding_its_own_skill_document_is_its_own_root() {
    let fixture = fixture();
    let directory = fixture.workspace.join("solo");
    write(&directory.join("SKILL.md"), "# solo");

    let wire = request(
        &fixture,
        "claude_code",
        vec![artifact("skill", Some(&directory.to_string_lossy()), None)],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![directory.to_string_lossy().into_owned()],
    );
}

#[test]
fn two_skills_in_one_collection_name_it_once() {
    let fixture = fixture();
    let collection = fixture.workspace.join("skills");
    write(&collection.join("alpha").join("SKILL.md"), "# alpha");
    write(&collection.join("beta").join("SKILL.md"), "# beta");

    let wire = request(
        &fixture,
        "claude_code",
        vec![
            artifact(
                "skill_file",
                Some(&collection.join("alpha").join("SKILL.md").to_string_lossy()),
                None,
            ),
            artifact(
                "skill_file",
                Some(&collection.join("beta").join("SKILL.md").to_string_lossy()),
                None,
            ),
        ],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![collection.to_string_lossy().into_owned()],
    );
}

#[test]
fn hermes_reads_its_own_skill_directory_instead_of_the_detections_artifacts() {
    let fixture = fixture();
    let hermes = fixture.home.join(".hermes").join("skills");
    write(&hermes.join("alpha").join("SKILL.md"), "# alpha");
    let elsewhere = fixture.workspace.join("other");
    write(&elsewhere.join("SKILL.md"), "# other");

    let wire = request(
        &fixture,
        "hermes",
        vec![artifact("skill", Some(&elsewhere.to_string_lossy()), None)],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![hermes.join("alpha").to_string_lossy().into_owned()],
    );
}

#[test]
fn hermes_falls_back_to_the_detection_when_its_own_directory_holds_no_skills() {
    let fixture = fixture();
    fs::create_dir_all(fixture.home.join(".hermes").join("skills")).expect("hermes");
    let elsewhere = fixture.workspace.join("other");
    write(&elsewhere.join("SKILL.md"), "# other");

    let wire = request(
        &fixture,
        "hermes",
        vec![artifact("skill", Some(&elsewhere.to_string_lossy()), None)],
    );
    assert_eq!(
        skill_roots(&wire),
        vec![elsewhere.to_string_lossy().into_owned()],
    );
}

#[test]
fn collections_are_reported_in_path_order_not_string_order() {
    let fixture = fixture();
    let collection = fixture.workspace.join("skills");
    write(&collection.join("a").join("b").join("SKILL.md"), "# nested");
    write(&collection.join("a-b").join("SKILL.md"), "# dashed");

    let cwd = fixture.workspace.clone();
    let scan = Scan {
        cwd: cwd.as_path(),
        home: fixture.home.clone(),
        workspace: Some(fixture.workspace.clone()),
        walked: RefCell::new(HashMap::new()),
        budget: Cell::new(INVENTORY_SCAN_TARGETS_MAX_VISITED_ENTRIES),
    };
    assert_eq!(
        skill_dirs_under(&collection, &scan).expect("walk"),
        vec![
            collection
                .join("a")
                .join("b")
                .to_string_lossy()
                .into_owned(),
            collection.join("a-b").to_string_lossy().into_owned(),
        ],
    );
}

#[test]
fn a_walk_past_the_requests_budget_is_refused_rather_than_truncated() {
    let fixture = fixture();
    let collection = fixture.workspace.join("skills");
    for name in ["alpha", "beta", "gamma"] {
        write(&collection.join(name).join("SKILL.md"), "# skill");
    }

    let cwd = fixture.workspace.clone();
    let scan = Scan {
        cwd: cwd.as_path(),
        home: fixture.home.clone(),
        workspace: Some(fixture.workspace.clone()),
        walked: RefCell::new(HashMap::new()),
        budget: Cell::new(2),
    };
    assert_eq!(
        skill_dirs_under(&collection, &scan),
        Err("native_inventory_scan_targets_walk_too_large"),
    );
}

#[test]
fn one_collection_is_charged_against_the_budget_once_however_often_it_is_reached() {
    let fixture = fixture();
    let collection = fixture.workspace.join("skills");
    for name in ["alpha", "beta", "gamma"] {
        write(&collection.join(name).join("SKILL.md"), "# skill");
    }

    let cwd = fixture.workspace.clone();
    let scan = Scan {
        cwd: cwd.as_path(),
        home: fixture.home.clone(),
        workspace: Some(fixture.workspace.clone()),
        walked: RefCell::new(HashMap::new()),
        // Exactly what one walk of this collection visits, so a second walk
        // that charged the budget again would have nothing left to spend.
        budget: Cell::new(6),
    };
    let first = skill_dirs_under(&collection, &scan).expect("first walk");
    assert_eq!(first.len(), 3);
    assert_eq!(scan.budget.get(), 0);
    assert_eq!(
        skill_dirs_under(&collection, &scan).expect("second walk"),
        first
    );
}

#[test]
fn every_skill_in_one_collection_names_that_collection_once() {
    let fixture = fixture();
    let collection = fixture.workspace.join("skills");
    let mut artifacts = Vec::new();
    for name in ["alpha", "beta", "gamma", "delta"] {
        let document = collection.join(name).join("SKILL.md");
        write(&document, "# skill");
        artifacts.push(artifact(
            "skill",
            Some(&document.to_string_lossy()),
            Some("skills"),
        ));
    }

    let wire = request(&fixture, "claude-code", artifacts);
    assert_eq!(
        skill_roots(&wire),
        vec![collection.to_string_lossy().into_owned()],
    );
}

#[test]
fn the_result_carries_the_schema_and_binds_itself_to_its_request() {
    let fixture = fixture();
    write(&fixture.workspace.join(".mcp.json"), "{}");
    let wire = request(&fixture, "claude_code", Vec::new());

    let encoded = evaluate_inventory_scan_targets_request(&parse(&wire)).expect("response");
    let result: InventoryScanTargetsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.schema, INVENTORY_SCAN_TARGETS_RESULT_SCHEMA);
    assert_eq!(result.request_id, "inventory-scan-targets-test");
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert!(result.request_sha256.starts_with("sha256:"));
    assert_eq!(result.request_sha256.len(), "sha256:".len() + 64);
    assert!(result.payload.is_some());
}

#[test]
fn a_refusal_answers_with_its_code_and_no_payload() {
    let fixture = fixture();
    let mut wire = request(&fixture, "claude_code", Vec::new());
    wire["schema"] = json!("guard-something-else.v1");

    let encoded = evaluate_inventory_scan_targets_request(&parse(&wire)).expect("response");
    let result: InventoryScanTargetsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_inventory_scan_targets_schema_mismatch");
    assert!(result.payload.is_none());
}

#[test]
fn the_runtime_advertises_the_operation() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::INVENTORY_SCAN_TARGETS_FEATURE));
}
