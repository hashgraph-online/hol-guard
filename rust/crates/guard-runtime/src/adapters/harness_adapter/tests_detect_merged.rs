//! A detection merged with the workspace AIBOM, and every harness's at once.

use std::fs;

use serde_json::{json, Value};

use super::super::describe::SPECS;
use super::super::detect_merged::ORDER;
use super::{dispatch, Home};

fn request(home: &Home, op: &str, harness: &str, workspace: Option<&str>) -> Value {
    let mut request = json!({"op": op, "context": home.context(json!({"PATH": ""}))});
    request["harness"] = json!(harness);
    if let Some(workspace) = workspace {
        request["context"]["workspace"] = json!(home.root.join(workspace));
    }
    request
}

fn workspace_with_skill(home: &Home) {
    let skill = home.root.join("work/.agents/skills/alpha");
    fs::create_dir_all(&skill).unwrap();
    fs::write(skill.join("SKILL.md"), "# alpha\n").unwrap();
}

#[test]
fn a_workspace_skill_joins_the_detection_and_its_config_paths() {
    let home = Home::new();
    workspace_with_skill(&home);

    let answer = dispatch(&request(&home, "detect_merged", "opencode", Some("work"))).unwrap();

    let skill = answer["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["artifact_id"] == "opencode:project:skill:agents:skills/alpha")
        .expect("the workspace skill");
    let path = skill["config_path"].as_str().unwrap();
    assert!(answer["config_paths"]
        .as_array()
        .unwrap()
        .contains(&json!(path)));
}

#[test]
fn a_detection_without_a_workspace_is_the_harness_own() {
    let home = Home::new();
    workspace_with_skill(&home);

    let merged = dispatch(&request(&home, "detect_merged", "opencode", None)).unwrap();
    let plain = dispatch(&request(&home, "detect", "opencode", None)).unwrap();

    assert_eq!(merged, plain);
}

#[test]
fn a_harness_that_takes_no_workspace_artifacts_is_left_alone() {
    let home = Home::new();
    workspace_with_skill(&home);

    let merged = dispatch(&request(&home, "detect_merged", "hermes", Some("work"))).unwrap();
    let plain = dispatch(&request(&home, "detect", "hermes", Some("work"))).unwrap();

    assert_eq!(plain["workspace_aibom"], json!(false));
    assert_eq!(merged, plain);
}

#[test]
fn the_registry_order_names_every_harness_once() {
    let mut ordered: Vec<&str> = ORDER.to_vec();
    ordered.sort_unstable();
    let mut described: Vec<&str> = SPECS.iter().map(|spec| spec.harness).collect();
    described.sort_unstable();
    assert_eq!(ordered, described);
    assert_eq!(ORDER[0], "codex");
}
