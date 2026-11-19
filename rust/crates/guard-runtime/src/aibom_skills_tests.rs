use std::fs;
use std::path::Path;

use serde_json::json;
use tempfile::TempDir;

use super::{project_skill_artifacts, scope_skill_artifacts, HOME_SKILL_ROOTS};

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
    fs::write(path, body).expect("write");
}

#[test]
fn the_native_walk_reports_each_project_skill_on_every_platform() {
    let workspace = TempDir::new().expect("workspace");
    write(
        &workspace.path().join(".agents/skills/alpha/SKILL.md"),
        "# alpha\n",
    );
    write(
        &workspace.path().join(".agents/skills/group/beta/SKILL.md"),
        "# beta\n",
    );

    let artifacts = project_skill_artifacts("codex", workspace.path(), &None).expect("native walk");

    let mut ids: Vec<&str> = artifacts
        .iter()
        .map(|artifact| artifact["artifact_id"].as_str().expect("id"))
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [
            "codex:project:skill:.agents/skills:alpha",
            "codex:project:skill:.agents/skills:group/beta",
        ]
    );
    let alpha = artifacts
        .iter()
        .find(|artifact| artifact["name"] == "alpha")
        .expect("alpha artifact");
    assert_eq!(alpha["metadata"]["skill_root"], ".agents/skills");
    assert_eq!(
        alpha["metadata"]["skillDirectoryIdentity"]["status"],
        "complete"
    );
    assert_eq!(alpha["metadata"]["versionInfo"]["versionLabel"], "alpha");
    let config_path = alpha["config_path"].as_str().expect("config path");
    assert!(Path::new(config_path).ends_with(Path::new("alpha").join("SKILL.md")));
}

#[test]
fn a_missing_skill_root_yields_no_artifacts() {
    let home = TempDir::new().expect("home");

    let artifacts = scope_skill_artifacts("codex", home.path(), &HOME_SKILL_ROOTS, "global", &None)
        .expect("native walk");

    assert!(artifacts.is_empty());
}

#[test]
fn a_root_level_skill_document_is_named_by_its_root() {
    let home = TempDir::new().expect("home");
    write(&home.path().join(".codex/skills/SKILL.md"), "# root\n");

    let artifacts = scope_skill_artifacts("codex", home.path(), &HOME_SKILL_ROOTS, "global", &None)
        .expect("native walk");

    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        artifacts[0]["artifact_id"],
        "codex:global:skill:.codex/skills:."
    );
}

#[test]
fn caller_supplied_artifacts_replace_the_walk() {
    let workspace = TempDir::new().expect("workspace");
    write(&workspace.path().join(".agents/skills/alpha/SKILL.md"), "x");
    let finished = vec![json!({"artifact_id": "supplied"})];

    let artifacts = project_skill_artifacts("codex", workspace.path(), &Some(finished.clone()))
        .expect("supplied artifacts");

    assert_eq!(artifacts, finished);
}
