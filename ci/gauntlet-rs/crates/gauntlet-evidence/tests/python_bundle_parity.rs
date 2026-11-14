//! Synthetic bundle exported and verified by pinned Python Gauntlet b4efd817.

use gauntlet_evidence::{verify_bundle, ExternalPins};
use std::fs;
use std::path::{Path, PathBuf};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python_bundle_v1")
}

fn pins() -> ExternalPins {
    ExternalPins::from_json(include_bytes!("fixtures/python_bundle_v1_pins.json")).unwrap()
}

fn copy_bundle(destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::create_dir(destination.join("effects")).unwrap();
    fs::create_dir(destination.join("state")).unwrap();
    for name in [
        "manifest.json",
        "campaign.json",
        "effects/world.json",
        "state/initial.json",
    ] {
        fs::copy(fixture().join(name), destination.join(name)).unwrap();
    }
}

#[test]
fn agrees_with_python_on_valid_incomplete_bundle() {
    let report = verify_bundle(&fixture(), &pins()).unwrap();
    assert_eq!(report.files, 4);
    assert_eq!(report.scheduled_episodes, 8);
    assert_eq!(report.recorded_episodes, 0);
    assert_eq!(report.missing_episodes.len(), 8);
    assert_eq!(report.to_json()["integrity"], "valid");
    assert_eq!(report.to_json()["status"], "exploratory");
    assert_eq!(report.to_json()["qualification_eligible"], false);
}

#[test]
fn agrees_with_python_on_complete_synthetic_inventory_without_claiming_success() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let complete = root.join("tests/fixtures/python_bundle_complete_v1");
    let pins = ExternalPins::from_json(include_bytes!(
        "fixtures/python_bundle_complete_v1_pins.json"
    ))
    .unwrap();
    let report = verify_bundle(&complete, &pins).unwrap();
    assert_eq!(report.files, 5);
    assert_eq!(report.scheduled_episodes, 8);
    assert_eq!(report.recorded_episodes, 8);
    assert!(report.missing_episodes.is_empty());
    assert_eq!(report.to_json()["completeness"], "complete");
    assert_eq!(report.to_json()["qualification_eligible"], false);
    assert_eq!(report.to_json()["status"], "exploratory");
}

#[test]
fn signed_hostile_python_bundles_still_fail_against_external_pins() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (case, reason) in [
        ("duplicate_path", "duplicate manifest path"),
        ("traversal", "manifest path"),
        ("source_swap", "external pins"),
        ("boolean_count", "inventory count"),
    ] {
        let bundle = root.join(format!("python_bundle_reject_{case}_v1"));
        let pin_bytes =
            fs::read(root.join(format!("python_bundle_reject_{case}_v1_pins.json"))).unwrap();
        let pins = ExternalPins::from_json(&pin_bytes).unwrap();
        let error = verify_bundle(&bundle, &pins).unwrap_err();
        assert!(error.to_string().contains(reason), "{case}: {error}");
    }
}

#[test]
fn independently_pinned_custody_cannot_be_replaced_by_bundle() {
    let mut changed = pins();
    changed.manifest_sha256 = "0".repeat(64);
    assert!(verify_bundle(&fixture(), &changed).is_err());

    let mut changed = pins();
    changed.controller_public_key[0] ^= 1;
    assert!(verify_bundle(&fixture(), &changed).is_err());

    let mut changed = pins();
    changed.source_identities["candidate"] = serde_json::json!("0".repeat(64));
    assert!(verify_bundle(&fixture(), &changed).is_err());

    let mut changed = pins();
    changed.effect_anchors["world"]["final_hash"] = serde_json::json!("0".repeat(64));
    assert!(verify_bundle(&fixture(), &changed).is_err());
}

#[test]
fn changed_and_unlisted_files_fail() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("bundle");
    copy_bundle(&bundle);
    let target = bundle.join("effects/world.json");
    let content = fs::read_to_string(&target).unwrap();
    fs::write(&target, content.replace("lead-a", "lead-x")).unwrap();
    assert!(verify_bundle(&bundle, &pins()).is_err());

    let another = temporary.path().join("another");
    copy_bundle(&another);
    fs::write(another.join("extra.json"), "{}").unwrap();
    assert!(verify_bundle(&another, &pins()).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_bundle_file_and_root_fail() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("bundle");
    copy_bundle(&bundle);
    let alias = temporary.path().join("alias");
    symlink(&bundle, &alias).unwrap();
    assert!(verify_bundle(&alias, &pins()).is_err());

    let target = bundle.join("state/initial.json");
    fs::remove_file(&target).unwrap();
    symlink(bundle.join("campaign.json"), &target).unwrap();
    assert!(verify_bundle(&bundle, &pins()).is_err());
}

#[test]
fn noncanonical_bundle_root_fails() {
    let root = fixture();
    assert!(verify_bundle(&root.join("."), &pins()).is_err());
    assert!(verify_bundle(&root.join("../python_bundle_v1"), &pins()).is_err());
}
