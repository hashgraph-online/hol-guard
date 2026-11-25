use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{advise, checked_path, for_approval, Manager};
use crate::runtime_identity::LaunchAdvisories;
use crate::runtime_known_vulnerable::Finding;

fn advisories() -> LaunchAdvisories {
    let range = |introduced: &str, fixed: &str| json!({"introduced": introduced, "fixed": fixed, "last_affected": null});
    LaunchAdvisories::for_tests(
        json!([{
            "advisory_id": "CVE-0000-0001",
            "family": "node",
            "vendor": "nodejs.org",
            "version_scheme": "semver",
            "severity": "high",
            "ranges": [
                range("11.7.0", "22.23.4"),
                range("23.0.0", "24.22.1"),
                range("25.0.0", "26.12.1"),
            ],
        }]),
        json!({"state": "verified"}),
    )
}

fn finding(version: &str, path: &Path) -> Finding {
    Finding {
        advisory_id: "CVE-0000-0001".to_owned(),
        severity: "high".to_owned(),
        known_exploited: false,
        version: version.to_owned(),
        resolved_path: path.to_string_lossy().into_owned(),
        expired_at: None,
    }
}

/// An nvm directory holding `versions`, with `default` aliased to `node`.
fn nvm(versions: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let directory = root.path().join("nvm");
    for version in versions {
        let bin = directory.join("versions/node").join(version).join("bin");
        fs::create_dir_all(&bin).expect("bin");
        fs::write(bin.join("node"), b"").expect("node");
    }
    fs::write(directory.join("nvm.sh"), b"").expect("nvm.sh");
    fs::create_dir_all(directory.join("alias")).expect("alias");
    fs::write(directory.join("alias/default"), b"node").expect("default");
    (root, directory)
}

fn node(directory: &Path, version: &str) -> PathBuf {
    directory
        .join("versions/node")
        .join(version)
        .join("bin/node")
}

#[test]
fn the_finding_text_names_the_checked_executable() {
    let path = Path::new("/opt/runtimes/node 25/bin/node");
    let text = finding("25.2.1", path).describe();
    assert_eq!(checked_path(&text), Some("/opt/runtimes/node 25/bin/node"));
    assert_eq!(
        checked_path("Node.js 25.2.1 at node is affected by X"),
        None
    );
    assert_eq!(checked_path("Command review required"), None);
}

#[test]
fn nvm_with_a_patched_version_installed_offers_a_switch_to_it() {
    let (_root, directory) = nvm(&["v25.2.1", "v24.22.1", "v24.16.0", "v22.22.2"]);
    let current = node(&directory, "v25.2.1");
    let advice = advise(finding("25.2.1", &current), &advisories(), |_| true);
    assert_eq!(advice.manager, Manager::Nvm(directory.clone()));
    let shown = advice.to_json();
    assert_eq!(shown["manager"], "nvm");
    assert_eq!(shown["installed_version"], "24.22.1");
    assert_eq!(shown["patched_version"], "26.12.1");
    assert_eq!(shown["switch_version"], "24.22.1");
    assert_eq!(shown["switched"], false);
    assert_eq!(shown["command"], "nvm alias default 24.22.1");

    assert_eq!(
        advice.switch("26.12.1"),
        Err("runtime_upgrade_version_mismatch")
    );
    assert_eq!(advice.switch("24.22.1"), Ok(()));
    let alias = fs::read_to_string(directory.join("alias/default")).expect("alias");
    assert_eq!(alias, "24.22.1");

    let again = advise(finding("25.2.1", &current), &advisories(), |_| true);
    assert_eq!(again.to_json()["switched"], true);
    assert_eq!(again.to_json()["switch_version"], Value::Null);
    assert_eq!(again.switch("24.22.1"), Err("runtime_upgrade_unavailable"));
}

#[test]
fn an_installed_version_the_binary_check_refuses_is_not_offered() {
    let (_root, directory) = nvm(&["v25.2.1", "v24.22.1"]);
    let current = node(&directory, "v25.2.1");
    let refused = node(&directory, "v24.22.1");
    let advice = advise(finding("25.2.1", &current), &advisories(), |binary| {
        binary != refused
    });
    let shown = advice.to_json();
    assert_eq!(shown["installed_version"], Value::Null);
    assert_eq!(shown["switch_version"], Value::Null);
    assert_eq!(
        shown["command"],
        "nvm install 26.12.1 && nvm alias default 26.12.1"
    );
    assert_eq!(advice.switch("24.22.1"), Err("runtime_upgrade_unavailable"));
}

#[test]
fn a_patched_version_on_the_same_line_wins_over_a_newer_line() {
    let (_root, directory) = nvm(&["v24.10.0", "v24.22.1", "v26.12.1"]);
    let current = node(&directory, "v24.10.0");
    let advice = advise(finding("24.10.0", &current), &advisories(), |_| true);
    assert_eq!(advice.to_json()["installed_version"], "24.22.1");
}

#[test]
fn homebrew_and_unknown_installs_get_a_command_or_a_download_but_no_switch() {
    let brew = Path::new("/opt/homebrew/Cellar/node/25.2.1/bin/node");
    let advice = advise(finding("25.2.1", brew), &advisories(), |_| true);
    let shown = advice.to_json();
    assert_eq!(shown["manager"], "homebrew");
    assert_eq!(shown["command"], "brew upgrade node");
    assert_eq!(shown["switch_version"], Value::Null);
    assert_eq!(advice.switch("26.12.1"), Err("runtime_upgrade_unavailable"));

    // A versions/node layout without nvm.sh beside it is not nvm.
    let root = tempfile::tempdir().expect("tempdir");
    let loose = root.path().join("versions/node/v25.2.1/bin/node");
    let advice = advise(finding("25.2.1", &loose), &advisories(), |_| true);
    let shown = advice.to_json();
    assert_eq!(shown["manager"], "other");
    assert_eq!(shown["command"], Value::Null);
    assert_eq!(shown["download_url"], "https://nodejs.org/en/download");
}

#[test]
fn only_a_pending_known_vulnerable_review_gets_advice() {
    let home = tempfile::tempdir().expect("tempdir");
    let row = |status: &str, envelope: Value| -> Map<String, Value> {
        let Value::Object(row) = json!({
            "status": status,
            "risk_summary": "Node.js 25.2.1 at /opt/node/bin/node is affected by CVE-0000-0001 (high).",
            "action_envelope_json": envelope,
        }) else {
            unreachable!()
        };
        row
    };
    let receipt = |code: &str| json!({"native_origin_receipt": {"reason_code": code}});
    // Each row stops before the advisories are read: this Guard home has none,
    // so reaching them would also answer `None`, and the assertions below
    // only pin the rows that must never get that far.
    for (status, envelope) in [
        ("approved", receipt("native_runtime_known_vulnerable")),
        ("pending", receipt("native_command_review_required")),
        (
            "pending",
            receipt("native_runtime_known_vulnerable_observed"),
        ),
        ("pending", Value::Null),
    ] {
        assert!(for_approval(&row(status, envelope), home.path()).is_none());
    }
    let stored = Value::String(receipt("native_runtime_known_vulnerable").to_string());
    assert_eq!(
        super::reason_code(&row("pending", stored)).as_deref(),
        Some("native_runtime_known_vulnerable")
    );
}
