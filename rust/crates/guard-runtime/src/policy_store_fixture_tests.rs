use super::{fixture_file, test_root};
use guard_policy_snapshot::EffectiveNativePolicyV3;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub(super) fn policy() -> EffectiveNativePolicyV3 {
    EffectiveNativePolicyV3 {
        protection_posture: "protected".into(),
        security_level: "balanced".into(),
        default_action: "warn".into(),
        unknown_publisher_action: "review".into(),
        changed_hash_action: "require-reapproval".into(),
        new_network_domain_action: "warn".into(),
        subprocess_action: "warn".into(),
        risk_actions: BTreeMap::new(),
        harness_risk_actions: BTreeMap::new(),
        harness_actions: BTreeMap::new(),
        publisher_actions: BTreeMap::new(),
        artifact_actions: BTreeMap::new(),
        mcp_tool_actions: BTreeMap::new(),
        sandbox_analysis: "off".into(),
        receipt_redaction_level: "full".into(),
    }
}

#[test]
fn fixture_rewrite_truncates_private_file_without_weakening_create_new() {
    let root = test_root("fixture-private-rewrite");
    let path = root.join("private.json");
    {
        let mut file = crate::resident_state::private_file(&path, true, &root).unwrap();
        file.write_all(b"original-long-fixture").unwrap();
    }
    fixture_file(&path, b"short");
    assert_eq!(fs::read(&path).unwrap(), b"short");

    // The production create-only contract must remain non-mutating. Fixing the
    // test writer must not reopen or truncate a pre-existing private object.
    assert!(crate::resident_state::private_file(&path, true, &root).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"short");

    fixture_file(&path, b"");
    assert!(fs::read(&path).unwrap().is_empty());
    #[cfg(windows)]
    crate::resident_state::verify_windows_private_path(&path, false, &root).unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(root).unwrap();
}
