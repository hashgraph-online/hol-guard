//! A machine policy governs this runtime only when the machine itself vouches
//! for it: an administrator-owned file, read under the byte cap, in one of the
//! two serialisations macOS and Linux deliver. Everything else that is still
//! configured has to fail closed, because an unmanaged default would be a
//! quieter policy than the administrator installed.

use super::*;

use crate::managed_policy::POLICY_SCHEMA_VERSION;
use serde_json::json;
use tempfile::TempDir;

fn policy_document() -> Value {
    json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
        "requiredHarnesses": ["claude-code"],
    })
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent");
    }
    fs::write(path, bytes).expect("write");
}

/// A source whose machine paths live under a directory the test owns. Nothing
/// below it is root-owned, so the trust walk refuses it exactly as it refuses a
/// profile an unprivileged account dropped on a real machine.
fn rooted(root: &TempDir, system: MachineSystem) -> ManagedPolicySource {
    ManagedPolicySource {
        system,
        policy_path: None,
        write_cache: true,
        machine_root: Some(root.path().to_path_buf()),
    }
}

fn explicit(path: &Path) -> ManagedPolicySource {
    ManagedPolicySource {
        system: MachineSystem::Other,
        policy_path: Some(path.to_path_buf()),
        write_cache: true,
        machine_root: None,
    }
}

#[test]
fn an_explicit_document_loads_as_the_machine_policy() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("managed-policy.json");
    write(&path, policy_document().to_string().as_bytes());

    let state = load_managed_policy(&explicit(&path));

    assert_eq!(state.status, ManagedPolicyStatus::Active);
    assert_eq!(state.source, path.to_string_lossy());
    assert_eq!(state.reason_code, None);
    let policy = state.policy.expect("policy");
    assert_eq!(policy.settings["mode"], json!("enforce"));
    assert!(policy.locked_settings.contains("mode"));
}

#[test]
fn an_explicit_plist_loads_as_the_same_policy() {
    let root = TempDir::new().expect("tempdir");
    let json_path = root.path().join("managed-policy.json");
    let plist_path = root.path().join("org.hol.guard.plist");
    write(&json_path, policy_document().to_string().as_bytes());
    write(
        &plist_path,
        br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>schemaVersion</key>
	<string>hol-guard-mdm-policy.v1</string>
	<key>settings</key>
	<dict>
		<key>mode</key>
		<string>enforce</string>
	</dict>
	<key>lockedSettings</key>
	<array>
		<string>mode</string>
	</array>
	<key>requiredHarnesses</key>
	<array>
		<string>claude-code</string>
	</array>
</dict>
</plist>
"#,
    );

    let from_plist = load_managed_policy(&explicit(&plist_path));
    let from_json = load_managed_policy(&explicit(&json_path));

    assert_eq!(from_plist.status, ManagedPolicyStatus::Active);
    // The content hash covers the document, so the two serialisations of one
    // policy are one policy.
    assert_eq!(from_plist.policy, from_json.policy);
}

#[test]
fn a_policy_that_cannot_be_read_as_one_is_invalid_with_its_reason() {
    let root = TempDir::new().expect("tempdir");
    let broken = root.path().join("broken.json");
    write(&broken, b"{\"schemaVersion\": ");
    let unsupported = root.path().join("unsupported.json");
    write(
        &unsupported,
        br#"{"schemaVersion": "hol-guard-mdm-policy.v2"}"#,
    );

    let torn = load_managed_policy(&explicit(&broken));
    assert_eq!(torn.status, ManagedPolicyStatus::Invalid);
    assert_eq!(torn.reason_code, Some("managed_policy_invalid"));
    assert!(
        torn.detail
            .as_deref()
            .expect("detail")
            .starts_with("managed policy is not valid JSON"),
        "{:?}",
        torn.detail
    );

    let refused = load_managed_policy(&explicit(&unsupported));
    assert_eq!(refused.status, ManagedPolicyStatus::Invalid);
    assert_eq!(
        refused.detail.as_deref(),
        Some("unsupported managed policy schema")
    );
    assert!(refused.policy.is_none(), "a refused document is not policy");
}

#[test]
fn a_document_past_the_byte_cap_is_never_parsed() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("huge.json");
    let mut document = policy_document();
    document["settings"]["mode"] = json!("e".repeat(MAX_POLICY_BYTES as usize + 1));
    write(&path, document.to_string().as_bytes());

    let state = load_managed_policy(&explicit(&path));

    assert_eq!(state.status, ManagedPolicyStatus::Invalid);
    assert_eq!(
        state.detail.as_deref(),
        Some("managed policy exceeds size limit")
    );
}

#[test]
fn a_missing_explicit_path_carries_no_authority() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("absent.json");

    let state = load_managed_policy(&explicit(&path));

    assert_eq!(state.status, ManagedPolicyStatus::Absent);
    assert_eq!(state.reason_code, Some("managed_policy_absent"));
    assert!(
        !state.status.fails_closed(),
        "no authority to fail closed on"
    );
}

#[test]
fn a_profile_the_machine_does_not_own_is_not_authority() {
    let root = TempDir::new().expect("tempdir");
    let source = rooted(&root, MachineSystem::Other);
    let native = source.native_policy_path().expect("native path");
    write(&native, policy_document().to_string().as_bytes());

    let state = load_managed_policy(&source);

    // The document is valid; the path is not root-owned, so it is refused
    // before it is read rather than applied as machine authority.
    assert_eq!(state.status, ManagedPolicyStatus::Tampered);
    assert_eq!(state.reason_code, Some("managed_policy_source_tampered"));
    assert_eq!(state.source, native.to_string_lossy());
    assert!(state.policy.is_none());
    assert!(state.status.fails_closed());
}

/// Root reads a directory whose mode forbids it, so the one machine that
/// cannot reproduce an unreadable profile is one running as root.
#[test]
#[cfg(unix)]
fn an_unreadable_profile_directory_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    if administrator_context(MachineSystem::Other) {
        return;
    }
    let root = TempDir::new().expect("tempdir");
    let source = rooted(&root, MachineSystem::Other);
    let native = source.native_policy_path().expect("native path");
    let parent = native.parent().expect("parent");
    fs::create_dir_all(parent).expect("parent");
    let mut blocked = fs::metadata(parent).expect("metadata").permissions();
    blocked.set_mode(0o000);
    fs::set_permissions(parent, blocked).expect("block");

    let state = load_managed_policy(&source);

    let mut restored = fs::metadata(parent).expect("metadata").permissions();
    restored.set_mode(0o755);
    fs::set_permissions(parent, restored).expect("restore");
    assert_eq!(state.status, ManagedPolicyStatus::Inaccessible);
    assert_eq!(state.reason_code, Some("managed_policy_inaccessible"));
    assert!(state.status.fails_closed());
}

#[test]
fn no_profile_and_no_cache_is_an_unmanaged_machine() {
    let root = TempDir::new().expect("tempdir");
    let source = rooted(&root, MachineSystem::Other);

    let state = load_managed_policy(&source);

    assert_eq!(state.status, ManagedPolicyStatus::Absent);
    assert_eq!(state.reason_code, Some("managed_policy_absent"));
    assert_eq!(
        state.source,
        source
            .native_policy_path()
            .expect("native path")
            .to_string_lossy()
    );
}

#[test]
fn a_cache_the_machine_does_not_own_is_not_promoted_into_authority() {
    let root = TempDir::new().expect("tempdir");
    let source = rooted(&root, MachineSystem::Other);
    let cache = source.cache_path();
    write(&cache, policy_document().to_string().as_bytes());

    let state = load_managed_policy(&source);

    // A removed profile falls back to the cache, and a cache this account could
    // have written is a tampered source, not the policy it claims to hold.
    assert_eq!(state.status, ManagedPolicyStatus::Tampered);
    assert_eq!(state.reason_code, Some("managed_policy_cache_tampered"));
    assert_eq!(state.source, cache.to_string_lossy());
    assert!(state.policy.is_none());
}

#[test]
fn an_unprivileged_load_writes_no_cache_to_distrust_later() {
    let root = TempDir::new().expect("tempdir");
    let source = rooted(&root, MachineSystem::Other);
    let explicit_path = root.path().join("managed-policy.json");
    write(&explicit_path, policy_document().to_string().as_bytes());

    load_managed_policy(&explicit(&explicit_path));
    load_managed_policy(&source);

    assert!(
        !source.cache_path().exists(),
        "a cache written without administrator rights would only be refused"
    );
}

#[test]
fn a_windows_machine_fails_closed_on_the_registry_it_cannot_read() {
    let root = TempDir::new().expect("tempdir");
    let source = rooted(&root, MachineSystem::Windows);

    let state = load_managed_policy(&source);

    assert_eq!(state.status, ManagedPolicyStatus::Inaccessible);
    assert_eq!(
        state.reason_code,
        Some("managed_policy_registry_unreadable")
    );
    assert_eq!(state.source, r"HKLM\Software\Policies\HOL\Guard");
    assert!(
        state.status.fails_closed(),
        "configured authority this runtime cannot read is not an absent policy"
    );
}

#[test]
fn the_machine_paths_are_the_ones_the_platform_installs_to() {
    assert_eq!(
        MachineSystem::Darwin.policy_path().expect("darwin"),
        Path::new("/Library/Managed Preferences/org.hol.guard.plist")
    );
    assert_eq!(
        MachineSystem::Darwin.cache_path(),
        Path::new("/Library/Application Support/HOL Guard State/managed-policy-cache.json")
    );
    assert_eq!(
        MachineSystem::Other.policy_path().expect("other"),
        Path::new("/etc/hol-guard/managed-policy.json")
    );
    assert_eq!(
        MachineSystem::Other.cache_path(),
        Path::new("/var/lib/hol-guard/managed-policy-cache.json")
    );
    // Windows authority is a registry key, so there is no file to read.
    assert_eq!(MachineSystem::Windows.policy_path(), None);
}

#[test]
fn every_status_but_absent_and_active_fails_closed() {
    for status in [
        ManagedPolicyStatus::Invalid,
        ManagedPolicyStatus::Inaccessible,
        ManagedPolicyStatus::Tampered,
    ] {
        assert!(status.fails_closed(), "{}", status.as_str());
    }
    assert!(!ManagedPolicyStatus::Absent.fails_closed());
    assert!(!ManagedPolicyStatus::Active.fails_closed());
    assert_eq!(ManagedPolicyStatus::Active.as_str(), "active");
    assert_eq!(ManagedPolicyStatus::Tampered.as_str(), "tampered");
}
