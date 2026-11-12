use super::*;
use guard_cigar_release::{
    SelectionData, SelectionInstallation, SelectionOrigin, SelectionRecovery,
};
use guard_context_assistance::ContextAssistanceConfig;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn pointer(id: &str) -> SelectionPointer {
    SelectionPointer {
        runtime: SelectionInstallation {
            installation_id: id.into(),
            installation_sha256: "1".repeat(64),
            approval_sha256: "2".repeat(64),
            producer_sha256: "3".repeat(64),
            origin: SelectionOrigin::Enrolled {
                sdk_version: "0.14.1".into(),
                core_version: "0.14.0".into(),
                profile_id: "cigar-014".into(),
                adapter_id: "guard-cigar-python-sdk-v1".into(),
                adapter_revision: 1,
            },
        },
        data: SelectionData::Memory,
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    source: ContextAssistanceConfig,
}
impl Fixture {
    fn new(enabled: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let source = ContextAssistanceConfig {
            enabled,
            runtime_id: "old".into(),
            ..Default::default()
        };
        let text = format!(
            "# Operator comment remains\nupdate_channel = 'stable'\n{}",
            toml::to_string(&std::collections::BTreeMap::from([(
                "context_assistance",
                &source
            )]))
            .unwrap()
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(home.join("config.toml"))
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
        Self {
            _dir: dir,
            home,
            source,
        }
    }
    fn begin(&self) -> (Owner, SwitchSettings) {
        let settings = SwitchSettings::capture(&self.home, &self.source, "new").unwrap();
        let mut owner = Owner::acquire(&self.home).unwrap();
        owner.initialize(pointer("old")).unwrap();
        owner
            .begin(SelectionTransaction {
                request_id: "switch-test".into(),
                expected_service_generation: 4,
                before_settings_sha256: settings.before_sha256(),
                after_settings_sha256: settings.after_sha256(),
                source_semantic_sha256: "4".repeat(64),
                from: pointer("old"),
                to: pointer("new"),
                was_enabled: self.source.enabled,
                activate_target: self.source.enabled,
                reconnect_acknowledged: true,
                cancel_requested: false,
                phase: SelectionPhase::Prepared,
            })
            .unwrap();
        (owner, settings)
    }
}
#[test]
fn switch_owner_excludes_installer_and_interpreter_preparation_on_the_same_profile() {
    let f = Fixture::new(false);
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    let owner = Owner::acquire(&f.home).unwrap();
    assert!(preparation::lifecycle_lease(&f.home).is_err());
    assert!(Owner::acquire(&f.home).is_err());
    assert!(owner.record().is_none());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    drop(owner);
    assert!(preparation::lifecycle_lease(&f.home).is_ok());
}
#[test]
fn actual_config_commit_preserves_disabled_intent_and_promotes_last_good_only_after_health() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    let text = fs::read_to_string(f.home.join("config.toml")).unwrap();
    assert!(text.contains("# Operator comment remains\nupdate_channel = 'stable'"));
    let current = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert!(!current.requested.enabled);
    assert_eq!(current.requested.runtime_id, "new");
    assert_eq!(
        owner.record().unwrap().current.runtime.installation_id,
        "new"
    );
    assert!(owner.record().unwrap().last_good.is_none());
    owner.advance(SelectionPhase::Healthy).unwrap();
    owner.advance(SelectionPhase::Completed).unwrap();
    assert_eq!(
        owner.record().unwrap().last_good.as_ref(),
        Some(&pointer("old"))
    );
    drop(owner);
    let owner = Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::Completed
    );
}
#[test]
fn stop_committed_before_cutover_is_never_overwritten_or_reenabled() {
    let f = Fixture::new(true);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
    let stopped = fs::read(f.home.join("config.toml")).unwrap();
    assert!(owner.commit(&settings).is_err());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), stopped);
    assert_eq!(owner.record().unwrap().current, pointer("old"));
    let config = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert!(!config.requested.enabled);
    assert_eq!(
        owner
            .record()
            .unwrap()
            .recovery("old", &"8".repeat(64), false, false, false)
            .unwrap(),
        SelectionRecovery::PreserveDisabled(Box::new(pointer("old")))
    );
}
#[test]
fn changed_settings_or_locked_writer_refuses_before_selection_publication() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    let lock = WriteLock::acquire(&f.home).unwrap();
    assert!(owner.commit(&settings).is_err());
    drop(lock);
    fs::OpenOptions::new()
        .append(true)
        .open(f.home.join("config.toml"))
        .unwrap()
        .write_all(b"\n# later external edit\n")
        .unwrap();
    assert!(owner.commit(&settings).is_err());
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::StopIntent
    );
}
#[test]
fn unknown_record_rename_requires_reopen_and_never_replays_or_overwrites() {
    let f = Fixture::new(false);
    let (mut owner, _) = f.begin();
    crate::guard_config_update::io::fail_next_lifecycle_record_after_rename();
    assert_eq!(
        owner.advance(SelectionPhase::StopIntent).unwrap_err(),
        "native_context_assistance_switch_commit_outcome_unknown"
    );
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::Prepared
    );
    let actual = fs::read(f.home.join("cigar-lifecycle.json")).unwrap();
    assert!(owner.advance(SelectionPhase::Cancelled).is_err());
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        actual
    );
    drop(owner);
    let owner = Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::StopIntent
    );
}
#[test]
fn tampered_or_cross_profile_record_does_not_authenticate_and_reads_do_not_replace_it() {
    let f = Fixture::new(false);
    let (owner, _) = f.begin();
    drop(owner);
    let other = Fixture::new(false);
    fs::copy(
        f.home.join("cigar-lifecycle.key"),
        other.home.join("cigar-lifecycle.key"),
    )
    .unwrap();
    fs::copy(
        f.home.join("cigar-lifecycle.json"),
        other.home.join("cigar-lifecycle.json"),
    )
    .unwrap();
    assert!(Owner::acquire(&other.home).is_err());
    let path = f.home.join("cigar-lifecycle.json");
    let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    envelope["payload"] = json!(envelope["payload"]
        .as_str()
        .unwrap()
        .replace("\"revision\":2", "\"revision\":9"));
    let bytes = serde_json::to_vec(&envelope).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(Owner::acquire(&f.home).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
#[test]
fn missing_key_or_linked_or_public_record_refuses_without_repair() {
    let f = Fixture::new(false);
    let (owner, _) = f.begin();
    drop(owner);
    let key = fs::read(f.home.join("cigar-lifecycle.key")).unwrap();
    fs::remove_file(f.home.join("cigar-lifecycle.key")).unwrap();
    assert!(Owner::acquire(&f.home).is_err());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(f.home.join("cigar-lifecycle.key"))
        .unwrap();
    file.write_all(&key).unwrap();
    let path = f.home.join("cigar-lifecycle.json");
    fs::hard_link(&path, f.home.join("linked-record")).unwrap();
    assert!(Owner::acquire(&f.home).is_err());
    fs::remove_file(f.home.join("linked-record")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Owner::acquire(&f.home).is_err());
}
#[test]
fn readonly_record_is_not_replaced_by_an_atomic_write() {
    let f = Fixture::new(false);
    let (mut owner, _) = f.begin();
    let path = f.home.join("cigar-lifecycle.json");
    let old = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(owner.advance(SelectionPhase::StopIntent).is_err());
    assert_eq!(fs::read(&path).unwrap(), old);
}

#[path = "context_assistance_disabled_recovery_tests.rs"]
mod disabled_recovery;
#[path = "context_assistance_switch_erasure_tests.rs"]
mod erasure;
#[path = "context_assistance_switch_privacy_tests.rs"]
mod privacy;
#[path = "context_assistance_switch_publication_tests.rs"]
mod publication;
#[path = "context_assistance_switch_reconcile_tests.rs"]
mod reconciliation;
#[path = "context_assistance_switch_restore_tests.rs"]
mod restoration;
#[path = "context_assistance_switch_rollback_tests.rs"]
mod rollback;
#[path = "context_assistance_switch_scope_erasure_tests.rs"]
mod scope_erasure;
