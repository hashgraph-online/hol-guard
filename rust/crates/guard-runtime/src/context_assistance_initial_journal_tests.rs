//! Synthetic native filesystem transitions, not SDK acceptance.
use super::super::tests::{home, intent};
use super::*;
use guard_context_assistance::{ContextAssistanceConfig, EvidenceCache, StorageMode};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

struct Fixture {
    owner: Owner,
    settings: SwitchSettings,
    proof: empty::EmptyDataProof,
    plan: InitialSelection,
    before: Vec<u8>,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let dir = home();
        let path = dir.path().canonicalize().unwrap();
        let mut source = ContextAssistanceConfig::default();
        source.storage.mode = StorageMode::Sqlite;
        let text = format!(
            "# Keep operator preferences\nmode='enforce'\ndesktop_notifications=false\n{}",
            toml::to_string(&std::collections::BTreeMap::from([(
                "context_assistance",
                &source
            )]))
            .unwrap()
        );
        fs::write(path.join("config.toml"), text).unwrap();
        fs::set_permissions(path.join("config.toml"), fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(path.join("config.toml")).unwrap();
        let settings = SwitchSettings::capture(&path, &source, "first-sdk").unwrap();
        let owner = Owner::acquire(&path).unwrap();
        let proof = empty::EmptyDataProof::capture(&owner).unwrap();
        let mut plan = intent();
        plan.before_settings_sha256 = settings.before_sha256();
        plan.after_settings_sha256 = settings.after_sha256();
        plan.empty_data_sha256 = proof.sha256().into();
        Self {
            owner,
            settings,
            proof,
            plan,
            before,
            dir,
        }
    }
    fn begin(&mut self) {
        self.owner
            .begin_initial(self.plan.clone(), &self.settings, &self.proof)
            .unwrap();
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.dir.path().join("config.toml")).unwrap()
    }
}
#[test]
fn initial_commit_selects_only_the_target_and_stays_off_without_a_last_good_or_previous_pointer() {
    let mut f = Fixture::new();
    f.begin();
    assert!(f.owner.record().is_none());
    assert_eq!(f.bytes(), f.before);
    f.owner
        .commit_initial("first", &f.settings, &f.proof)
        .unwrap();
    assert_eq!(
        f.owner.initial_record().unwrap().phase,
        InitialPhase::Committed
    );
    assert!(f.owner.check_initial_clear().is_err());
    let record = f.owner.record().unwrap();
    assert_eq!(record.current, f.plan.target);
    assert!(record.last_good.is_none());
    assert!(record.transaction.is_none());
    let current = crate::guard_config_load::context_assistance_config(f.dir.path()).unwrap();
    assert_eq!(current.requested.runtime_id, "first-sdk");
    assert!(!current.requested.enabled);
    assert!(!current.effective.enabled);
    assert_eq!(current.requested.storage.mode, StorageMode::Sqlite);
    let raw: String = String::from_utf8(f.bytes()).unwrap();
    assert!(raw.contains("# Keep operator preferences"));
    assert!(raw.contains("desktop_notifications=false"));
    f.owner.mark_initial_healthy("first").unwrap();
    assert!(f.owner.check_initial_clear().is_err());
    f.owner.complete_initial("first").unwrap();
    f.owner.complete_initial("first").unwrap();
    f.owner.check_initial_clear().unwrap();
    assert!(!f.dir.path().join("cigar-scopes.json").exists());
}
#[test]
fn cancelling_after_an_already_off_stop_preserves_its_stronger_intent_and_no_selection() {
    let mut f = Fixture::new();
    f.begin();
    crate::guard_config_update::disable_context_assistance(f.dir.path()).unwrap();
    let stopped = f.bytes();
    assert_ne!(stopped, f.before);
    f.owner.cancel_initial("first").unwrap();
    assert_eq!(f.bytes(), stopped);
    assert!(f.owner.record().is_none());
    assert_eq!(
        f.owner.initial_record().unwrap().phase,
        InitialPhase::Cancelled
    );
    f.owner.check_initial_clear().unwrap();
    assert!(!f.dir.path().join("cigar-lifecycle.json").exists());
}
#[test]
fn data_appearing_after_preparation_refuses_commit_and_is_never_swept_or_discarded() {
    let mut f = Fixture::new();
    f.begin();
    let cache = EvidenceCache::open(&f.owner.home).unwrap();
    let key = "8".repeat(64);
    let slot = cache.open_slot(&key, 1, jobs::now().unwrap()).unwrap();
    drop(slot);
    drop(cache);
    assert!(f
        .owner
        .commit_initial("first", &f.settings, &f.proof)
        .unwrap_err()
        .ends_with("initial_selection_data_choice_required"));
    assert_eq!(f.bytes(), f.before);
    assert!(f.owner.record().is_none());
    assert_eq!(
        f.owner.initial_record().unwrap().phase,
        InitialPhase::Prepared
    );
    let cache = EvidenceCache::existing(&f.owner.home).unwrap().unwrap();
    assert_eq!(cache.slot_keys().unwrap(), vec![key]);
    drop(cache);
    assert!(f
        .owner
        .cancel_initial("first")
        .unwrap_err()
        .ends_with("initial_selection_data_choice_required"));
}
#[test]
fn uncertain_config_rename_is_reconciled_without_rewriting_config_or_inventing_a_source() {
    let mut f = Fixture::new();
    f.begin();
    crate::guard_config_update::io::fail_next_config_write_after_rename();
    assert!(f
        .owner
        .commit_initial("first", &f.settings, &f.proof)
        .unwrap_err()
        .ends_with("switch_commit_outcome_unknown"));
    let after = f.bytes();
    let inode = fs::metadata(f.dir.path().join("config.toml"))
        .unwrap()
        .ino();
    assert!(f.owner.record().is_none());
    assert!(f.owner.check_initial_clear().is_err());
    let proof = empty::EmptyDataProof::capture_for_initial(&f.owner, "first").unwrap();
    f.owner
        .reconcile_initial_committed("first", &f.settings, &proof, &f.plan.target)
        .unwrap();
    assert_eq!(f.bytes(), after);
    assert_eq!(
        fs::metadata(f.dir.path().join("config.toml"))
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(f.owner.record().unwrap().current, f.plan.target);
    assert_eq!(
        f.owner.initial_record().unwrap().phase,
        InitialPhase::Committed
    );
}
#[test]
fn uncertain_first_record_rename_can_reopen_the_owner_and_recover_only_the_exact_target() {
    let mut f = Fixture::new();
    f.begin();
    crate::guard_config_update::io::fail_next_lifecycle_record_after_rename();
    assert!(f
        .owner
        .commit_initial("first", &f.settings, &f.proof)
        .unwrap_err()
        .ends_with("switch_commit_outcome_unknown"));
    let after = f.bytes();
    drop(f.owner);
    f.owner = Owner::acquire(f.dir.path()).unwrap();
    assert!(f.owner.check_initial_clear().is_err());
    assert_eq!(f.owner.record().unwrap().current, f.plan.target);
    let proof = empty::EmptyDataProof::capture_for_initial(&f.owner, "first").unwrap();
    let mut wrong = f.plan.target.clone();
    wrong.runtime.producer_sha256 = "9".repeat(64);
    assert!(f
        .owner
        .reconcile_initial_committed("first", &f.settings, &proof, &wrong)
        .is_err());
    assert_eq!(f.bytes(), after);
    f.owner
        .reconcile_initial_committed("first", &f.settings, &proof, &f.plan.target)
        .unwrap();
    assert_eq!(f.bytes(), after);
    f.owner.mark_initial_healthy("first").unwrap();
    f.owner.complete_initial("first").unwrap();
    assert!(f.owner.record().unwrap().last_good.is_none());
}
#[test]
fn empty_data_proof_and_target_binding_cannot_be_substituted_from_another_profile() {
    let mut a = Fixture::new();
    let b = Fixture::new();
    assert_ne!(a.proof.sha256(), b.proof.sha256());
    assert!(a
        .owner
        .begin_initial(a.plan.clone(), &a.settings, &b.proof)
        .is_err());
    assert!(a.owner.initial_record().is_none());
    assert_eq!(a.bytes(), a.before);
    let mut wrong = a.plan.clone();
    wrong.target.runtime.installation_id = "unrelated".into();
    assert!(a.owner.begin_initial(wrong, &a.settings, &a.proof).is_err());
    assert!(a.owner.initial_record().is_none());
}
#[test]
fn replacing_the_profile_directory_cannot_rebind_an_inflight_initial_owner_or_empty_proof() {
    let f = Fixture::new();
    let profile = f.dir.path().join("profile");
    fs::create_dir(&profile).unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(profile.join("config.toml"), &f.before).unwrap();
    let mut owner = Owner::acquire(&profile).unwrap();
    let proof = empty::EmptyDataProof::capture(&owner).unwrap();
    let source = crate::guard_config_load::context_assistance_config(&profile)
        .unwrap()
        .effective;
    let settings = SwitchSettings::capture(&profile, &source, "first-sdk").unwrap();
    let mut plan = f.plan.clone();
    plan.empty_data_sha256 = proof.sha256().into();
    plan.before_settings_sha256 = settings.before_sha256();
    plan.after_settings_sha256 = settings.after_sha256();
    fs::rename(&profile, f.dir.path().join("previous-profile")).unwrap();
    fs::create_dir(&profile).unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(profile.join("config.toml"), &f.before).unwrap();
    assert!(owner.begin_initial(plan, &settings, &proof).is_err());
    assert!(owner.reload().is_err());
    assert_eq!(fs::read(profile.join("config.toml")).unwrap(), f.before);
    assert!(!profile.join("cigar-lifecycle.key").exists());
    assert!(!profile.join("cigar-initial-selection.json").exists());
}

fn recovery_job(f: &Fixture) -> jobs::SwitchJob {
    let mut job = jobs::SwitchJob::new_initial(jobs::SwitchRequest {
        job_id: f.plan.request_id.clone(),
        target_runtime_id: f.plan.target.runtime.installation_id.clone(),
        expected_generation: f.plan.expected_service_generation,
        rollback: false,
    })
    .unwrap();
    jobs::save(
        &f.owner.home,
        &mut job,
        jobs::JobPhase::RecoveryRequired,
        "recovery_required",
    )
    .unwrap();
    job
}
#[test]
fn recovery_admission_binds_target_generation_and_empty_data_without_rewriting_preferences() {
    let mut f = Fixture::new();
    f.begin();
    f.owner
        .commit_initial("first", &f.settings, &f.proof)
        .unwrap();
    let before = f.bytes();
    let job = recovery_job(&f);
    let (target, proof, attempt) = f.owner.begin_initial_recovery(&job, 9).unwrap();
    assert_eq!(attempt.request.expected_generation, 1);
    assert_eq!(attempt.recovery.as_ref().unwrap().expected_generation, 9);
    assert_eq!(f.bytes(), before);
    let mut wrong = f.plan.target.clone();
    wrong.runtime.producer_sha256 = "f".repeat(64);
    assert!(f
        .owner
        .recover_initial_target("first", &target, &proof, &wrong)
        .is_err());
    assert_eq!(
        f.owner.initial_record().unwrap().phase,
        InitialPhase::Committed
    );
    f.owner
        .recover_initial_target("first", &target, &proof, &f.plan.target)
        .unwrap();
    f.owner.mark_initial_healthy("first").unwrap();
    f.owner.complete_initial("first").unwrap();
    f.owner.reconcile_initial_job(&attempt).unwrap();
    assert_eq!(f.bytes(), before);
    assert!(f.owner.record().unwrap().last_good.is_none());
    assert!(f.owner.record().unwrap().transaction.is_none());
    assert!(!f.owner.home.join("cigar-scopes.json").exists());
    assert_eq!(
        jobs::get(&f.owner.home, "first").unwrap().unwrap().phase,
        jobs::JobPhase::Completed
    );
}
#[test]
fn stronger_off_preferences_or_new_saved_data_refuse_recovery_without_discarding_either() {
    for add_data in [false, true] {
        let mut f = Fixture::new();
        f.begin();
        f.owner
            .commit_initial("first", &f.settings, &f.proof)
            .unwrap();
        let job = recovery_job(&f);
        let (target, proof, _) = f.owner.begin_initial_recovery(&job, 9).unwrap();
        if add_data {
            let cache = EvidenceCache::open(&f.owner.home).unwrap();
            let slot = cache
                .open_slot(&"8".repeat(64), 1, jobs::now().unwrap())
                .unwrap();
            drop(slot);
            drop(cache);
        } else {
            crate::guard_config_update::disable_context_assistance(&f.owner.home).unwrap();
        }
        let before = f.bytes();
        assert!(f
            .owner
            .recover_initial_target("first", &target, &proof, &f.plan.target)
            .is_err());
        assert_eq!(f.bytes(), before);
        assert_eq!(
            f.owner.initial_record().unwrap().phase,
            InitialPhase::Committed
        );
        assert!(f.owner.check_initial_clear().is_err());
        if add_data {
            assert_eq!(
                EvidenceCache::existing(&f.owner.home)
                    .unwrap()
                    .unwrap()
                    .summary()
                    .unwrap()
                    .slots,
                1
            );
        }
    }
}
