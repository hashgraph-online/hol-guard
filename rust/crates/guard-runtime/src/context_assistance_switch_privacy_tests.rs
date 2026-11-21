//! Repair and staging boundaries run without any CIGAR process or grant.
use super::*;

fn orphan(f: &Fixture, index: usize) -> PathBuf {
    f.home
        .join(format!(".cigar-lifecycle.json.9876.{index:032x}.tmp"))
}
fn private_file(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
#[test]
fn explicit_full_forget_waits_for_the_owner_and_repairs_corrupt_record_and_key() {
    let f = Fixture::new(false);
    let (owner, _) = f.begin();
    let before = fs::read(f.home.join("cigar-lifecycle.json")).unwrap();
    assert!(matches!(
        crate::context_assistance_data::remove(&f.home),
        Err(guard_context_assistance::RuntimeError::Busy)
    ));
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        before
    );
    drop(owner);
    fs::write(f.home.join("cigar-lifecycle.json"), b"{broken selection}").unwrap();
    fs::write(f.home.join("cigar-lifecycle.key"), [42; 32]).unwrap();
    let settings = fs::read(f.home.join("config.toml")).unwrap();
    crate::context_assistance_data::remove(&f.home).unwrap();
    assert!(!f.home.join("cigar-lifecycle.json").exists());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), settings);
    assert!(Owner::acquire(&f.home).unwrap().record().is_none());
}
#[test]
fn private_orphan_staging_is_bounded_and_unrelated_files_are_preserved() {
    let f = Fixture::new(false);
    let (mut owner, _) = f.begin();
    private_file(&orphan(&f, 1), b"partial metadata");
    let unrelated = f.home.join("operator-note.tmp");
    private_file(&unrelated, b"keep this exact text");
    owner.advance(SelectionPhase::StopIntent).unwrap();
    assert!(!orphan(&f, 1).exists());
    assert_eq!(fs::read(unrelated).unwrap(), b"keep this exact text");
}
#[test]
fn too_many_orphans_refuse_before_deleting_any_or_advancing_the_journal() {
    let f = Fixture::new(false);
    let (mut owner, _) = f.begin();
    for index in 0..33 {
        private_file(&orphan(&f, index), b"bounded partial");
    }
    let record = fs::read(f.home.join("cigar-lifecycle.json")).unwrap();
    assert!(owner.advance(SelectionPhase::StopIntent).is_err());
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        record
    );
    for index in 0..33 {
        assert!(orphan(&f, index).exists());
    }
}
#[test]
fn orphan_symlink_refuses_without_following_or_removing_its_target() {
    let f = Fixture::new(false);
    let (mut owner, _) = f.begin();
    let target = f.home.join("operator-document");
    private_file(&target, b"private unrelated text");
    std::os::unix::fs::symlink(&target, orphan(&f, 3)).unwrap();
    assert!(owner.advance(SelectionPhase::StopIntent).is_err());
    assert!(fs::symlink_metadata(orphan(&f, 3))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(target).unwrap(), b"private unrelated text");
}
#[test]
fn readonly_config_leaves_only_recoverable_intent_and_never_a_target_selection() {
    let f = Fixture::new(true);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    let path = f.home.join("config.toml");
    let original = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(owner.commit(&settings).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    drop(owner);
    let owner = Owner::acquire(&f.home).unwrap();
    assert_eq!(owner.record().unwrap().current, pointer("old"));
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::CommitIntent
    );
    assert_eq!(
        owner
            .record()
            .unwrap()
            .recovery("old", &settings.before_sha256(), true, false, true)
            .unwrap(),
        SelectionRecovery::PreservePrevious
    );
}
