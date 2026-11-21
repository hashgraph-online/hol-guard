use super::*;

#[test]
fn lost_config_and_health_acknowledgements_are_inspected_without_replaying_publication() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    crate::guard_config_update::io::fail_next_config_write_after_rename();
    assert!(owner
        .commit(&settings)
        .unwrap_err()
        .ends_with("commit_outcome_unknown"));
    let actual = fs::read(f.home.join("config.toml")).unwrap();
    owner.reconcile_committed("switch-test", &settings).unwrap();
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), actual);
    assert_eq!(owner.record().unwrap().current, pointer("new"));
    assert!(owner.record().unwrap().last_good.is_none());
    crate::guard_config_update::io::fail_next_lifecycle_record_after_rename();
    owner.finish_health("switch-test").unwrap();
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::Completed
    );
    assert_eq!(
        owner.record().unwrap().last_good.as_ref(),
        Some(&pointer("old"))
    );
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), actual);
}
#[test]
fn uncertain_config_commit_refuses_to_infer_success_after_an_external_edit() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    crate::guard_config_update::io::fail_next_config_write_after_rename();
    assert!(owner.commit(&settings).is_err());
    fs::OpenOptions::new()
        .append(true)
        .open(f.home.join("config.toml"))
        .unwrap()
        .write_all(b"\n# external edit following uncertain commit\n")
        .unwrap();
    let before = fs::read(f.home.join("config.toml")).unwrap();
    assert!(owner.reconcile_committed("switch-test", &settings).is_err());
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::CommitIntent
    );
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    settings.check_target_policy().unwrap();
    assert!(settings.check_target_exact().is_err());
}
#[test]
fn preflight_refuses_a_readonly_or_changed_config_before_any_stop_intent() {
    let f = Fixture::new(false);
    let (owner, settings) = f.begin();
    settings.preflight_publish().unwrap();
    let path = f.home.join("config.toml");
    let before = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(settings.preflight_publish().is_err());
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::Prepared
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n# changed before cutover\n")
        .unwrap();
    assert!(settings.preflight_publish().is_err());
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::Prepared
    );
}
