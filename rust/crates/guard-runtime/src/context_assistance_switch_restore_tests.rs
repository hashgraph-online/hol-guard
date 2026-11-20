use super::*;

#[test]
fn an_unchanged_readonly_source_is_restored_without_replacing_the_config_file() {
    let f = Fixture::new(true);
    let (mut owner, settings) = f.begin();
    let path = f.home.join("config.toml");
    let original = fs::read(&path).unwrap();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(owner.commit(&settings).is_err());
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::CommitIntent
    );
    owner.restore_source("switch-test", &settings).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    owner.finish_restore("switch-test", &settings).unwrap();
    owner.finish_restore("switch-test", &settings).unwrap();
    assert_eq!(owner.record().unwrap().current, pointer("old"));
    assert!(owner.record().unwrap().last_good.is_none());
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::RolledBack
    );
}
#[test]
fn unpublished_target_health_can_restore_exact_source_preferences_and_previous_last_good() {
    let f = Fixture::new(true);
    let (mut owner, settings) = f.begin();
    let original = fs::read(f.home.join("config.toml")).unwrap();
    let mut recorded = owner.record().unwrap().clone();
    recorded.last_good = Some(pointer("older"));
    {
        let lock = WriteLock::acquire(&f.home).unwrap();
        owner.publish_locked(&lock, recorded).unwrap();
    }
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("switch-test").unwrap();
    owner.restore_source("switch-test", &settings).unwrap();
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), original);
    owner.finish_restore("switch-test", &settings).unwrap();
    assert_eq!(owner.record().unwrap().current, pointer("old"));
    assert_eq!(
        owner.record().unwrap().last_good.as_ref(),
        Some(&pointer("older"))
    );
    // Publication is the dividing line: an attached target requires an
    // explicit rollback job rather than automatic revival of a past selection.
    drop(owner);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("switch-test").unwrap();
    owner.complete_publication("switch-test").unwrap();
    assert!(owner.restore_source("switch-test", &settings).is_err());
    assert_eq!(owner.record().unwrap().current, pointer("new"));
}
#[test]
fn edits_stop_disabled_sources_and_changed_authentication_never_authorize_restoration() {
    for kind in ["comment", "stop", "key", "record", "disabled"] {
        let f = Fixture::new(kind != "disabled");
        let (mut owner, settings) = f.begin();
        owner.advance(SelectionPhase::StopIntent).unwrap();
        owner.commit(&settings).unwrap();
        match kind {
            "comment" => {
                let p = f.home.join("config.toml");
                let mut t = fs::read_to_string(&p).unwrap();
                t.push_str("\n# changed independently\n");
                fs::write(p, t).unwrap();
            }
            "stop" => {
                crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
            }
            "key" => {
                fs::write(f.home.join("cigar-lifecycle.key"), [19_u8; 32]).unwrap();
            }
            "record" => {
                fs::write(f.home.join("cigar-lifecycle.json"), b"{}").unwrap();
            }
            "disabled" => {}
            _ => unreachable!(),
        }
        let before = fs::read(f.home.join("config.toml")).unwrap();
        assert!(
            owner.restore_source("switch-test", &settings).is_err(),
            "{kind}"
        );
        assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    }
}
