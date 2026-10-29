//! Authentication, bounded history, and repair tests with no SDK startup.
use super::*;
use std::os::unix::fs::PermissionsExt;
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    cache: EvidenceCache,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = EvidenceCache::open(&home).unwrap();
        Self {
            _dir: dir,
            home,
            cache,
        }
    }
    fn add(&self, app: &str) -> String {
        let key = EvidenceCache::key(app, &self.home, &"a".repeat(64)).unwrap();
        let scope = EvidenceScope::new(app, &self.home).unwrap();
        remember(&self.home, &self.cache, &scope, &key).unwrap();
        drop(
            self.cache
                .open_slot(&key, 1, crate::context_assistance_data::now_ms())
                .unwrap(),
        );
        key
    }
}
#[test]
fn ownership_index_is_private_pathless_and_scoped_removal_preserves_other_apps() {
    let f = Fixture::new();
    let one = f.add("codex");
    let other = f.add("dashboard");
    let raw = fs::read(f.home.join("cigar-scopes.json")).unwrap();
    assert!(!String::from_utf8(raw)
        .unwrap()
        .contains(f.home.to_str().unwrap()));
    let before = fs::read(f.home.join("cigar-lifecycle.key")).unwrap();
    let scope = EvidenceScope::new("codex", &f.home).unwrap();
    let removal = ScopeRemoval::acquire(
        &f.home,
        &scope,
        &BTreeSet::from(["a".repeat(64)]),
        Some(&f.cache),
    )
    .unwrap();
    removal.remove(Some(&f.cache)).unwrap();
    assert!(!f.cache.slot_keys().unwrap().contains(&one));
    assert_eq!(f.cache.slot_keys().unwrap(), vec![other]);
    let owner = Owner::acquire(&f.home).unwrap();
    let rows = owners(&owner).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].scope_sha256,
        EvidenceScope::new("dashboard", &f.home)
            .unwrap()
            .namespace_sha256()
    );
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.key")).unwrap(),
        before
    );
}
#[test]
fn unknown_legacy_slots_refuse_before_intent_and_before_any_data_mutation() {
    let f = Fixture::new();
    let own = f.add("codex");
    let other = EvidenceCache::key("unindexed", &f.home, &"b".repeat(64)).unwrap();
    drop(
        f.cache
            .open_slot(&other, 1, crate::context_assistance_data::now_ms())
            .unwrap(),
    );
    let scope = EvidenceScope::new("codex", &f.home).unwrap();
    assert!(matches!(
        ScopeRemoval::acquire(
            &f.home,
            &scope,
            &BTreeSet::from(["a".repeat(64)]),
            Some(&f.cache)
        ),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert!(DataRemoval::check_clear(&f.home).is_ok());
    assert_eq!(f.cache.summary().unwrap().slots, 2);
    assert!(f.cache.slot_keys().unwrap().contains(&own));
}
#[test]
fn corrupt_or_copied_index_refuses_without_reclassification_or_key_regeneration() {
    let f = Fixture::new();
    f.add("codex");
    let path = f.home.join("cigar-scopes.json");
    let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut payload: Value = serde_json::from_str(envelope["payload"].as_str().unwrap()).unwrap();
    payload["owners"][0]["scope_sha256"] = json!("f".repeat(64));
    envelope["payload"] = json!(serde_json::to_string(&payload).unwrap());
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let before = fs::read(&path).unwrap();
    let scope = EvidenceScope::new("codex", &f.home).unwrap();
    assert!(remember(&f.home, &f.cache, &scope, &f.cache.slot_keys().unwrap()[0]).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(validate_present(&f.home).is_err());
    fs::remove_file(f.home.join("cigar-lifecycle.key")).unwrap();
    assert!(remember(&f.home, &f.cache, &scope, &f.cache.slot_keys().unwrap()[0]).is_err());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    let source = Fixture::new();
    source.add("codex");
    fs::write(
        &path,
        fs::read(source.home.join("cigar-scopes.json")).unwrap(),
    )
    .unwrap();
    fs::write(
        f.home.join("cigar-lifecycle.key"),
        fs::read(source.home.join("cigar-lifecycle.key")).unwrap(),
    )
    .unwrap();
    assert!(validate_present(&f.home).is_err());
    assert_eq!(f.cache.summary().unwrap().slots, 1);
}
#[test]
fn repeated_new_workspaces_do_not_grow_attribution_history_or_create_a_selection() {
    let f = Fixture::new();
    for n in 0..80 {
        for key in f.cache.slot_keys().unwrap() {
            f.cache.forget(&key).unwrap();
        }
        f.add(&format!("app{n}"));
        let owner = Owner::acquire(&f.home).unwrap();
        assert_eq!(owners(&owner).unwrap().len(), 1);
        assert!(owner.record().is_none());
    }
    assert!(!f.home.join("config.toml").exists());
}
#[test]
fn current_data_index_does_not_allow_new_rows_while_an_erasure_intent_is_pending() {
    let f = Fixture::new();
    f.add("codex");
    let scope = EvidenceScope::new("codex", &f.home).unwrap();
    drop(
        ScopeRemoval::acquire(
            &f.home,
            &scope,
            &BTreeSet::from(["a".repeat(64)]),
            Some(&f.cache),
        )
        .unwrap(),
    );
    let raw = fs::read(f.home.join("cigar-scopes.json")).unwrap();
    let another = EvidenceScope::new("dashboard", &f.home).unwrap();
    let key = EvidenceCache::key("dashboard", &f.home, &"a".repeat(64)).unwrap();
    assert!(remember(&f.home, &f.cache, &another, &key).is_err());
    assert_eq!(fs::read(f.home.join("cigar-scopes.json")).unwrap(), raw);
    ScopeRemoval::resume(&f.home)
        .unwrap()
        .remove(Some(&f.cache))
        .unwrap();
    assert_eq!(f.cache.summary().unwrap().slots, 0);
}
