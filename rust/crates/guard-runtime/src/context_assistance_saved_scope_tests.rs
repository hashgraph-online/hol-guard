//! Authenticated off-state scoped repair, with no interpreter or SDK installed.
use super::*;
use crate::policy_store::context_assistance_registry::switching::{scope_index, ScopeRemoval};
use guard_context_assistance::EvidenceScope;
use std::collections::BTreeSet;
fn pending(f: &Fixture) -> (String, String) {
    let cache = EvidenceCache::open(&f.home).unwrap();
    let mut keys = Vec::new();
    for app in ["codex", "dashboard"] {
        let key = EvidenceCache::key(app, &f.home, &"a".repeat(64)).unwrap();
        scope_index::remember(
            &f.home,
            &cache,
            &EvidenceScope::new(app, &f.home).unwrap(),
            &key,
        )
        .unwrap();
        drop(
            cache
                .open_slot(&key, 1, crate::context_assistance_data::now_ms())
                .unwrap(),
        );
        keys.push(key);
    }
    drop(
        ScopeRemoval::acquire(
            &f.home,
            &EvidenceScope::new("codex", &f.home).unwrap(),
            &BTreeSet::from(["a".repeat(64)]),
            Some(&cache),
        )
        .unwrap(),
    );
    (keys.remove(0), keys.remove(0))
}
#[test]
fn authenticated_resume_while_off_erases_only_the_pending_scope_and_preserves_preferences() {
    let f = Fixture::new();
    let (erased, other) = pending(&f);
    let prefs = std::fs::read(f.home.join("config.toml")).ok();
    let marker = std::fs::read(f.home.join("cigar-erasure.json")).unwrap();
    assert_eq!(
        f.ask_input("workspace", json!({"action":"resume_erasure"}))["code"],
        "native_context_assistance_workspace_input_invalid"
    );
    assert_eq!(
        std::fs::read(f.home.join("cigar-erasure.json")).unwrap(),
        marker
    );
    let done = result(f.ask_input("workspace_access", json!({"action":"resume_erasure"})));
    assert_eq!(done["resumed_erasure"], true);
    assert_eq!(done["cleared_saved"], false);
    assert_eq!(done["scope_erasure"]["removed_slots"], 1);
    assert_eq!(done["saved_evidence"]["status"], "saved");
    assert!(!f
        .home
        .join("context-assistance/saved-evidence")
        .join(erased)
        .exists());
    assert!(f
        .home
        .join("context-assistance/saved-evidence")
        .join(other)
        .exists());
    assert_eq!(std::fs::read(f.home.join("config.toml")).ok(), prefs);
    assert!(!f.home.join("cigar-erasure.json").exists());
    assert!(!f.home.join("context-assistance/installations").exists());
    for field in ["runtime", "last_check", "job"] {
        assert!(f.ask("status")["payload"]["state"][field].is_null());
    }
}
#[test]
fn interrupted_off_state_resume_retains_intent_until_explicit_retry_without_sdk_startup() {
    let f = Fixture::new();
    pending(&f);
    ScopeRemoval::fail_next_after_purge();
    assert_eq!(
        f.ask_input("workspace_access", json!({"action":"resume_erasure"}))["code"],
        "native_context_assistance_context_storage_outcome_unknown"
    );
    let marker = std::fs::read(f.home.join("cigar-erasure.json")).unwrap();
    let data = result(f.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["saved_evidence"]["status"], "repair_required");
    assert_eq!(
        std::fs::read(f.home.join("cigar-erasure.json")).unwrap(),
        marker
    );
    let done = result(f.ask_input("workspace_access", json!({"action":"resume_erasure"})));
    assert_eq!(done["scope_erasure"]["removed_slots"], 0);
    assert_eq!(done["resumed_erasure"], true);
    assert_eq!(done["saved_evidence"]["slots"], 1);
    assert!(!f.ask("status")["payload"]["state"]["effective_enabled"]
        .as_bool()
        .unwrap());
    assert!(!f.home.join("context-assistance/installations").exists());
}

#[test]
fn scoped_resume_uses_its_authenticated_intent_even_when_configuration_is_corrupt() {
    let f = Fixture::new();
    let (erased, other) = pending(&f);
    let broken = b"broken = [";
    std::fs::write(f.home.join("config.toml"), broken).unwrap();
    let done = result(f.ask_input("workspace_access", json!({"action":"resume_erasure"})));
    assert_eq!(done["resumed_erasure"], true);
    assert!(!f
        .home
        .join("context-assistance/saved-evidence")
        .join(erased)
        .exists());
    assert!(f
        .home
        .join("context-assistance/saved-evidence")
        .join(other)
        .exists());
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), broken);
    let state = f.store.context_assistance().status().unwrap();
    assert!(!state["effective_enabled"].as_bool().unwrap());
    assert!(state["runtime"].is_null());
    assert!(!f.home.join("context-assistance/installations").exists());
}
