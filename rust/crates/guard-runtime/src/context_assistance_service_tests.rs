use super::*;
use guard_context_assistance::ContextAssistanceConfig;

fn local(config: ContextAssistanceConfig) -> AssistanceSettings {
    AssistanceSettings {
        requested: config.clone(),
        effective: config,
        ..Default::default()
    }
}

#[test]
fn default_status_and_disabled_activation_do_not_inspect_or_launch_a_runtime() {
    let service = Service::default();
    let before = service.status().unwrap();
    assert_eq!(before["availability"], "off");
    assert_eq!(before["effective_enabled"], false);
    assert!(before["runtime"].is_null());
    assert!(before["job"].is_null());
    assert_eq!(
        service
            .schedule(Check::Activate, "/nonexistent/not-inspected".into())
            .unwrap_err(),
        "native_context_assistance_disabled"
    );
    assert_eq!(service.status().unwrap(), before);
}

#[test]
fn native_launch_fences_revoke_on_permission_change_stop_shutdown_and_owner_drop() {
    let service = Service::default();
    let initial = lock(&service.state).unwrap().epoch.fence();
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    service.configure(local(config.clone())).unwrap();
    assert!(!initial.is_current());
    let current = lock(&service.state).unwrap().epoch.fence();
    service.configure(local(config.clone())).unwrap();
    assert!(
        current.is_current(),
        "an identical read does not revoke consent"
    );
    let mut changed = config;
    changed.features.review_briefs = false;
    service.configure(local(changed)).unwrap();
    assert!(!current.is_current());
    let stopped = lock(&service.state).unwrap().epoch.fence();
    service.stop().unwrap();
    assert!(!stopped.is_current());
    let shut_down = lock(&service.state).unwrap().epoch.fence();
    service.shutdown();
    assert!(!shut_down.is_current());
    let dropped = lock(&service.state).unwrap().epoch.fence();
    drop(service);
    assert!(!dropped.is_current());
}

#[test]
fn stop_remains_off_across_old_disk_reads_until_persisted_opt_out_is_observed() {
    let service = Service::default();
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    service.configure(local(config.clone())).unwrap();
    let before_stop = service.configuration_generation().unwrap();
    service.stop().unwrap();
    service.configure(local(config.clone())).unwrap();
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
    let during_stop = service.configuration_generation().unwrap();
    assert_eq!(
        service
            .schedule(Check::Recheck, "/not-inspected".into())
            .unwrap_err(),
        "native_context_assistance_busy"
    );
    let mut off = config.clone();
    off.enabled = false;
    service.configure(local(off)).unwrap();
    assert_eq!(
        service
            .configure_at(local(config.clone()), during_stop)
            .unwrap_err(),
        "native_context_assistance_context_stale"
    );
    assert_eq!(
        service
            .configure_at(local(config.clone()), before_stop)
            .unwrap_err(),
        "native_context_assistance_context_stale"
    );
    assert_eq!(
        service.status().unwrap()["requested_enabled"],
        false,
        "an older read cannot re-enable after off has been persisted"
    );
    service.configure(local(config)).unwrap();
    assert_eq!(
        service.status().unwrap()["requested_enabled"],
        true,
        "a later explicit opt-in remains available after the saved off state"
    );
    assert_eq!(service.status().unwrap()["effective_enabled"], false);
}

#[test]
fn resident_shutdown_cancels_pending_jobs_and_permanently_closes_the_old_service() {
    let service = Service::default();
    let settings = local(ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    });
    service.configure(settings.clone()).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut state = lock(&service.state).unwrap();
        state.pending = Some(Pending {
            id: state.generation,
            operation: Check::Activate,
            cancel: Arc::clone(&cancel),
        });
    }
    service.shutdown();
    assert!(cancel.load(Ordering::Acquire));
    assert_eq!(service.status().unwrap()["effective_enabled"], false);
    assert_eq!(
        service.configure(settings.clone()).unwrap_err(),
        "native_context_assistance_shutdown"
    );
    assert_eq!(
        service
            .schedule(Check::Activate, "/not-opened".into())
            .unwrap_err(),
        "native_context_assistance_shutdown"
    );
    // A fresh resident has no verified runtime, session or source authority.
    let replacement = Service::default();
    replacement.configure(settings).unwrap();
    let recovered = replacement.status().unwrap();
    assert_eq!(recovered["effective_enabled"], false);
    assert!(recovered["runtime"].is_null());
    assert!(recovered["job"].is_null());
}

#[test]
fn permission_changes_cancel_pending_generation_and_do_not_allow_another_job_until_acknowledged() {
    let service = Service::default();
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    service.configure(local(config.clone())).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut state = lock(&service.state).unwrap();
        let generation = state.generation;
        state.pending = Some(Pending {
            id: generation,
            operation: Check::Activate,
            cancel: Arc::clone(&cancel),
        });
    }
    service.configure(local(config)).unwrap();
    assert!(!cancel.load(Ordering::Acquire));
    service.stop().unwrap();
    assert!(cancel.load(Ordering::Acquire));
    let status = service.status().unwrap();
    assert_eq!(status["availability"], "off");
    assert_eq!(status["effective_enabled"], false);
    assert_eq!(status["job"]["phase"], "cancelling");
    assert_eq!(
        service
            .schedule(Check::Recheck, "/nonexistent/not-inspected".into())
            .unwrap_err(),
        "native_context_assistance_busy"
    );
}

#[test]
#[cfg(not(unix))]
fn unqualified_private_persistence_cannot_silently_activate_a_graph_runtime() {
    let service = Service::default();
    let mut config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    config.features.agent_context = true;
    config.storage.mode = StorageMode::Sqlite;
    service.configure(local(config)).unwrap();
    assert_eq!(
        service
            .schedule(Check::Activate, "/not-inspected".into())
            .unwrap_err(),
        "native_context_assistance_persistence_unavailable"
    );
    assert!(service.status().unwrap()["job"].is_null());
}

#[test]
#[cfg(unix)]
fn private_storage_selection_cannot_invent_qualification_or_start_without_enrollment() {
    let home = tempfile::tempdir().unwrap();
    let service = Service::default();
    let mut config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    config.storage.mode = StorageMode::Sqlite;
    std::fs::write(home.path().join("config.toml"), "[context_assistance]\nenabled=true\nruntime_id='selected'\n[context_assistance.storage]\nmode='sqlite'\n").unwrap();
    service.configure(local(config)).unwrap();
    assert_eq!(service.status().unwrap()["effective_enabled"], false);
    service
        .schedule(Check::Activate, home.path().into())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while service.status().unwrap()["job"].is_object() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = service.status().unwrap();
    assert_eq!(status["effective_enabled"], false);
    assert!(status["runtime"].is_null());
    assert!(status["diagnostic"].is_string());
    assert!(!home.path().join("context-assistance").exists());
}

#[test]
fn managed_denial_preserves_local_intent_and_blocks_activation_before_runtime_io() {
    let service = Service::default();
    let requested = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    let mut effective = requested.clone();
    effective.enabled = false;
    effective.limits.context_tokens = 768;
    service
        .configure(AssistanceSettings {
            requested,
            effective,
            restriction: Some("managed_policy"),
            diagnostic: None,
            verification_permitted: false,
        })
        .unwrap();
    let status = service.status().unwrap();
    assert_eq!(status["requested_enabled"], true);
    assert_eq!(status["preferences"]["enabled"], true);
    assert_eq!(status["effective_preferences"]["enabled"], false);
    assert_eq!(
        status["effective_preferences"]["limits"]["context_tokens"],
        768
    );
    assert_eq!(status["effective_enabled"], false);
    assert_eq!(status["availability"], "unavailable");
    assert_eq!(status["diagnostic"], "policy_restricted");
    assert_eq!(status["verification_permitted"], false);
    assert_eq!(
        service
            .schedule(Check::Activate, "/never-inspected".into())
            .unwrap_err(),
        "native_context_assistance_disabled"
    );
    service.stop().unwrap();
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
    assert_eq!(
        service
            .schedule(Check::Recheck, "/never-inspected".into())
            .unwrap_err(),
        "native_context_assistance_policy_restricted"
    );
}

#[test]
fn hidden_local_permission_changes_invalidate_pending_generation_even_when_effective_scope_is_equal(
) {
    let service = Service::default();
    let mut settings = local(ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    });
    settings.requested.features.agent_context = true;
    service.configure(settings.clone()).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let before = service.status().unwrap()["generation"].clone();
    {
        let mut state = lock(&service.state).unwrap();
        state.pending = Some(Pending {
            id: state.generation,
            operation: Check::Activate,
            cancel: Arc::clone(&cancel),
        });
    }
    settings.requested.features.agent_context = false;
    service.configure(settings).unwrap();
    assert!(cancel.load(Ordering::Acquire));
    assert_ne!(service.status().unwrap()["generation"], before);
}
