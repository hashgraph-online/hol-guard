use super::*;
use guard_context_assistance::ContextAssistanceConfig;

fn saved_on(service: &Service) -> AssistanceSettings {
    let config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "selected".into(),
        ..Default::default()
    };
    let settings = AssistanceSettings {
        requested: config.clone(),
        effective: config,
        ..Default::default()
    };
    service.configure(settings.clone()).unwrap();
    settings
}

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "[context_assistance]\nenabled=true\nruntime_id='selected'\n",
    )
    .unwrap();
    home
}

#[test]
fn a_saved_opt_in_without_a_worker_reports_resting_not_off() {
    let service = Service::default();
    saved_on(&service);
    let fresh = service.status().unwrap();
    assert_eq!(fresh["requested_enabled"], true);
    assert_eq!(fresh["diagnostic"], "runtime_resting");
    for (error, expected) in [
        ("runtime_idle", "runtime_resting"),
        ("runtime_closed", "runtime_resting"),
        ("runtime_unverified", "runtime_unverified"),
    ] {
        lock(&service.state).unwrap().error = Some(error.into());
        assert_eq!(service.status().unwrap()["diagnostic"], expected, "{error}");
    }
    service.stop().unwrap();
    assert_ne!(service.status().unwrap()["diagnostic"], "runtime_resting");
}

#[test]
fn a_request_wakes_a_resting_opt_in_once_and_a_failed_start_stays_visible() {
    let home = home();
    let service = Service::default();
    saved_on(&service);
    lock(&service.state).unwrap().error = Some("runtime_idle".into());
    assert!(
        !service.wake(home.path(), |_| false),
        "an unused feature never starts the worker"
    );
    assert!(service.wake(home.path(), |_| true));
    assert!(
        !service.wake(home.path(), |_| true),
        "one attempt per retry window"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while service.status().unwrap()["job"].is_object() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = service.status().unwrap();
    assert_eq!(
        status["requested_enabled"], true,
        "waking never changes consent"
    );
    assert_eq!(status["effective_enabled"], false);
    assert!(status["diagnostic"].is_string());
    assert_ne!(status["diagnostic"], "runtime_resting");
    lock(&service.state).unwrap().woke = None;
    assert!(
        !service.wake(home.path(), |_| true),
        "a failed start is not retried automatically"
    );
}

#[test]
fn a_wake_and_a_click_share_one_pending_start() {
    let service = Service::default();
    saved_on(&service);
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut state = lock(&service.state).unwrap();
        state.pending = Some(Pending {
            id: state.generation,
            operation: Check::Activate,
            cancel: Arc::clone(&cancel),
        });
    }
    service
        .schedule(Check::Activate, "/not-opened".into())
        .unwrap();
    assert_eq!(
        service
            .schedule(Check::Recheck, "/not-opened".into())
            .unwrap_err(),
        "native_context_assistance_busy"
    );
    cancel.store(true, Ordering::Release);
    assert_eq!(
        service
            .schedule(Check::Activate, "/not-opened".into())
            .unwrap_err(),
        "native_context_assistance_busy"
    );
    assert!(!service.wake(std::path::Path::new("/not-opened"), |_| true));
}

#[test]
fn a_worker_that_stops_right_after_starting_is_shown_not_rested() {
    let service = Service::default();
    saved_on(&service);
    let mut state = lock(&service.state).unwrap();
    assert_eq!(wake::closed(&state), "runtime_closed", "never started here");
    state.started = Some(Instant::now());
    assert_eq!(wake::closed(&state), "runtime_crashed");
    state.error = Some(wake::closed(&state).into());
    assert!(!resting(&state), "a crash is never restarted automatically");
    state.started = Instant::now().checked_sub(Duration::from_secs(600));
    assert_eq!(
        wake::closed(&state),
        "runtime_closed",
        "a settled worker rests"
    );
}

#[test]
fn a_start_that_cannot_be_queued_is_shown_instead_of_resting() {
    let home = home();
    std::fs::write(home.path().join("cigar-erasure.json"), "{}").unwrap();
    let service = Service::default();
    saved_on(&service);
    assert!(!service.wake(home.path(), |_| true));
    let status = service.status().unwrap();
    assert_ne!(status["diagnostic"], "runtime_resting");
    assert_eq!(status["requested_enabled"], true, "consent is unchanged");
}

#[cfg(target_os = "macos")]
#[test]
fn a_command_hook_reaches_the_wake_only_for_resting_execution_context() {
    let service = Service::default();
    let mut settings = saved_on(&service);
    assert!(
        !service.execution_resting(),
        "execution context was never chosen"
    );
    settings.requested.features.execution_context = true;
    settings.requested.sources.native_policy_facts = true;
    settings.effective = settings.requested.clone();
    service.configure(settings).unwrap();
    assert!(service.execution_resting());
    lock(&service.state).unwrap().woke = Some(Instant::now());
    assert!(!service.execution_resting(), "one attempt per retry window");
    let guard = lock(&service.state).unwrap();
    assert!(
        !service.execution_resting(),
        "a busy service never blocks a hook"
    );
    drop(guard);
}
