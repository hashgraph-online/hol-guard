//! The existing bounded job/lease owns all temporary SDKs through cleanup.
use super::*;
use std::sync::mpsc::Receiver;

fn discard_owned_preparation(owner: &mut switching::Owner, id: &str) -> Result<(), String> {
    owner.reload()?;
    if let Some(t) = owner.record().and_then(|r| r.transaction.as_ref()) {
        if t.request_id == id {
            owner.cancel_precommit(id)?;
        } else if !t.phase.terminal() {
            return Err(error("switch_recovery_required"));
        }
    }
    owner.discard_job_data(id).map(|_| ())
}

pub(super) fn run(
    shared: Weak<Mutex<State>>,
    home: PathBuf,
    source: Source,
    mut owner: switching::Owner,
    mut job: SwitchJob,
    signal: Arc<Signal>,
    receive: Receiver<Decision>,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = deadline::Deadline::start(
            home.clone(),
            job.clone(),
            Arc::clone(&signal),
            shared.clone(),
        )?;
        let mut prepared = prepare::run(&shared, &home, &source, &mut owner, &mut job, &signal)?;
        super::super::worker::step(&home, &mut job, &signal, JobPhase::Ready, "ready_disabled")?;
        loop {
            check(&shared, &source, &signal)?;
            prepared.settings.check_current()?;
            if jobs::now()? >= job.deadline_at_ms {
                return Err(error("switch_deadline_exceeded"));
            }
            match receive.recv_timeout(Duration::from_millis(25)) {
                Ok(Decision::Commit) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(error("switch_cancelled")),
            }
        }
        commit::run(
            &shared,
            &source,
            &mut owner,
            &mut job,
            &signal,
            &mut prepared,
            &deadline,
        )
    }))
    .unwrap_or_else(|_| Err(error("switch_worker_failed")));
    let (phase, code) = match result {
        Ok(()) => (JobPhase::Completed, "completed_disabled".to_owned()),
        Err(_) if signal.published.load(Ordering::Acquire) => (
            JobPhase::RecoveryRequired,
            "switch_publication_acknowledgement_pending".into(),
        ),
        Err(code) => {
            let diagnostic = super::super::worker::diagnostic(&code);
            job.failure_code = Some(diagnostic.clone());
            signal.cancel.store(true, Ordering::Release);
            if discard_owned_preparation(&mut owner, &job.request.job_id).is_err() {
                (
                    JobPhase::RecoveryRequired,
                    "switch_recovery_required".into(),
                )
            } else if code.ends_with("switch_cancelled") {
                (JobPhase::Cancelled, "cancelled".into())
            } else {
                (JobPhase::Failed, diagnostic)
            }
        }
    };
    let _ = super::super::worker::step(&home, &mut job, &signal, phase, &code);
    drop(owner);
    signal.cleaned.store(true, Ordering::Release);
    if let Some(shared) = shared.upgrade() {
        if let Ok(mut state) = lock(&shared) {
            if state
                .upgrade
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &signal))
            {
                state.upgrade = None;
            }
        }
    }
}
