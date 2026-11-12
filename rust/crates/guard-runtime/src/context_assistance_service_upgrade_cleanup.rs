//! Keep the original lifecycle owner and private actor handles until every
//! cleanup acknowledgement arrives. Availability alone cannot release ownership.
use super::*;

#[derive(Default)]
pub(super) struct Pending(Mutex<[Option<Arc<RuntimeActor<Engine>>>; 3]>);
pub(super) enum Role {
    Source,
    Candidate,
    Restoration,
}
impl Pending {
    pub(super) fn active(&self) -> bool {
        let mut actors = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for actor in actors.iter_mut() {
            if actor.as_ref().is_some_and(|a| a.cleanup_finished()) {
                actor.take();
            }
        }
        actors.iter().any(Option::is_some)
    }
}
/// Each role has exactly one native construction/cleanup path per job. There
/// is no queue of orphan workers and no replacement of a pending role.
pub(super) fn close(signal: &Signal, role: Role, actor: Arc<RuntimeActor<Engine>>) {
    if actor.close_and_wait(Duration::from_millis(500)) {
        return;
    }
    let mut actors = signal
        .pending_cleanup
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let slot = &mut actors[role as usize];
    if let Some(current) = slot {
        assert!(
            Arc::ptr_eq(current, &actor),
            "one cleanup actor per native role"
        );
    } else {
        *slot = Some(actor);
    }
}
/// The caller keeps Owner on its stack during this metadata-only wait. SDK
/// cancellation already happened; status and Stop never join this worker.
pub(super) fn drain(home: &Path, job: &mut SwitchJob, signal: &Signal) -> Result<(), String> {
    if !signal.pending_cleanup.active() {
        return Ok(());
    }
    let recorded = worker::step(
        home,
        job,
        signal,
        JobPhase::CleanupPending,
        "waiting_for_sdk_cleanup",
    );
    while signal.pending_cleanup.active() {
        std::thread::sleep(Duration::from_millis(25));
    }
    recorded
}
