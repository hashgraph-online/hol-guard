//! Capture the serving/off distinction once under the same native job owner.
use super::*;
use std::sync::mpsc::Receiver;

pub(super) enum Input {
    Active(Source),
    Disabled(cold::Source),
    Initial(cold::Source),
}
pub(super) fn capture(shared: &Mutex<State>, request: &SwitchRequest) -> Result<Input, String> {
    if !lock(shared)?.settings.requested.enabled {
        let source = cold::Source::capture(shared, request)?;
        Ok(if source.settings.effective.runtime_id.is_empty() {
            Input::Initial(source)
        } else {
            Input::Disabled(source)
        })
    } else {
        source(shared, request).map(Input::Active)
    }
}
impl Input {
    pub(super) fn job(&self, request: SwitchRequest) -> Result<SwitchJob, String> {
        match self {
            Self::Initial(_) => SwitchJob::new_initial(request),
            Self::Active(source) => {
                SwitchJob::new(request, source.settings.effective.runtime_id.clone())
            }
            Self::Disabled(source) => {
                SwitchJob::new_disabled(request, source.settings.effective.runtime_id.clone())
            }
        }
    }
    pub(super) fn matches(&self, state: &State) -> bool {
        if state.closed
            || state.stopping
            || state.pending.is_some()
            || state.upgrade.is_some()
            || state.cutover.is_some()
            || state
                .retiring
                .as_ref()
                .is_some_and(|a| !a.cleanup_finished())
        {
            return false;
        }
        match self {
            Self::Active(source) => {
                state.generation == source.generation
                    && state.settings == source.settings
                    && state
                        .runtime
                        .as_ref()
                        .is_some_and(|a| Arc::ptr_eq(a, &source.actor) && a.is_active())
            }
            Self::Disabled(source) | Self::Initial(source) => source.matches(state),
        }
    }
}
pub(super) fn run(
    shared: Weak<Mutex<State>>,
    home: PathBuf,
    source: Input,
    owner: switching::Owner,
    job: SwitchJob,
    signal: Arc<Signal>,
    receive: Receiver<Decision>,
) {
    match source {
        Input::Initial(source) => initial::run(shared, home, source, owner, job, signal, receive),
        Input::Active(source) => worker::run(shared, home, source, owner, job, signal, receive),
        Input::Disabled(source) => cold::run(shared, home, source, owner, job, signal, receive),
    }
}

fn source(shared: &Mutex<State>, request: &SwitchRequest) -> Result<Source, String> {
    let state = lock(shared)?;
    if state.closed {
        return Err(error("shutdown"));
    }
    if state.stopping
        || state.pending.is_some()
        || state.upgrade.is_some()
        || state.cutover.is_some()
        || state
            .retiring
            .as_ref()
            .is_some_and(|a| !a.cleanup_finished())
    {
        return Err(error("switch_busy"));
    }
    if state.generation != request.expected_generation {
        return Err(error("switch_selection_conflict"));
    }
    if !state.settings.effective.enabled
        || !state.settings.requested.enabled
        || !state.settings.verification_permitted
        || state.settings.diagnostic.is_some()
    {
        return Err(error("disabled"));
    }
    if state.settings.effective.runtime_id == request.target_runtime_id {
        return Err(error("switch_request_invalid"));
    }
    let actor = state
        .runtime
        .as_ref()
        .filter(|a| a.is_active())
        .cloned()
        .ok_or_else(|| error("runtime_not_verified"))?;
    Ok(Source {
        actor,
        settings: state.settings.clone(),
        generation: state.generation,
    })
}
