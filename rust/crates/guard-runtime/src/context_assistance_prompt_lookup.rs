//! CIGAR lookups for typed prompts. One lookup runs per project and app, on
//! its own thread, so a hook never waits past its budget. A prompt that finds
//! CIGAR still starting leaves a warm-up behind: it waits for the worker and
//! loads the project, so the next prompt gets code instead of a file list.
use super::{render, Rendered, Span};
use crate::context_assistance_engine::PickedExcerpt;
use crate::context_assistance_service::{LaneMiss, LaneWatch, PromptLane, Service};
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a warm-up waits for a starting worker before giving up.
const WARM_WAIT: Duration = Duration::from_secs(60);
/// What a prompt keeps of its wait, at most, to read the matched files
/// itself when CIGAR is still starting.
const READ_RESERVE: Duration = Duration::from_millis(300);

/// Why CIGAR gave a prompt no answer.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Miss {
    /// CIGAR is on and still starting, so no worker holds the project yet.
    Starting,
    /// CIGAR is busy with another prompt for this project, or was late.
    Pending,
}

pub(super) struct Request {
    pub(super) root: PathBuf,
    pub(super) app: String,
    pub(super) query: String,
    pub(super) words: Vec<String>,
    pub(super) found: Vec<String>,
    /// What earlier prompts of the session were shown.
    pub(super) earlier: Vec<Span>,
}

type Key = (PathBuf, String);

/// CIGAR's excerpts for a prompt, with the files the prompt matched.
type Picked = Option<Arc<(Vec<PickedExcerpt>, Vec<String>)>>;

/// One lookup per project and app. A second hook for the same prompt waits
/// on it; a different prompt meanwhile gets the matched files rather than
/// queueing. The flight holds CIGAR's excerpts, not rendered text, so each
/// hook renders them against its own session.
struct Flight {
    prompt: u64,
    lane: PromptLane,
    done: Mutex<Option<Picked>>,
    ready: Condvar,
}

type Flights = Mutex<BTreeMap<Key, Arc<Flight>>>;

fn flights() -> &'static Flights {
    static FLIGHTS: OnceLock<Flights> = OnceLock::new();
    FLIGHTS.get_or_init(Default::default)
}

/// Projects with a warm-up waiting for their worker.
fn warming() -> &'static Mutex<BTreeSet<Key>> {
    static WARMING: OnceLock<Mutex<BTreeSet<Key>>> = OnceLock::new();
    WARMING.get_or_init(Default::default)
}

/// CIGAR's rendered answer, `Ok(None)` when it had nothing that fits, was
/// off, or failed, and a [`Miss`] when CIGAR is on but did not answer before
/// `deadline`.
pub(super) fn lookup(
    service: &Service,
    guard_home: &Path,
    request: Request,
    deadline: Instant,
) -> Result<Option<Rendered>, Miss> {
    let key = (request.root.clone(), request.app.clone());
    let prompt = hashed(&request.query);
    let words = request.words.clone();
    let earlier = request.earlier.clone();
    let rendered = |flight: &Flight| {
        answer(service, flight, deadline)
            .map(|picked| picked.and_then(|found| render(&found.0, &found.1, &words, &earlier)))
            .ok_or(Miss::Pending)
    };
    let flight = {
        let Ok(running) = flights().lock() else {
            return Ok(None);
        };
        match running.get(&key) {
            Some(flight) if flight.prompt == prompt => Some(Arc::clone(flight)),
            Some(_) => return Err(Miss::Pending),
            None => None,
        }
    };
    if let Some(flight) = flight {
        return rendered(&flight);
    }
    // The lane keeps at least half of what is left, so a short or late wait
    // still finds out whether CIGAR is on.
    let left = deadline.saturating_duration_since(Instant::now());
    let lane_until = deadline - READ_RESERVE.min(left / 2);
    let lane = match service.prompt_lane(guard_home, lane_until) {
        Ok(lane) => lane,
        Err(LaneMiss::Starting) => {
            warm_when_ready(service.lane_watch(), key, request);
            return Err(Miss::Starting);
        }
        Err(LaneMiss::Off) => return Ok(None),
    };
    let flight = launch(key, prompt, lane, request).ok_or(Miss::Pending)?;
    rendered(&flight)
}

/// Waits on its own thread for a worker that is still starting, then runs
/// the prompt's lookup so the project is loaded before the next prompt. Its
/// answer reaches no one; only a repeat of the same prompt may join it.
fn warm_when_ready(watch: LaneWatch, key: Key, request: Request) {
    let Ok(mut waiting) = warming().lock() else {
        return;
    };
    if !waiting.insert(key.clone()) {
        return;
    }
    drop(waiting);
    let warm_key = key.clone();
    let spawned = std::thread::Builder::new()
        .name("guard-cigar-warm".into())
        .spawn(move || {
            if let Ok(lane) = watch.wait(Instant::now() + WARM_WAIT) {
                let prompt = hashed(&request.query);
                let _ = launch(warm_key.clone(), prompt, lane, request);
            }
            done_warming(&warm_key);
        });
    if spawned.is_err() {
        done_warming(&key);
    }
}

fn done_warming(key: &Key) {
    if let Ok(mut waiting) = warming().lock() {
        waiting.remove(key);
    }
}

/// Starts CIGAR's lookup for `request` on its own thread. `None` when
/// another lookup for the project got there first or no thread started.
fn launch(key: Key, prompt: u64, lane: PromptLane, request: Request) -> Option<Arc<Flight>> {
    let flight = Arc::new(Flight {
        prompt,
        lane,
        done: Mutex::new(None),
        ready: Condvar::new(),
    });
    {
        let mut running = flights().lock().ok()?;
        if running.contains_key(&key) {
            return None;
        }
        running.insert(key.clone(), Arc::clone(&flight));
    }
    let actor = Arc::clone(&flight.lane.actor);
    let worker = Arc::clone(&flight);
    let spawned = std::thread::Builder::new()
        .name("guard-cigar-prompt".into())
        .spawn(move || {
            let Request {
                root,
                app,
                query,
                words,
                found,
                ..
            } = request;
            let picked = actor
                .call(move |runtime, engine| {
                    engine
                        .prompt_context(runtime, root, app, found.clone(), query, &words)
                        .map(|picked| picked.map(|picked| Arc::new((picked, found))))
                })
                .ok()
                .flatten();
            if let Ok(mut done) = worker.done.lock() {
                *done = Some(picked);
            }
            worker.ready.notify_all();
            if let Ok(mut running) = flights().lock() {
                if running
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &worker))
                {
                    running.remove(&key);
                }
            }
        });
    if spawned.is_err() {
        if let Ok(mut running) = flights().lock() {
            running.retain(|_, current| !Arc::ptr_eq(current, &flight));
        }
        return None;
    }
    Some(flight)
}

/// The flight's excerpts, dropped if project context changed meanwhile.
fn answer(service: &Service, flight: &Flight, deadline: Instant) -> Option<Picked> {
    let picked = wait_for(flight, deadline)?;
    Some(picked.filter(|_| service.prompt_lane_current(&flight.lane)))
}

fn wait_for(flight: &Flight, deadline: Instant) -> Option<Picked> {
    let mut done = flight.done.lock().ok()?;
    while done.is_none() {
        let left = deadline.checked_duration_since(Instant::now())?;
        done = flight.ready.wait_timeout(done, left).ok()?.0;
    }
    done.clone()
}

fn hashed(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
#[path = "context_assistance_prompt_lookup_tests.rs"]
mod tests;
