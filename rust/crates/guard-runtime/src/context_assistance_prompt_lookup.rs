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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Condvar, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

/// How long a warm-up waits for a starting worker before giving up.
const WARM_WAIT: Duration = Duration::from_secs(60);
/// What a prompt keeps of its wait, at most, to read the matched files
/// itself when CIGAR is starting, busy or late.
const READ_RESERVE: Duration = Duration::from_millis(300);
/// CIGAR is advisory work. Cap prompt threads globally so many distinct
/// workspaces cannot consume the daemon's thread budget.
const MAX_PROMPT_THREADS: usize = 32;

struct PromptThreadBudget {
    active: AtomicUsize,
    limit: usize,
}

impl PromptThreadBudget {
    const fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(&'static self) -> Option<PromptThreadPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        while active < self.limit {
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(PromptThreadPermit { budget: self }),
                Err(observed) => active = observed,
            }
        }
        None
    }
}

static PROMPT_THREADS: PromptThreadBudget = PromptThreadBudget::new(MAX_PROMPT_THREADS);

pub(super) struct PromptThreadPermit {
    budget: &'static PromptThreadBudget,
}

impl Drop for PromptThreadPermit {
    fn drop(&mut self) {
        self.budget.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) fn try_prompt_thread() -> Option<PromptThreadPermit> {
    PROMPT_THREADS.try_acquire()
}

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
    /// The project's names the prompt writes as code, which an answer holds.
    pub(super) names: Vec<String>,
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
    let names = request.names.clone();
    // One cutoff for every wait, so the read keeps its reserve however long
    // the lane took.
    let cutoff = short_of(deadline, Instant::now());
    let shown = |found: Arc<(Vec<PickedExcerpt>, Vec<String>)>| {
        render(&found.0, &found.1, &words, &earlier, &names)
    };
    let rendered = |flight: &Flight| {
        answer(service, flight, cutoff)
            .map(|picked| picked.and_then(shown))
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
    // Reserve advisory capacity before waiting for CIGAR's lane. When the
    // global budget is full, return immediately so a hook never spends its
    // response budget waiting for work that cannot start.
    let Some(permit) = try_prompt_thread() else {
        return Err(Miss::Pending);
    };
    let lane = match service.prompt_lane(guard_home, cutoff) {
        Ok(lane) => lane,
        Err(LaneMiss::Starting) => {
            warm_when_ready(service.lane_watch(), key, request, permit);
            return Err(Miss::Starting);
        }
        Err(LaneMiss::Off) => return Ok(None),
    };
    let flight = launch(key, prompt, lane, request, permit).ok_or(Miss::Pending)?;
    rendered(&flight)
}

/// Waits on its own thread for a worker that is still starting, then runs
/// the prompt's lookup so the project is loaded before the next prompt. Its
/// answer reaches no one; only a repeat of the same prompt may join it.
fn warm_when_ready(watch: LaneWatch, key: Key, request: Request, permit: PromptThreadPermit) {
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
                if let Some(flight) = launch(warm_key.clone(), prompt, lane, request, permit) {
                    let _ = wait_for(&flight, Instant::now() + WARM_WAIT);
                }
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
fn launch(
    key: Key,
    prompt: u64,
    lane: PromptLane,
    request: Request,
    permit: PromptThreadPermit,
) -> Option<Arc<Flight>> {
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
            let permit = permit;
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
            drop(permit);
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

/// When a wait on CIGAR gives up: early enough before `deadline` for Guard
/// to read the matched files itself. A wait keeps at least half of what is
/// left, so a short or late one still finds out whether CIGAR is on.
fn short_of(deadline: Instant, now: Instant) -> Instant {
    let left = deadline.saturating_duration_since(now);
    deadline - READ_RESERVE.min(left / 2)
}

fn hashed(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// Whether the prompt points at code itself: a quoted phrase, a file it
/// names, or a name written as code (`parse_basic_str`, `IntRange`).
pub(super) fn anchored(prompt: &str) -> bool {
    use crate::context_assistance_prompt_files::{named, phrases};
    !(phrases(prompt).is_empty()
        && named(prompt).is_empty()
        && crate::context_assistance_prompt_words::spellings(prompt).is_empty())
}

/// True when what points the prompt at code is not in this project: quoted
/// text no file read holds, such as a pasted task title or a word quoted for
/// emphasis (`use "password" to approve`), and paths to files outside it,
/// such as a link to a guide in another folder. A quoted error message is
/// held by the file that raises it, and a traceback's path from another
/// machine ends with a file here. A walk cut short by its time or size
/// budget may have missed the file holding a quote, so its zero counts only
/// mean "held nowhere" when it read every file.
pub(super) fn points_nowhere(prompt: &str, root: &Path, quoting: &[usize], complete: bool) -> bool {
    (quoting.is_empty() || (complete && quoting.iter().all(|&files| files == 0)))
        && only_quoted(prompt, root)
}

/// True when only quoted text let the prompt through, no file the walk read
/// holds it, and the note shows none of it either. Its excerpts were then
/// ranked on the prompt's plain words alone, as a task title pasted in a
/// project too big to read whole got: a config file and unrelated modules.
/// CIGAR's own search can still find the quote in a file the walk did not
/// reach, and a note that shows it is kept. Only what files hold counts:
/// a quote such as "project" or "lines" that only Guard's own words in the
/// note hold is not shown.
pub(super) fn quote_unshown(
    prompt: &str,
    root: &Path,
    (quoted, quoting): (&[String], &[usize]),
    note: &str,
) -> bool {
    !quoted.is_empty()
        && quoting.iter().all(|&files| files == 0)
        && only_quoted(prompt, root)
        && !crate::context_assistance_prompt_words::quoted(&file_text(note), quoted).contains(&true)
}

/// How the lines Guard writes between a note's excerpts start, lowercased.
const GUARD_LEAD_INS: &[&str] = &[
    "already shown earlier in this session:",
    "other matching files:",
];

/// The fixed titles Guard writes on a line of their own, lowercased.
const GUARD_TITLES: &[&str] = &[
    "definitions this request names:",
    "tests that use the changed definitions:",
    "changed definitions as they read now:",
    "changed definitions (current line numbers):",
    "definitions this request names or quotes, in files guard keeps out of this context \
     (open these lines yourself):",
];

/// A note's text without Guard's own words, lowercased: every note opens
/// with Guard's paragraph and its excerpts follow a blank line. Lines inside
/// a code fence are a file's and always kept. Outside one, an excerpt's
/// label (its path and `(lines a-b)`), a list's lead-in and a title that is
/// the whole line are Guard's.
fn file_text(note: &str) -> String {
    let note = note.to_lowercase();
    let label = |line: &str| {
        (line.strip_suffix(')'))
            .and_then(|line| line.rsplit_once(" (lines "))
            .is_some_and(|(_, range)| {
                range.split_once('-').is_some_and(|(from, to)| {
                    [from, to]
                        .iter()
                        .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                })
            })
    };
    let own = |line: &str| {
        label(line)
            || GUARD_TITLES.contains(&line.trim_end())
            || GUARD_LEAD_INS.iter().any(|lead| line.starts_with(lead))
    };
    let body = note.split_once("\n\n").map_or("", |(_, body)| body);
    // An excerpt's fence is longer than any backtick run inside it, so a
    // fence closes only on a bare run at least as long as its opener.
    let ticks = |line: &str| line.trim_start().bytes().take_while(|&b| b == b'`').count();
    let mut fence = 0;
    let mut kept = Vec::new();
    for line in body.lines() {
        let run = ticks(line);
        if fence == 0 && run >= 3 {
            fence = run;
        } else if fence > 0 && run >= fence && line.trim().len() == run {
            fence = 0;
        } else if fence > 0 || !own(line) {
            kept.push(line);
        }
    }
    kept.join("\n")
}

/// True when the prompt writes no name as code and names no file in this
/// project, so only quoted text, if any, points it at code.
fn only_quoted(prompt: &str, root: &Path) -> bool {
    use crate::context_assistance_prompt_files::named;
    let elsewhere = |name: &String| {
        let mut tails =
            (0..=name.matches('/').count()).filter_map(|skip| name.splitn(skip + 1, '/').last());
        name.contains('/') && !tails.any(|tail| root.join(tail).is_file())
    };
    named(prompt).iter().all(elsewhere)
        && crate::context_assistance_prompt_words::spellings(prompt).is_empty()
}

pub(super) fn truncated(text: &str, max_bytes: usize) -> String {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
#[path = "context_assistance_prompt_lookup_tests.rs"]
mod tests;
