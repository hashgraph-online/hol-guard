//! Bounded, deadline-aware admission for runtime hook reviews.
//!
//! Short bursts of hooks queue here while the count in flight, the bytes
//! retained and the time each one waits all stay bounded. Lanes share the
//! review slots by weighted deficit round robin (decisions first), a client
//! that already holds half the slots yields to a competing one, a waiter
//! older than half a second jumps the rotation, and a hook that cannot finish
//! within its deadline on the recent service time is refused before it
//! starts rather than after it has spent the harness's budget.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

/// The review lanes, in rotation order, with their weights.
pub(super) const LANES: [&str; 3] = ["decision", "content-security", "evidence"];
const LANE_WEIGHTS: [i64; 3] = [4, 3, 1];
const AGE_BOOST_SECONDS: f64 = 0.5;
const DEFAULT_SERVICE_SECONDS: f64 = 0.75;
const MIN_SERVICE_SECONDS: f64 = 0.1;
const MAX_SERVICE_SECONDS: f64 = 2.8;
const MIN_PREDICTION_SAMPLES: usize = 20;
const HISTOGRAM_WINDOW_SECONDS: f64 = 60.0;
const SAMPLE_LIMIT: usize = 2048;
const STABLE_HARNESSES: [&str; 6] = ["pi", "omp", "codex", "claude-code", "cursor", "opencode"];
/// What the deadline keeps back for writing the answer.
const SERIALIZATION_RESERVE_SECONDS: f64 = 0.05;

pub(super) const DEADLINE_EXHAUSTED: &str = "daemon_hook_deadline_exhausted";
pub(super) const QUEUE_CAPACITY: &str = "daemon_hook_queue_capacity";
pub(super) const QUEUE_BYTES: &str = "daemon_hook_queue_bytes";

/// The scheduler's bounds.
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub active: usize,
    pub per_harness_active: usize,
    pub queued: usize,
    pub per_harness_queued: usize,
    pub per_client_queued: usize,
    pub retained_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            active: 32,
            per_harness_active: 24,
            queued: 128,
            per_harness_queued: 64,
            per_client_queued: 32,
            retained_bytes: 32 * 1024 * 1024,
        }
    }
}

struct Item {
    sequence: u64,
    harness: String,
    client: String,
    lane: usize,
    bytes: u64,
    expires_at: f64,
    queued_at: f64,
    admitted_at: Option<f64>,
    rejection: Option<&'static str>,
}

/// One client's queued hooks in one lane, in arrival order.
struct Group {
    client: String,
    harness: String,
    items: VecDeque<u64>,
}

#[derive(Default)]
struct State {
    items: HashMap<u64, Item>,
    /// Per lane, the client groups in rotation order.
    queues: [VecDeque<Group>; 3],
    sequence: u64,
    lane_cursor: usize,
    deficits: [i64; 3],
    active: usize,
    active_by_harness: HashMap<String, usize>,
    active_by_client: HashMap<String, usize>,
    queued: usize,
    queued_by_harness: HashMap<String, usize>,
    queued_by_client: HashMap<String, usize>,
    retained_bytes: u64,
    admitted: u64,
    completed: u64,
    expired: u64,
    cancelled: u64,
    retries: u64,
    rejected: BTreeMap<String, u64>,
    harness_rejected: BTreeMap<String, u64>,
    queue_wait: VecDeque<f64>,
    service_time: VecDeque<f64>,
    queue_wait_by_lane: [VecDeque<(f64, f64)>; 3],
    service_time_by_lane: [VecDeque<(f64, f64)>; 3],
}

/// The admission queue every runtime hook passes through.
pub(super) struct Scheduler {
    limits: Limits,
    state: Mutex<State>,
    changed: Condvar,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
}

/// Retained bytes held for a hook that has not been queued yet.
pub(super) struct ByteReservation<'a> {
    scheduler: &'a Scheduler,
    bytes: u64,
    held: bool,
}

impl Drop for ByteReservation<'_> {
    fn drop(&mut self) {
        if self.held {
            let mut state = self.scheduler.lock();
            state.retained_bytes = state.retained_bytes.saturating_sub(self.bytes);
            self.scheduler.changed.notify_all();
        }
    }
}

/// A review slot. Dropping it frees the slot and admits the next waiter.
pub(super) struct Permit<'a> {
    scheduler: &'a Scheduler,
    item: Option<Item>,
}

impl Permit<'_> {
    /// Frees the slot now, before the answer is written.
    pub(super) fn release(&mut self) {
        if let Some(item) = self.item.take() {
            self.scheduler.release(&item);
        }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// The process's scheduler.
pub(super) fn shared() -> &'static Scheduler {
    static SCHEDULER: OnceLock<Scheduler> = OnceLock::new();
    SCHEDULER.get_or_init(|| Scheduler::new(Limits::default(), monotonic()))
}

/// Seconds since this process first asked, on the monotonic clock.
pub(super) fn monotonic() -> Box<dyn Fn() -> f64 + Send + Sync> {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    Box::new(move || origin.elapsed().as_secs_f64())
}

/// The lane index a lane name names.
pub(super) fn lane_index(lane: &str) -> usize {
    LANES.iter().position(|known| *known == lane).unwrap_or(1)
}

fn bump(counts: &mut HashMap<String, usize>, key: &str) {
    *counts.entry(key.to_owned()).or_insert(0) += 1;
}

fn drop_count(counts: &mut HashMap<String, usize>, key: &str) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}

fn push_bounded<T>(samples: &mut VecDeque<T>, value: T) {
    if samples.len() == SAMPLE_LIMIT {
        samples.pop_front();
    }
    samples.push_back(value);
}

fn percentile(samples: impl Iterator<Item = f64>, percentile: f64) -> f64 {
    let mut ordered: Vec<f64> = samples.collect();
    if ordered.is_empty() {
        return 0.0;
    }
    ordered.sort_by(f64::total_cmp);
    let rank = (ordered.len() as f64 * percentile).ceil() as usize;
    ordered[rank.saturating_sub(1).min(ordered.len() - 1)]
}

fn timed_percentile_ms(samples: &VecDeque<(f64, f64)>, now: f64, rank: f64) -> f64 {
    percentile(
        samples
            .iter()
            .filter(|(at, _)| now - at <= HISTOGRAM_WINDOW_SECONDS)
            .map(|(_, value)| *value),
        rank,
    ) * 1000.0
}

fn bounded_harness_counts(counts: &HashMap<String, usize>) -> Value {
    let mut bounded: BTreeMap<&str, usize> = BTreeMap::new();
    for (harness, count) in counts {
        let key = if STABLE_HARNESSES.contains(&harness.as_str()) {
            harness.as_str()
        } else {
            "other"
        };
        *bounded.entry(key).or_insert(0) += count;
    }
    json!(bounded)
}

impl Scheduler {
    pub(super) fn new(limits: Limits, clock: Box<dyn Fn() -> f64 + Send + Sync>) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            clock,
        }
    }

    pub(super) fn now(&self) -> f64 {
        (self.clock)()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait<'a>(&self, state: MutexGuard<'a, State>, seconds: f64) -> MutexGuard<'a, State> {
        let timeout = Duration::from_secs_f64(seconds.clamp(0.0, 60.0));
        self.changed
            .wait_timeout(state, timeout)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
    }

    /// Holds `bytes` of the retained budget until `deadline`, waiting for
    /// bytes other hooks free.
    pub(super) fn reserve_bytes(
        &self,
        bytes: u64,
        deadline: f64,
    ) -> Result<ByteReservation<'_>, &'static str> {
        let mut state = self.lock();
        if deadline <= self.now() {
            return Err(reject(&mut state, DEADLINE_EXHAUSTED));
        }
        if bytes > self.limits.retained_bytes {
            return Err(reject(&mut state, QUEUE_BYTES));
        }
        while state.retained_bytes + bytes > self.limits.retained_bytes {
            let remaining = deadline - self.now();
            if remaining <= 0.0 {
                return Err(reject(&mut state, DEADLINE_EXHAUSTED));
            }
            state = self.wait(state, remaining);
        }
        state.retained_bytes += bytes;
        Ok(ByteReservation {
            scheduler: self,
            bytes,
            held: true,
        })
    }

    /// Queues a hook whose bytes are already reserved and waits for a slot.
    pub(super) fn acquire<'a>(
        &'a self,
        harness: &str,
        client: &str,
        lane: usize,
        mut reservation: ByteReservation<'a>,
        expires_at: f64,
    ) -> Result<Permit<'a>, &'static str> {
        let mut state = self.lock();
        let now = self.now();
        if expires_at <= now {
            return Err(reject(&mut state, DEADLINE_EXHAUSTED));
        }
        let limits = self.limits;
        if state.queued >= limits.queued
            || state.queued_by_harness.get(harness).copied().unwrap_or(0)
                >= limits.per_harness_queued
            || state.queued_by_client.get(client).copied().unwrap_or(0) >= limits.per_client_queued
        {
            return Err(reject(&mut state, QUEUE_CAPACITY));
        }
        // The reservation's bytes now belong to the queued item.
        reservation.held = false;
        state.sequence += 1;
        let id = state.sequence;
        state.items.insert(
            id,
            Item {
                sequence: id,
                harness: harness.to_owned(),
                client: client.to_owned(),
                lane,
                bytes: reservation.bytes,
                expires_at,
                queued_at: now,
                admitted_at: None,
                rejection: None,
            },
        );
        enqueue(&mut state, id);
        self.dispatch(&mut state);
        loop {
            let item = state.items.get(&id).unwrap_or_else(|| unreachable!());
            if item.admitted_at.is_some() {
                let item = state.items.remove(&id).unwrap_or_else(|| unreachable!());
                return Ok(Permit {
                    scheduler: self,
                    item: Some(item),
                });
            }
            if let Some(reason) = item.rejection {
                state.items.remove(&id);
                return Err(reason);
            }
            let remaining = expires_at - self.now();
            if remaining <= 0.0 {
                if remove_queued(&mut state, id) {
                    state.expired += 1;
                    self.changed.notify_all();
                }
                state.items.remove(&id);
                return Err(DEADLINE_EXHAUSTED);
            }
            state = self.wait(state, remaining);
            self.dispatch(&mut state);
        }
    }

    /// Counts a hook the daemon refused for capacity against its harness.
    pub(super) fn record_harness_rejection(&self, harness: &str) {
        *self
            .lock()
            .harness_rejected
            .entry(harness.to_owned())
            .or_insert(0) += 1;
    }

    fn release(&self, item: &Item) {
        let mut state = self.lock();
        state.active -= 1;
        drop_count(&mut state.active_by_harness, &item.harness);
        drop_count(&mut state.active_by_client, &item.client);
        state.retained_bytes = state.retained_bytes.saturating_sub(item.bytes);
        state.completed += 1;
        if let Some(admitted_at) = item.admitted_at {
            let finished_at = self.now();
            let service = (finished_at - admitted_at).max(0.0);
            push_bounded(&mut state.service_time, service);
            push_bounded(
                &mut state.service_time_by_lane[item.lane],
                (finished_at, service),
            );
        }
        self.dispatch(&mut state);
    }

    fn dispatch(&self, state: &mut State) {
        self.expire_waiters(state);
        while state.active < self.limits.active && state.queued > 0 {
            let Some(id) = self.next_item(state) else {
                break;
            };
            let now = self.now();
            let item = state.items.get_mut(&id).unwrap_or_else(|| unreachable!());
            item.admitted_at = Some(now);
            let (lane, waited) = (item.lane, (now - item.queued_at).max(0.0));
            let (harness, client) = (item.harness.clone(), item.client.clone());
            decrement_queued(state, &harness, &client);
            push_bounded(&mut state.queue_wait, waited);
            push_bounded(&mut state.queue_wait_by_lane[lane], (now, waited));
            state.active += 1;
            bump(&mut state.active_by_harness, &harness);
            bump(&mut state.active_by_client, &client);
            state.admitted += 1;
        }
        self.changed.notify_all();
    }

    fn share_limit(&self) -> usize {
        self.limits.active.div_ceil(2).max(1)
    }

    /// Whether this group may take a slot now.
    fn eligible(&self, state: &State, harness: &str, client: &str) -> bool {
        if state.active_by_harness.get(harness).copied().unwrap_or(0)
            >= self.limits.per_harness_active
        {
            return false;
        }
        let competing = state
            .queues
            .iter()
            .flatten()
            .any(|group| group.client != client);
        !(competing
            && state.active_by_client.get(client).copied().unwrap_or(0) >= self.share_limit())
    }

    fn next_item(&self, state: &mut State) -> Option<u64> {
        if let Some(id) = self.oldest_aged_eligible(state) {
            return Some(id);
        }
        let rounds = LANE_WEIGHTS.iter().sum::<i64>() as usize + LANES.len();
        for _ in 0..rounds {
            let lane = state.lane_cursor;
            if state.deficits[lane] == 0 {
                state.deficits[lane] = LANE_WEIGHTS[lane];
            }
            if state.queues[lane].is_empty() {
                state.deficits[lane] = 0;
                state.lane_cursor = (lane + 1) % LANES.len();
                continue;
            }
            if state.deficits[lane] < 1 {
                continue;
            }
            for _ in 0..state.queues[lane].len() {
                let mut group = state.queues[lane]
                    .pop_front()
                    .unwrap_or_else(|| unreachable!());
                if !self.eligible(state, &group.harness, &group.client) {
                    state.queues[lane].push_back(group);
                    continue;
                }
                let id = group.items.pop_front().unwrap_or_else(|| unreachable!());
                if !group.items.is_empty() {
                    state.queues[lane].push_back(group);
                }
                if !self.can_finish(state, id) {
                    self.reject_queued(state, id);
                    continue;
                }
                state.deficits[lane] -= 1;
                if state.deficits[lane] == 0 {
                    state.lane_cursor = (lane + 1) % LANES.len();
                }
                return Some(id);
            }
            state.deficits[lane] = 0;
            state.lane_cursor = (lane + 1) % LANES.len();
        }
        None
    }

    fn oldest_aged_eligible(&self, state: &mut State) -> Option<u64> {
        let now = self.now();
        let mut candidates: Vec<(u64, u64)> = state
            .queues
            .iter()
            .flatten()
            .filter_map(|group| group.items.front())
            .filter_map(|id| state.items.get(id).map(|item| (item.sequence, *id)))
            .filter(|(_, id)| now - state.items[id].queued_at >= AGE_BOOST_SECONDS)
            .collect();
        candidates.sort_unstable();
        for (_, id) in candidates {
            let (harness, client) = {
                let item = &state.items[&id];
                (item.harness.clone(), item.client.clone())
            };
            if !self.eligible(state, &harness, &client) {
                continue;
            }
            if !self.can_finish(state, id) {
                remove_queued(state, id);
                if let Some(item) = state.items.get_mut(&id) {
                    item.rejection = Some(DEADLINE_EXHAUSTED);
                }
                state.expired += 1;
                continue;
            }
            remove_from_lane(state, id);
            return Some(id);
        }
        None
    }

    fn can_finish(&self, state: &State, id: u64) -> bool {
        let item = &state.items[&id];
        let remaining = (item.expires_at - self.now()).max(0.0);
        self.service_estimate(state, item.lane)
            <= (remaining - SERIALIZATION_RESERVE_SECONDS).max(0.0)
    }

    fn service_estimate(&self, state: &State, lane: usize) -> f64 {
        let now = self.now();
        let recent: Vec<f64> = state.service_time_by_lane[lane]
            .iter()
            .filter(|(at, _)| now - at <= HISTOGRAM_WINDOW_SECONDS)
            .map(|(_, value)| *value)
            .collect();
        if recent.len() < MIN_PREDICTION_SAMPLES {
            return DEFAULT_SERVICE_SECONDS;
        }
        let estimate =
            percentile(recent.into_iter(), 0.95).clamp(MIN_SERVICE_SECONDS, MAX_SERVICE_SECONDS);
        if state.active == 0 {
            // Nothing is in flight, so the slow samples describe a stall that
            // already ended; admit on the cold-start estimate.
            return estimate.min(DEFAULT_SERVICE_SECONDS);
        }
        estimate
    }

    fn reject_queued(&self, state: &mut State, id: u64) {
        drop_queued(state, id);
        if let Some(item) = state.items.get_mut(&id) {
            item.rejection = Some(DEADLINE_EXHAUSTED);
        }
        state.expired += 1;
    }

    fn expire_waiters(&self, state: &mut State) {
        let now = self.now();
        let expired: Vec<u64> = state
            .queues
            .iter()
            .flatten()
            .flat_map(|group| group.items.iter().copied())
            .filter(|id| state.items[id].expires_at <= now)
            .collect();
        for id in expired {
            remove_queued(state, id);
            state.expired += 1;
            if let Some(item) = state.items.get_mut(&id) {
                item.rejection = Some(DEADLINE_EXHAUSTED);
            }
        }
    }

    /// The scheduler's counters as the health details report them.
    pub(super) fn stats(&self) -> Value {
        let state = self.lock();
        let now = self.now();
        let oldest = state
            .queues
            .iter()
            .flatten()
            .flat_map(|group| group.items.iter())
            .map(|id| state.items[id].queued_at)
            .fold(None, |oldest: Option<f64>, at| {
                Some(oldest.map_or(at, |oldest| oldest.min(at)))
            });
        let by_lane = |samples: &[VecDeque<(f64, f64)>; 3], rank: f64| {
            Value::Object(
                LANES
                    .iter()
                    .zip(samples)
                    .map(|(lane, samples)| {
                        (
                            (*lane).to_owned(),
                            json!(timed_percentile_ms(samples, now, rank)),
                        )
                    })
                    .collect::<Map<String, Value>>(),
            )
        };
        json!({
            "active": state.active,
            "active_limit": self.limits.active,
            "queued": state.queued,
            "queued_limit": self.limits.queued,
            "retained_bytes": state.retained_bytes,
            "retained_bytes_limit": self.limits.retained_bytes,
            "admitted": state.admitted,
            "completed": state.completed,
            "expired": state.expired,
            "cancelled": state.cancelled,
            "retries": state.retries,
            "rejected": state.rejected,
            "per_harness_active": bounded_harness_counts(&state.active_by_harness),
            "per_harness_queued": bounded_harness_counts(&state.queued_by_harness),
            "per_harness_rejected": state.harness_rejected,
            "queue_wait_p95_ms": percentile(state.queue_wait.iter().copied(), 0.95) * 1000.0,
            "service_time_p95_ms": percentile(state.service_time.iter().copied(), 0.95) * 1000.0,
            "queue_wait_p99_ms": percentile(state.queue_wait.iter().copied(), 0.99) * 1000.0,
            "service_time_p99_ms": percentile(state.service_time.iter().copied(), 0.99) * 1000.0,
            "oldest_queued_ms": oldest.map_or(0.0, |at| (now - at).max(0.0) * 1000.0),
            "queue_wait_by_lane_p95_ms": by_lane(&state.queue_wait_by_lane, 0.95),
            "service_time_by_lane_p95_ms": by_lane(&state.service_time_by_lane, 0.95),
            "queue_wait_by_lane_p99_ms": by_lane(&state.queue_wait_by_lane, 0.99),
            "service_time_by_lane_p99_ms": by_lane(&state.service_time_by_lane, 0.99),
        })
    }
}

fn reject(state: &mut State, reason: &'static str) -> &'static str {
    *state.rejected.entry(reason.to_owned()).or_insert(0) += 1;
    reason
}

fn enqueue(state: &mut State, id: u64) {
    let (lane, client, harness) = {
        let item = &state.items[&id];
        (item.lane, item.client.clone(), item.harness.clone())
    };
    match state.queues[lane]
        .iter_mut()
        .find(|group| group.client == client && group.harness == harness)
    {
        Some(group) => group.items.push_back(id),
        None => state.queues[lane].push_back(Group {
            client: client.clone(),
            harness: harness.clone(),
            items: VecDeque::from([id]),
        }),
    }
    state.queued += 1;
    bump(&mut state.queued_by_harness, &harness);
    bump(&mut state.queued_by_client, &client);
}

fn decrement_queued(state: &mut State, harness: &str, client: &str) {
    state.queued -= 1;
    drop_count(&mut state.queued_by_harness, harness);
    drop_count(&mut state.queued_by_client, client);
}

fn drop_queued(state: &mut State, id: u64) {
    let (harness, client, bytes) = {
        let item = &state.items[&id];
        (item.harness.clone(), item.client.clone(), item.bytes)
    };
    decrement_queued(state, &harness, &client);
    state.retained_bytes = state.retained_bytes.saturating_sub(bytes);
}

/// Takes a queued item out of its lane without touching the counters.
fn remove_from_lane(state: &mut State, id: u64) -> bool {
    let Some(item) = state.items.get(&id) else {
        return false;
    };
    let lane = item.lane;
    let Some(position) = state.queues[lane]
        .iter()
        .position(|group| group.items.contains(&id))
    else {
        return false;
    };
    let group = &mut state.queues[lane][position];
    group.items.retain(|queued| *queued != id);
    if group.items.is_empty() {
        state.queues[lane].remove(position);
    }
    true
}

/// Takes a queued item out and gives back what it held.
fn remove_queued(state: &mut State, id: u64) -> bool {
    if !remove_from_lane(state, id) {
        return false;
    }
    drop_queued(state, id);
    true
}

#[cfg(test)]
#[path = "daemon_edge_hook_scheduler_tests.rs"]
mod tests;
