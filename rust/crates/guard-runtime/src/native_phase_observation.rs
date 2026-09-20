//! Aggregate-only native phase observations for an explicitly diagnostic build.
//!
//! The default macro expands to its original expression. No request data or
//! free-form errors enter this module. These inclusive spans are not additive,
//! and instrumented timings are never eligible for headline SLO measurements.

#[cfg(not(all(feature = "diagnostic-phases", target_os = "linux")))]
#[macro_export]
macro_rules! observe_native_phase {
    ($phase:ident, $operation:expr) => {
        $operation
    };
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
#[macro_export]
macro_rules! observe_native_phase {
    ($phase:ident, $operation:expr) => {{
        let observation = $crate::native_phase_observation::begin(
            $crate::native_phase_observation::Phase::$phase,
        );
        let result = $operation;
        if let Some(observation) = observation {
            observation.finish(result.is_ok());
        }
        result
    }};
}

#[cfg(not(all(feature = "diagnostic-phases", target_os = "linux")))]
#[macro_export]
macro_rules! with_native_phase_export {
    ($operation:expr) => {
        $operation
    };
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
#[macro_export]
macro_rules! with_native_phase_export {
    ($operation:expr) => {{
        let diagnostics = $crate::native_phase_sink::start();
        let result = $operation;
        if let Some(diagnostics) = diagnostics {
            diagnostics.finished(result.is_ok());
        }
        result
    }};
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
mod enabled {
    use serde::Serialize;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Instant;

    pub(crate) const MAX_OBSERVATIONS_PER_PHASE: u64 = 100_000;
    pub(crate) const MAX_DURATION_NS: u64 = 60_000_000_000;
    const PHASE_COUNT: usize = 7;

    static COLLECTOR: Collector = Collector::new();

    struct Collector {
        enabled: AtomicBool,
        loss_observed: AtomicBool,
        active: AtomicUsize,
        aggregates: Mutex<[Aggregate; PHASE_COUNT]>,
    }

    impl Collector {
        const fn new() -> Self {
            Self {
                enabled: AtomicBool::new(false),
                loss_observed: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                aggregates: Mutex::new([Aggregate::EMPTY; PHASE_COUNT]),
            }
        }

        fn enable(&self) {
            self.enabled.store(true, Ordering::Relaxed);
        }

        fn begin(&self, phase: Phase) -> Option<Observation<'_>> {
            if !self.enabled.load(Ordering::Relaxed) {
                return None;
            }
            self.active.fetch_add(1, Ordering::Relaxed);
            Some(Observation {
                collector: self,
                phase,
                started: Some(Instant::now()),
            })
        }

        fn record(&self, phase: Phase, started: Instant, outcome: Outcome) {
            let elapsed_ns = started.elapsed().as_nanos();
            match self.aggregates.try_lock() {
                Ok(mut aggregates) => aggregates[phase as usize].record(elapsed_ns, outcome),
                Err(_) => self.loss_observed.store(true, Ordering::Relaxed),
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(crate) enum Phase {
        ClientConnect,
        ClientAuthenticate,
        ClientRequestWriteFlush,
        ClientCommittedResponseRead,
        ResidentEvaluate,
        UnixSocketCreation,
        LoopbackConnectHandle,
    }

    impl Phase {
        const ALL: [Self; PHASE_COUNT] = [
            Self::ClientConnect,
            Self::ClientAuthenticate,
            Self::ClientRequestWriteFlush,
            Self::ClientCommittedResponseRead,
            Self::ResidentEvaluate,
            Self::UnixSocketCreation,
            Self::LoopbackConnectHandle,
        ];

        const fn name(self) -> &'static str {
            match self {
                Self::ClientConnect => "client_connect_inclusive",
                Self::ClientAuthenticate => "client_authenticate",
                Self::ClientRequestWriteFlush => "client_request_write_flush",
                Self::ClientCommittedResponseRead => "client_committed_response_read",
                Self::ResidentEvaluate => "resident_evaluate_inclusive",
                Self::UnixSocketCreation => "unix_socket_creation",
                Self::LoopbackConnectHandle => "loopback_connect_handle",
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        ReturnedOk,
        ReturnedErr,
        Unwound,
        Abandoned,
    }

    #[derive(Clone, Copy, Serialize)]
    struct Aggregate {
        retained_count: u64,
        returned_ok: u64,
        returned_err: u64,
        unwound: u64,
        abandoned: u64,
        duration_ns_sum: u64,
        duration_ns_min: u64,
        duration_ns_max: u64,
        duration_clipped: bool,
        observations_discarded_at_cap: bool,
    }

    impl Aggregate {
        const EMPTY: Self = Self {
            retained_count: 0,
            returned_ok: 0,
            returned_err: 0,
            unwound: 0,
            abandoned: 0,
            duration_ns_sum: 0,
            duration_ns_min: 0,
            duration_ns_max: 0,
            duration_clipped: false,
            observations_discarded_at_cap: false,
        };

        fn record(&mut self, elapsed_ns: u128, outcome: Outcome) {
            if self.retained_count == MAX_OBSERVATIONS_PER_PHASE {
                self.observations_discarded_at_cap = true;
                return;
            }
            let duration = elapsed_ns.min(u128::from(MAX_DURATION_NS)) as u64;
            self.duration_clipped |= elapsed_ns > u128::from(MAX_DURATION_NS);
            self.duration_ns_min = if self.retained_count == 0 {
                duration
            } else {
                self.duration_ns_min.min(duration)
            };
            self.duration_ns_max = self.duration_ns_max.max(duration);
            // The fixed retention and duration caps bound this sum below u64::MAX.
            self.duration_ns_sum += duration;
            self.retained_count += 1;
            match outcome {
                Outcome::ReturnedOk => self.returned_ok += 1,
                Outcome::ReturnedErr => self.returned_err += 1,
                Outcome::Unwound => self.unwound += 1,
                Outcome::Abandoned => self.abandoned += 1,
            }
        }
    }

    pub(crate) struct Observation<'a> {
        collector: &'a Collector,
        phase: Phase,
        started: Option<Instant>,
    }

    impl Observation<'_> {
        pub(crate) fn finish(mut self, returned_ok: bool) {
            if let Some(started) = self.started.take() {
                let outcome = if returned_ok {
                    Outcome::ReturnedOk
                } else {
                    Outcome::ReturnedErr
                };
                self.collector.record(self.phase, started, outcome);
                self.collector.active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    impl Drop for Observation<'_> {
        fn drop(&mut self) {
            if let Some(started) = self.started.take() {
                // This records memory only; request threads never export.
                let outcome = if std::thread::panicking() {
                    Outcome::Unwound
                } else {
                    Outcome::Abandoned
                };
                self.collector.record(self.phase, started, outcome);
                self.collector.active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn begin(phase: Phase) -> Option<Observation<'static>> {
        COLLECTOR.begin(phase)
    }

    pub(crate) fn enable() {
        COLLECTOR.enable();
    }

    #[derive(Serialize)]
    struct PhaseReport {
        phase: &'static str,
        statistics: Option<Aggregate>,
    }

    #[derive(Serialize)]
    pub(crate) struct Report {
        schema: &'static str,
        scope: &'static str,
        span_semantics: &'static str,
        headline_timing_eligible: bool,
        complete_run: bool,
        snapshot_atomic: bool,
        collector_loss_observed: bool,
        active_observations_when_read: usize,
        max_observations_per_phase: u64,
        max_duration_ns: u64,
        unobserved_phase: &'static str,
        loopback_failed_internal_socket_creations: Option<u64>,
        all_platform_socket_opens: Option<u64>,
        phases: [PhaseReport; PHASE_COUNT],
    }

    fn snapshot_collector(collector: &Collector) -> Option<Report> {
        let aggregates = *collector.aggregates.try_lock().ok()?;
        Some(Report {
            schema: "hol-guard-native-phase-diagnostics.v1",
            scope: "diagnostic_instrumented_process_snapshot",
            span_semantics: "inclusive_do_not_sum",
            headline_timing_eligible: false,
            // Existing resident workers are not joined or drained by diagnostics.
            // A snapshot cannot prove that queued or later work is absent.
            complete_run: false,
            snapshot_atomic: false,
            collector_loss_observed: collector.loss_observed.load(Ordering::Relaxed),
            active_observations_when_read: collector.active.load(Ordering::Relaxed),
            max_observations_per_phase: MAX_OBSERVATIONS_PER_PHASE,
            max_duration_ns: MAX_DURATION_NS,
            unobserved_phase: "null_missing_or_unretained_not_zero_cost",
            loopback_failed_internal_socket_creations: None,
            all_platform_socket_opens: None,
            phases: Phase::ALL.map(|phase| {
                let aggregate = aggregates[phase as usize];
                PhaseReport {
                    phase: phase.name(),
                    statistics: (aggregate.retained_count != 0).then_some(aggregate),
                }
            }),
        })
    }

    pub(crate) fn snapshot() -> Option<Report> {
        snapshot_collector(&COLLECTOR)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        include!("native_phase_observation_tests.rs");
    }
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
pub(crate) use enabled::{begin, enable, snapshot, Phase, Report};

#[cfg(test)]
mod macro_tests {
    include!("native_phase_macro_tests.rs");
}
