//! Opt-in, payload-free phase evidence for native response-wait failures.

use std::io::{Cursor, Write};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    StreamLease,
    StreamDispatch,
    StreamResponseWrite,
    ClientPrepare,
    ClientDiscovery,
    ClientIdentity,
    ClientStartupLock,
    ClientStartupWait,
    ClientSpawn,
    ClientSpawnWait,
    ClientConnect,
    ClientAuthenticate,
    ClientRequestWrite,
    ClientResponseRead,
    ResidentStartup,
    ResidentAuthenticate,
    ResidentHeaderRead,
    ResidentPayloadRead,
    ResidentDispatchWait,
    ResidentEvaluate,
    ResidentResponseWrite,
    ContextDigest,
    ContextRuntimeExecutableIdentity,
    ContextRuntimeLaunchIdentity,
    ContextRuntimeLaunchIdentityMatches,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::StreamLease => "stream_lease",
            Self::StreamDispatch => "stream_dispatch",
            Self::StreamResponseWrite => "stream_response_write",
            Self::ClientPrepare => "client_prepare",
            Self::ClientDiscovery => "client_discovery",
            Self::ClientIdentity => "client_identity",
            Self::ClientStartupLock => "client_startup_lock",
            Self::ClientStartupWait => "client_startup_wait",
            Self::ClientSpawn => "client_spawn",
            Self::ClientSpawnWait => "client_spawn_wait",
            Self::ClientConnect => "client_connect",
            Self::ClientAuthenticate => "client_authenticate",
            Self::ClientRequestWrite => "client_request_write",
            Self::ClientResponseRead => "client_response_read",
            Self::ResidentStartup => "resident_startup",
            Self::ResidentAuthenticate => "resident_authenticate",
            Self::ResidentHeaderRead => "resident_header_read",
            Self::ResidentPayloadRead => "resident_payload_read",
            Self::ResidentDispatchWait => "resident_dispatch_wait",
            Self::ResidentEvaluate => "resident_evaluate",
            Self::ResidentResponseWrite => "resident_response_write",
            Self::ContextDigest => "context_digest",
            Self::ContextRuntimeExecutableIdentity => "context_runtime_executable_identity",
            Self::ContextRuntimeLaunchIdentity => "context_runtime_launch_identity",
            Self::ContextRuntimeLaunchIdentityMatches => "context_runtime_launch_identity_matches",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Status {
    Start,
    Ok,
    Error,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

static ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("HOL_GUARD_NATIVE_DIAGNOSTIC").is_ok_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
});

pub(crate) fn enabled() -> bool {
    *ENABLED
}

fn emit(phase: Phase, status: Status, elapsed: Duration) {
    // A broken diagnostic sink must not change native wire/error results.
    // Render into a bounded stack buffer, then append one complete line: the
    // helper and managed resident can share this diagnostic file descriptor.
    let mut line = [0u8; 192];
    let mut output = Cursor::new(line.as_mut_slice());
    if writeln!(
        output,
        "native_resident_phase phase={} status={} elapsed_ms={}",
        phase.label(),
        status.label(),
        elapsed.as_millis()
    )
    .is_ok()
    {
        let length = output.position() as usize;
        let _ = std::io::stderr().lock().write_all(&line[..length]);
    }
}

pub(crate) fn observe<T, E>(
    phase: Phase,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    if !enabled() {
        return operation();
    }
    let started = Instant::now();
    emit(phase, Status::Start, Duration::ZERO);
    let result = operation();
    emit(
        phase,
        if result.is_ok() {
            Status::Ok
        } else {
            Status::Error
        },
        started.elapsed(),
    );
    result
}

pub(crate) fn start(phase: Phase) {
    if enabled() {
        emit(phase, Status::Start, Duration::ZERO);
    }
}

pub(crate) fn finish_since(phase: Phase, status: Status, started: Instant) {
    if enabled() {
        emit(phase, status, started.elapsed());
    }
}

pub(crate) fn child_stderr() -> Stdio {
    if enabled() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

pub(crate) fn observe_value<T>(phase: Phase, operation: impl FnOnce() -> T) -> T {
    if !enabled() {
        return operation();
    }
    let started = Instant::now();
    emit(phase, Status::Start, Duration::ZERO);
    let result = operation();
    emit(phase, Status::Ok, started.elapsed());
    result
}
