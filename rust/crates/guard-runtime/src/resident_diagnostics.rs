//! Opt-in, payload-free phase evidence for native response-wait failures.

use std::fs::{File, Metadata};
use std::io::{Cursor, Seek, Write};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

// One resident-owned file in the CLI's state base (`Guardhome/native-runtime`).
// It is reused in place, never inherited by a child or rotated/unlinked.
const MANAGED_PHASE_FILE_NAME: &str = "managed-resident-phases.v1.log";
const MAX_MANAGED_PHASE_BYTES: u64 = 64 * 1024;

struct ManagedPhaseFile {
    file: File,
    length: u64,
    #[cfg(unix)]
    owner_uid: u32,
}

impl ManagedPhaseFile {
    fn open(state_base: &Path, owner: &crate::managed_resident::ManagedOwnerLock) -> Option<Self> {
        #[cfg(unix)]
        let file = {
            let _ = state_base;
            owner
                .open_private_child_file(MANAGED_PHASE_FILE_NAME)
                .ok()?
        };
        #[cfg(windows)]
        let file = {
            let _ = owner;
            let private_root =
                crate::resident_state::private_root_for_state_base(state_base).ok()?;
            let (file, directory_binding) = crate::resident_state::private_lock_file(
                &state_base.join(MANAGED_PHASE_FILE_NAME),
                &private_root,
            )
            .ok()?;
            // Do not hold a Windows directory barrier for the resident lifetime:
            // other clients must still be able to bind the state ancestry.
            drop(directory_binding);
            file
        };
        #[cfg(not(any(unix, windows)))]
        let file = {
            let _ = owner;
            let private_root =
                crate::resident_state::private_root_for_state_base(state_base).ok()?;
            crate::resident_state::private_lock_file(
                &state_base.join(MANAGED_PHASE_FILE_NAME),
                &private_root,
            )
            .ok()?
        };
        let metadata = file.metadata().ok()?;
        let mut sink = Self {
            file,
            length: 0,
            #[cfg(unix)]
            owner_uid: {
                use std::os::unix::fs::MetadataExt;
                metadata.uid()
            },
        };
        if !sink.is_private_file(&metadata) {
            return None;
        }
        // A new exclusive resident owner starts a fresh bounded phase history.
        sink.file.set_len(0).ok()?;
        sink.file.rewind().ok()?;
        Some(sink)
    }

    fn is_private_file(&self, metadata: &Metadata) -> bool {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != self.owner_uid
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return false;
            }
        }
        #[cfg(windows)]
        if crate::resident_state::verify_windows_private_file(&self.file).is_err()
            || guard_runtime_windows_process::is_single_link_handle(&self.file).ok() != Some(true)
        {
            return false;
        }
        true
    }

    fn append(&mut self, line: &[u8]) -> Option<()> {
        let metadata = self.file.metadata().ok()?;
        if !self.is_private_file(&metadata)
            || metadata.len() != self.length
            || line.len() as u64 > MAX_MANAGED_PHASE_BYTES
        {
            return None;
        }
        if self.length + line.len() as u64 > MAX_MANAGED_PHASE_BYTES {
            // Reuse this same private inode: no stale generations or unlinked
            // descriptors can accumulate over the hour-long resident lifetime.
            self.file.set_len(0).ok()?;
            self.file.rewind().ok()?;
            self.length = 0;
        }
        self.file.write_all(line).ok()?;
        self.length += line.len() as u64;
        Some(())
    }
}

enum PhaseOutput {
    HelperStderr,
    ManagedFile(Option<ManagedPhaseFile>),
}

static PHASE_OUTPUT: LazyLock<Mutex<PhaseOutput>> =
    LazyLock::new(|| Mutex::new(PhaseOutput::HelperStderr));

pub(crate) struct ManagedPhaseLifetime;

impl Drop for ManagedPhaseLifetime {
    fn drop(&mut self) {
        *PHASE_OUTPUT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PhaseOutput::ManagedFile(None);
        // Keep the capped file after retirement for a client's timeout tail;
        // only the resident's descriptor and ownership end here.
    }
}

pub(crate) fn install_managed_sink(
    state_base: &Path,
    owner: &crate::managed_resident::ManagedOwnerLock,
) -> Option<ManagedPhaseLifetime> {
    if !enabled() {
        return None;
    }
    let mut sink = PHASE_OUTPUT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(*sink, PhaseOutput::ManagedFile(Some(_))) {
        return None;
    }
    let file = ManagedPhaseFile::open(state_base, owner);
    let lifetime = file.as_ref().map(|_| ManagedPhaseLifetime);
    *sink = PhaseOutput::ManagedFile(file);
    lifetime
}

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
    // Render only finite phase/status labels and elapsed time into a bounded
    // stack buffer. Helper stderr and the shared resident sink stay separate.
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
        let mut sink = PHASE_OUTPUT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *sink {
            PhaseOutput::ManagedFile(file) => {
                if file
                    .as_mut()
                    .is_some_and(|file| file.append(&line[..length]).is_none())
                {
                    // Refuse an unlinked, altered, non-private, or broken sink.
                    // Diagnostic I/O must never change native wire results.
                    *file = None;
                }
            }
            PhaseOutput::HelperStderr => {
                let _ = std::io::stderr().lock().write_all(&line[..length]);
            }
        }
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
