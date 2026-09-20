#![forbid(unsafe_code)]

//! Opt-in, content-free client stages. No timing or success inference is made.
use std::cell::Cell;
use std::io::Write;

const ENVIRONMENT_KEY: &str = "HOL_GUARD_NATIVE_CLIENT_STAGE_DIAGNOSTIC";

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Stage {
    StreamEntry,
    LeaseAcquired,
    FrameRead,
    RequestEntry,
    Discovery,
    StartupLock,
    Spawn,
    Connect,
    Authenticate,
    RequestWritten,
    ResponseReceived,
    FrameWritten,
    LeaseDirectoryReady,
    LeaseProcessIdentified,
    LeaseRuntimeHashed,
    LeaseNonceReady,
    LeaseDirectoryLockAcquired,
    LeaseFileReady,
    LeaseDurable,
    LeaseRefused,
}

impl Stage {
    fn line(self) -> &'static [u8] {
        match self {
            Self::StreamEntry => b"guard_native_client_stage_v1=stream_entry\n",
            Self::LeaseAcquired => b"guard_native_client_stage_v1=lease_acquired\n",
            Self::FrameRead => b"guard_native_client_stage_v1=frame_read\n",
            Self::RequestEntry => b"guard_native_client_stage_v1=request_entry\n",
            Self::Discovery => b"guard_native_client_stage_v1=discovery\n",
            Self::StartupLock => b"guard_native_client_stage_v1=startup_lock\n",
            Self::Spawn => b"guard_native_client_stage_v1=spawn\n",
            Self::Connect => b"guard_native_client_stage_v1=connect\n",
            Self::Authenticate => b"guard_native_client_stage_v1=authenticate\n",
            Self::RequestWritten => b"guard_native_client_stage_v1=request_written\n",
            Self::ResponseReceived => b"guard_native_client_stage_v1=response_received\n",
            Self::FrameWritten => b"guard_native_client_stage_v1=frame_written\n",
            Self::LeaseDirectoryReady => b"guard_native_client_stage_v1=lease_directory_ready\n",
            Self::LeaseProcessIdentified => {
                b"guard_native_client_stage_v1=lease_process_identified\n"
            }
            Self::LeaseRuntimeHashed => b"guard_native_client_stage_v1=lease_runtime_hashed\n",
            Self::LeaseNonceReady => b"guard_native_client_stage_v1=lease_nonce_ready\n",
            Self::LeaseDirectoryLockAcquired => {
                b"guard_native_client_stage_v1=lease_directory_lock_acquired\n"
            }
            Self::LeaseFileReady => b"guard_native_client_stage_v1=lease_file_ready\n",
            Self::LeaseDurable => b"guard_native_client_stage_v1=lease_durable\n",
            Self::LeaseRefused => b"guard_native_client_stage_v1=lease_refused\n",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Observation {
    enabled: bool,
    seen: u32,
}

impl Observation {
    fn take(&mut self, stage: Stage) -> Option<&'static [u8]> {
        let bit = 1 << stage as u8;
        if !self.enabled || self.seen & bit != 0 {
            return None;
        }
        self.seen |= bit;
        Some(stage.line())
    }
}

thread_local! {
    // Stream scope and deduplication never cross threads or parallel tests.
    static OBSERVATION: Cell<Observation> = Cell::new(Observation::default());
}

pub(super) struct Scope(Observation);

fn enabled(value: Option<std::ffi::OsString>) -> bool {
    value.is_some_and(|value| value == "1")
}

pub(super) fn begin() -> Scope {
    let enabled = enabled(std::env::var_os(ENVIRONMENT_KEY));
    Scope(OBSERVATION.replace(Observation { enabled, seen: 0 }))
}

impl Drop for Scope {
    fn drop(&mut self) {
        OBSERVATION.set(self.0);
    }
}

pub(crate) fn record(stage: Stage) {
    let line = OBSERVATION.with(|cell| {
        let mut observation = cell.get();
        let line = observation.take(stage);
        cell.set(observation);
        line
    });
    if let Some(line) = line {
        // At most 20 fixed lines (< 1 KiB) over this stream's entire lifetime.
        // A diagnostic sink failure never changes the actual request outcome.
        let _ = std::io::stderr().write_all(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGES: [Stage; 20] = [
        Stage::StreamEntry,
        Stage::LeaseAcquired,
        Stage::FrameRead,
        Stage::RequestEntry,
        Stage::Discovery,
        Stage::StartupLock,
        Stage::Spawn,
        Stage::Connect,
        Stage::Authenticate,
        Stage::RequestWritten,
        Stage::ResponseReceived,
        Stage::FrameWritten,
        Stage::LeaseDirectoryReady,
        Stage::LeaseProcessIdentified,
        Stage::LeaseRuntimeHashed,
        Stage::LeaseNonceReady,
        Stage::LeaseDirectoryLockAcquired,
        Stage::LeaseFileReady,
        Stage::LeaseDurable,
        Stage::LeaseRefused,
    ];

    #[test]
    fn default_is_silent_and_opt_in_is_finite_and_deduplicated() {
        let mut disabled = Observation::default();
        let mut enabled = Observation {
            enabled: true,
            seen: 0,
        };
        let mut output = Vec::new();
        for _ in 0..100 {
            for stage in STAGES {
                assert!(disabled.take(stage).is_none());
                if let Some(line) = enabled.take(stage) {
                    output.extend_from_slice(line);
                }
            }
        }
        assert!(output.len() < 1024);
        assert_eq!(output.len(), 892);
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 20);
        assert!(output
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || b"_=1\n".contains(byte)));
    }

    #[test]
    fn only_exact_opt_in_is_admitted() {
        assert!(!enabled(None));
        for value in ["", "true", "0", " 1", "1 ", "private-canary"] {
            assert!(!enabled(Some(value.into())));
        }
        assert!(enabled(Some("1".into())));
    }

    #[test]
    fn observation_is_thread_local_and_scope_restores_previous_state() {
        OBSERVATION.set(Observation {
            enabled: true,
            seen: 7,
        });
        std::thread::spawn(|| {
            assert!(!OBSERVATION.get().enabled);
            OBSERVATION.set(Observation {
                enabled: true,
                seen: 9,
            });
        })
        .join()
        .unwrap();
        assert_eq!(OBSERVATION.get().seen, 7);
        drop(Scope(Observation::default()));
        assert!(!OBSERVATION.get().enabled);
    }
}
