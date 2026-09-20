use std::io;
use std::path::Path;
use std::time::Instant;

use guard_runtime_windows_process::ManagedChild;

use crate::resident_state::{
    discover_states, token_from_state, validate_runtime_process_identity, ResidentState,
};

pub(super) fn complete(
    child: &ManagedChild,
    scope: &Path,
    digest: &str,
    generation: u64,
    token: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let ready = || {
        let owner_marker = child
            .start_marker()
            .map_err(|_| "native_resident_spawn_handoff_identity_failed".to_owned())?;
        let ready = discover_states(scope, digest)?.into_iter().any(|state| {
            matches_readiness(&state, child.id(), &owner_marker, digest, generation, token)
                && validate_runtime_process_identity(
                    state.process_id,
                    &state.process_start_marker,
                    digest,
                )
                .is_ok()
        });
        if ready {
            Ok(())
        } else {
            Err("native_resident_spawn_handoff_identity_failed".to_owned())
        }
    };
    complete_handoff(
        ready,
        || Instant::now() < deadline,
        || child.allow_detached_lifetime(),
        || child.terminate_with_timeout(super::MANAGED_STOP_TIMEOUT),
    )
}

fn matches_readiness(
    state: &ResidentState,
    owner_id: u32,
    owner_marker: &str,
    digest: &str,
    generation: u64,
    token: &[u8],
) -> bool {
    state.generation == generation
        && state.owner_process_id == owner_id
        && state.owner_process_start_marker == owner_marker
        && state.runtime_sha256 == digest
        && token_from_state(state).is_ok_and(|actual| crate::constant_time_eq(&actual, token))
}

fn complete_handoff(
    ready: impl FnOnce() -> Result<(), String>,
    mut within_deadline: impl FnMut() -> bool,
    release_close_kill: impl FnOnce() -> io::Result<()>,
    cleanup: impl FnOnce() -> io::Result<()>,
) -> Result<(), String> {
    let result = (|| {
        if !within_deadline() {
            return Err("native_client_deadline_exceeded".to_owned());
        }
        ready()?;
        if !within_deadline() {
            return Err("native_client_deadline_exceeded".to_owned());
        }
        release_close_kill().map_err(|_| "native_resident_spawn_handoff_failed".to_owned())?;
        if !within_deadline() {
            return Err("native_client_deadline_exceeded".to_owned());
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(original) => match cleanup() {
            Ok(()) => Err(original),
            Err(_) => Err(format!("{original};native_resident_child_cleanup_failed")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn readiness_matches_only_the_started_supervisor_generation_and_token() {
        let state = ResidentState {
            schema: String::new(),
            generation: 7,
            process_id: 19,
            process_start_marker: "serving-marker".to_owned(),
            owner_process_id: 11,
            owner_process_start_marker: "owner-marker".to_owned(),
            runtime_sha256: "digest".to_owned(),
            transport: "loopback".to_owned(),
            endpoint: String::new(),
            token_hex: "5a".repeat(crate::AUTH_TOKEN_BYTES),
            created_ms: 1,
            state_mac: String::new(),
        };
        let token = [0x5a; crate::AUTH_TOKEN_BYTES];
        assert!(matches_readiness(
            &state,
            11,
            "owner-marker",
            "digest",
            7,
            &token
        ));
        assert!(!matches_readiness(
            &state,
            12,
            "owner-marker",
            "digest",
            7,
            &token
        ));
        assert!(!matches_readiness(
            &state,
            11,
            "reused-pid",
            "digest",
            7,
            &token
        ));
        assert!(!matches_readiness(
            &state,
            11,
            "owner-marker",
            "other",
            7,
            &token
        ));
        assert!(!matches_readiness(
            &state,
            11,
            "owner-marker",
            "digest",
            8,
            &token
        ));
        assert!(!matches_readiness(
            &state,
            11,
            "owner-marker",
            "digest",
            7,
            &[0x6b; crate::AUTH_TOKEN_BYTES]
        ));
    }

    #[test]
    fn handoff_requires_readiness_before_releasing_and_preserves_cleanup_failure() {
        for ready in [false, true] {
            for release_ok in [false, true] {
                for cleanup_ok in [false, true] {
                    let events = RefCell::new(Vec::new());
                    let result = complete_handoff(
                        || {
                            if ready {
                                Ok(())
                            } else {
                                Err("identity failed".to_owned())
                            }
                        },
                        || true,
                        || {
                            events.borrow_mut().push("release");
                            if release_ok {
                                Ok(())
                            } else {
                                Err(io::Error::other("release failed"))
                            }
                        },
                        || {
                            events.borrow_mut().push("cleanup");
                            if cleanup_ok {
                                Ok(())
                            } else {
                                Err(io::Error::other("cleanup failed"))
                            }
                        },
                    );
                    assert_eq!(result.is_ok(), ready && release_ok);
                    let expected = match (ready, release_ok) {
                        (false, _) => vec!["cleanup"],
                        (true, false) => vec!["release", "cleanup"],
                        (true, true) => vec!["release"],
                    };
                    assert_eq!(*events.borrow(), expected);
                    if let Err(error) = result {
                        assert_eq!(error.contains("child_cleanup_failed"), !cleanup_ok);
                        assert!(error.starts_with(if ready {
                            "native_resident_spawn_handoff_failed"
                        } else {
                            "identity failed"
                        }));
                    }
                }
            }
        }
    }

    #[test]
    fn deadline_expiry_before_proof_after_proof_and_after_disarm_all_clean_up() {
        use std::cell::Cell;
        for allowed_checks in 0..3 {
            for cleanup_fails in [false, true] {
                let checks = Cell::new(0);
                let events = RefCell::new(Vec::new());
                let error = complete_handoff(
                    || {
                        events.borrow_mut().push("proof");
                        Ok(())
                    },
                    || {
                        let check = checks.get();
                        checks.set(check + 1);
                        check < allowed_checks
                    },
                    || {
                        events.borrow_mut().push("disarm");
                        Ok(())
                    },
                    || {
                        events.borrow_mut().push("cleanup");
                        if cleanup_fails {
                            Err(io::Error::other("cleanup failed"))
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
                let expected = match allowed_checks {
                    0 => vec!["cleanup"],
                    1 => vec!["proof", "cleanup"],
                    _ => vec!["proof", "disarm", "cleanup"],
                };
                assert_eq!(*events.borrow(), expected);
                assert!(error.starts_with("native_client_deadline_exceeded"));
                assert_eq!(error.contains("child_cleanup_failed"), cleanup_fails);
            }
        }
    }
}
