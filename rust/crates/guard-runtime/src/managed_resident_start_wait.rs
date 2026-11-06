#![forbid(unsafe_code)]

use std::time::Instant;

use super::{containment, CLIENT_RETRY_DELAY};

/// Wait for an authenticated response, not for a child that has already exited.
/// Errors still pass through the caller's identity-bound generation cleanup.
pub(super) fn wait_for_response(
    child: &mut containment::SpawnedManaged,
    deadline: Instant,
    poll_response: impl FnMut() -> Result<Option<Vec<u8>>, String>,
) -> Result<Vec<u8>, String> {
    wait_with(deadline, poll_response, || {
        containment::spawned_has_exited(child)
    })
}

fn wait_with(
    deadline: Instant,
    mut poll_response: impl FnMut() -> Result<Option<Vec<u8>>, String>,
    mut exited: impl FnMut() -> Result<bool, String>,
) -> Result<Vec<u8>, String> {
    loop {
        if Instant::now() >= deadline {
            return Err("native_resident_start_timeout".to_owned());
        }
        // Discovery and authentication remain authoritative. Another resident
        // may answer even if this spawn lost the race for the owner lock.
        if let Some(response) = poll_response()? {
            return Ok(response);
        }
        if exited()? {
            // Even a successful exit cannot serve a request. Use a registered,
            // finite code; do not forward child stderr, exit values or paths.
            return Err("native_resident_managed_exit_failed".to_owned());
        }
        std::thread::sleep(
            CLIENT_RETRY_DELAY.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn exited_child_fails_on_first_poll_without_waiting_for_timeout() {
        let mut polls = 0;
        let result = wait_with(
            deadline(),
            || {
                polls += 1;
                Ok(None)
            },
            || Ok(true),
        );
        assert_eq!(result.unwrap_err(), "native_resident_managed_exit_failed");
        assert_eq!(polls, 1);
    }

    #[test]
    fn live_child_can_publish_after_multiple_polls() {
        let mut polls = 0;
        let result = wait_with(
            deadline(),
            || {
                polls += 1;
                Ok((polls == 3).then(|| b"authenticated response".to_vec()))
            },
            || Ok(false),
        );
        assert_eq!(result.unwrap(), b"authenticated response");
        assert_eq!(polls, 3);
    }

    #[test]
    fn child_exit_after_an_initial_live_probe_stops_waiting() {
        let mut probes = 0;
        let result = wait_with(
            deadline(),
            || Ok(None),
            || {
                probes += 1;
                Ok(probes == 2)
            },
        );
        assert_eq!(result.unwrap_err(), "native_resident_managed_exit_failed");
        assert_eq!(probes, 2);
    }

    #[test]
    fn live_child_without_a_response_still_times_out() {
        let result = wait_with(
            Instant::now() + Duration::from_millis(2),
            || Ok(None),
            || Ok(false),
        );
        assert_eq!(result.unwrap_err(), "native_resident_start_timeout");
    }

    #[test]
    fn authenticated_response_wins_over_spawn_exit() {
        let result = wait_with(
            deadline(),
            || Ok(Some(b"authenticated response".to_vec())),
            || panic!("no liveness probe needed once a resident answered"),
        );
        assert_eq!(result.unwrap(), b"authenticated response");
    }

    #[test]
    fn discovery_and_process_probe_errors_remain_failures() {
        let result = wait_with(
            deadline(),
            || Err("native_resident_state_invalid".to_owned()),
            || panic!("discovery failure must not be hidden"),
        );
        assert_eq!(result.unwrap_err(), "native_resident_state_invalid");
        let result = wait_with(
            deadline(),
            || Ok(None),
            || Err("native_resident_supervisor_wait_failed".to_owned()),
        );
        assert_eq!(
            result.unwrap_err(),
            "native_resident_supervisor_wait_failed"
        );
    }

    #[test]
    fn expired_deadline_does_not_probe_or_send() {
        let result = wait_with(
            Instant::now(),
            || panic!("deadline expired"),
            || panic!("deadline expired"),
        );
        assert_eq!(result.unwrap_err(), "native_resident_start_timeout");
    }

    #[cfg(unix)]
    #[test]
    fn process_probe_distinguishes_live_child_from_successful_exit() {
        use std::process::{Command, Stdio};

        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(!containment::spawned_has_exited(&mut child).unwrap());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(containment::spawned_has_exited(&mut child).unwrap());
        assert_eq!(
            wait_for_response(&mut child, deadline(), || Ok(None)).unwrap_err(),
            "native_resident_managed_exit_failed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exited_child_is_reaped_and_generation_cleanup_still_runs() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-start-exit-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let invalid_scope = root.join("not-a-directory");
        std::fs::write(&invalid_scope, b"invalid scope").unwrap();
        for scope in [&root, &invalid_scope] {
            let mut child = std::process::Command::new("/bin/false").spawn().unwrap();
            // Synchronize the fixture, avoiding a scheduler-dependent exit race.
            assert!(!child.wait().unwrap().success());
            assert_eq!(
                wait_for_response(&mut child, deadline(), || Ok(None)).unwrap_err(),
                "native_resident_managed_exit_failed"
            );
            assert_eq!(
                containment::abort_spawned_managed(
                    &mut child,
                    scope,
                    &"0".repeat(64),
                    1,
                    &[0; crate::AUTH_TOKEN_BYTES],
                    deadline(),
                ),
                Err("native_resident_spawn_containment_failed".to_owned())
            );
            assert!(child.try_wait().unwrap().is_some());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
