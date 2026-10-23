//! Bounded worker half of the prelaunch pin/ack exchange. It does not start a
//! controller or choose a transport; the reviewed dispatcher must own both FDs.

use super::ControllerExecError;
use crate::BoottimeDeadline;
use gauntlet_contracts::{PrelaunchPrepared, WorkerAction, WorkerRequest};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_FRAME_BYTES: usize = 1024;
const MAX_HANDOFF_TIME: Duration = Duration::from_secs(60);
const MAX_POLL: Duration = Duration::from_millis(200);

fn ready(
    fd: libc::c_int,
    events: libc::c_short,
    deadline: &BoottimeDeadline,
    handoff_expires: Instant,
    cancellation: &AtomicBool,
) -> Result<(), ControllerExecError> {
    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(ControllerExecError::Cancelled);
        }
        let budget = deadline
            .remaining()
            .map_err(ControllerExecError::Deadline)?
            .min(handoff_expires.saturating_duration_since(Instant::now()));
        if budget.is_zero() {
            return Err(ControllerExecError::PrelaunchExpired);
        }
        let millis = budget.min(MAX_POLL).as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized descriptor without owning it.
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ControllerExecError::HostPipeUnavailable);
        }
        if result == 0 {
            continue;
        }
        if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(ControllerExecError::HostPipeUnavailable);
        }
        if descriptor.revents & events != 0
            || events == libc::POLLIN && descriptor.revents & libc::POLLHUP != 0
        {
            return Ok(());
        }
        if descriptor.revents & libc::POLLHUP != 0 {
            return Err(ControllerExecError::HostPipeUnavailable);
        }
    }
}

fn write_frame(
    fd: libc::c_int,
    bytes: &[u8],
    deadline: &BoottimeDeadline,
    expires: Instant,
    cancellation: &AtomicBool,
) -> Result<(), ControllerExecError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ControllerExecError::HostPipeTooLarge);
    }
    for byte in bytes.iter().copied().chain(std::iter::once(b'\n')) {
        loop {
            ready(fd, libc::POLLOUT, deadline, expires, cancellation)?;
            // SAFETY: write reads one initialized local byte.
            let count = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
            if count == 1 {
                break;
            }
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
            }
            return Err(ControllerExecError::HostPipeUnavailable);
        }
    }
    Ok(())
}

fn read_frame(
    fd: libc::c_int,
    deadline: &BoottimeDeadline,
    expires: Instant,
    cancellation: &AtomicBool,
) -> Result<Vec<u8>, ControllerExecError> {
    let mut bytes = Vec::new();
    loop {
        ready(fd, libc::POLLIN, deadline, expires, cancellation)?;
        let mut byte = 0u8;
        // SAFETY: read writes at most one byte into this initialized local.
        let count = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if count == 0 {
            return Err(ControllerExecError::HostPipeUnavailable);
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(ControllerExecError::HostPipeUnavailable);
        }
        if byte == b'\n' {
            if bytes.is_empty() {
                return Err(ControllerExecError::HostPipeUnavailable);
            }
            return Ok(bytes);
        }
        bytes.push(byte);
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ControllerExecError::HostPipeTooLarge);
        }
    }
}

/// Send one canonical prepared frame and await the matching host ack. Both
/// the active-run CLOCK_BOOTTIME budget and a 60-second handoff cap apply.
/// The caller must retain the resulting uncertainty if the ack is lost.
pub fn exchange_prelaunch_pipe(
    prepared_raw: &[u8],
    prepared_writer: &impl AsRawFd,
    ack_reader: &impl AsRawFd,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<Vec<u8>, ControllerExecError> {
    let prepared =
        PrelaunchPrepared::parse(prepared_raw).map_err(ControllerExecError::HostHandoff)?;
    let budget = deadline
        .remaining()
        .map_err(ControllerExecError::Deadline)?
        .min(MAX_HANDOFF_TIME);
    if budget.is_zero() {
        return Err(ControllerExecError::PrelaunchExpired);
    }
    let expires = Instant::now() + budget;
    write_frame(
        prepared_writer.as_raw_fd(),
        prepared_raw,
        deadline,
        expires,
        cancellation,
    )?;
    let acknowledgement = read_frame(ack_reader.as_raw_fd(), deadline, expires, cancellation)?;
    prepared
        .verify_acknowledgement(&acknowledgement)
        .map_err(ControllerExecError::HostHandoff)?;
    Ok(acknowledgement)
}

/// Read one bounded, canonical `run` request on the same pipe used later for
/// the host acknowledgement. The caller must compare the request to its own
/// outside deployment and one-use job pins before doing any reservation.
pub fn read_run_request_pipe(
    request_reader: &impl AsRawFd,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<WorkerRequest, ControllerExecError> {
    let budget = deadline
        .remaining()
        .map_err(ControllerExecError::Deadline)?
        .min(MAX_HANDOFF_TIME);
    if budget.is_zero() {
        return Err(ControllerExecError::PrelaunchExpired);
    }
    let raw = read_frame(
        request_reader.as_raw_fd(),
        deadline,
        Instant::now() + budget,
        cancellation,
    )?;
    let request = WorkerRequest::parse(&raw).map_err(|_| ControllerExecError::InvalidPlan)?;
    if request.action() != WorkerAction::Run || request.to_json().to_string().as_bytes() != raw {
        return Err(ControllerExecError::InvalidPlan);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_contracts::canonicalize;
    use gauntlet_host_state::{HostControllerKeyPinJournal, HostPrelaunchIdentity};
    use serde_json::json;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn prepared() -> PrelaunchPrepared {
        PrelaunchPrepared {
            job_id: "a".repeat(16),
            source_sha: "b".repeat(40),
            deployment_digest: "c".repeat(64),
            worker_generation: "d".repeat(64),
            started_marker_sha256: "e".repeat(64),
            controller_key_pin_sha256: "f".repeat(64),
            controller_public_key_hex: "0".repeat(64),
        }
    }

    #[test]
    fn worker_accepts_one_canonical_run_request_and_refuses_other_actions() {
        let pins = prepared();
        let value = json!({
            "schema":"hol-gauntlet-worker-request.v1",
            "action":"run",
            "source_sha":pins.source_sha,
            "job_id":pins.job_id,
            "deployment_digest":pins.deployment_digest,
        });
        let mut raw = canonicalize(value.to_string().as_bytes()).unwrap();
        let (mut host, worker) = UnixStream::pair().unwrap();
        host.write_all(&raw).unwrap();
        host.write_all(b"\n").unwrap();
        let request = read_run_request_pipe(
            &worker,
            &BoottimeDeadline::start(10).unwrap(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(request.matches_deployment(&pins.source_sha, &pins.deployment_digest));

        let (mut host, worker) = UnixStream::pair().unwrap();
        raw.insert(0, b' ');
        host.write_all(&raw).unwrap();
        host.write_all(b"\n").unwrap();
        assert!(matches!(
            read_run_request_pipe(
                &worker,
                &BoottimeDeadline::start(10).unwrap(),
                &AtomicBool::new(false),
            ),
            Err(ControllerExecError::InvalidPlan)
        ));

        let (mut host, worker) = UnixStream::pair().unwrap();
        let progress = json!({
            "schema":"hol-gauntlet-worker-request.v1",
            "action":"progress",
            "source_sha":pins.source_sha,
            "job_id":pins.job_id,
        });
        host.write_all(&canonicalize(progress.to_string().as_bytes()).unwrap())
            .unwrap();
        host.write_all(b"\n").unwrap();
        assert!(matches!(
            read_run_request_pipe(
                &worker,
                &BoottimeDeadline::start(10).unwrap(),
                &AtomicBool::new(false),
            ),
            Err(ControllerExecError::InvalidPlan)
        ));
    }

    #[test]
    fn worker_accepts_only_ack_for_host_durable_planned_pin() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let pins = prepared();
        let expected = HostPrelaunchIdentity {
            job_id: pins.job_id.clone(),
            source_sha: pins.source_sha.clone(),
            deployment_digest: pins.deployment_digest.clone(),
            worker_generation: pins.worker_generation.clone(),
        };
        let raw = pins.to_bytes().unwrap();
        let (host, worker) = UnixStream::pair().unwrap();
        let host_root = root.clone();
        let host_thread = thread::spawn(move || {
            let journal = HostControllerKeyPinJournal::open(&host_root).unwrap();
            journal
                .accept_prepared_pipe(&host, &host, &expected, Duration::from_secs(2))
                .unwrap()
        });
        let ack = exchange_prelaunch_pipe(
            &raw,
            &worker,
            &worker,
            &BoottimeDeadline::start(10).unwrap(),
            &AtomicBool::new(false),
        )
        .unwrap();
        pins.verify_acknowledgement(&ack).unwrap();
        let record = host_thread.join().unwrap();
        assert_eq!(record.pins.job_id, pins.job_id);
        assert_eq!(
            record.pins.controller_public_key_hex,
            pins.controller_public_key_hex
        );
        assert_eq!(
            HostControllerKeyPinJournal::open(&root)
                .unwrap()
                .read(&pins.job_id),
            Ok(record)
        );
    }

    #[test]
    fn worker_refuses_wrong_ack_and_oversized_ack() {
        let raw = prepared().to_bytes().unwrap();
        let (mut host, worker) = UnixStream::pair().unwrap();
        let count = raw.len() + 1;
        let host_thread = thread::spawn(move || {
            let mut received = vec![0u8; count];
            host.read_exact(&mut received).unwrap();
            host.write_all(b"{}\n").unwrap();
        });
        assert!(matches!(
            exchange_prelaunch_pipe(
                &raw,
                &worker,
                &worker,
                &BoottimeDeadline::start(10).unwrap(),
                &AtomicBool::new(false),
            ),
            Err(ControllerExecError::HostHandoff(_))
        ));
        host_thread.join().unwrap();

        let (mut host, worker) = UnixStream::pair().unwrap();
        let count = raw.len() + 1;
        let host_thread = thread::spawn(move || {
            let mut received = vec![0u8; count];
            host.read_exact(&mut received).unwrap();
            host.write_all(&vec![b'x'; 1025]).unwrap();
        });
        let oversized = exchange_prelaunch_pipe(
            &raw,
            &worker,
            &worker,
            &BoottimeDeadline::start(10).unwrap(),
            &AtomicBool::new(false),
        );
        assert!(
            matches!(oversized, Err(ControllerExecError::HostPipeTooLarge)),
            "{oversized:?}"
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn worker_refuses_cancelled_or_unanswered_handoff() {
        let raw = prepared().to_bytes().unwrap();
        let (_host, worker) = UnixStream::pair().unwrap();
        assert!(matches!(
            exchange_prelaunch_pipe(
                &raw,
                &worker,
                &worker,
                &BoottimeDeadline::start(10).unwrap(),
                &AtomicBool::new(true),
            ),
            Err(ControllerExecError::Cancelled)
        ));
        let (_host, worker) = UnixStream::pair().unwrap();
        assert!(matches!(
            exchange_prelaunch_pipe(
                &raw,
                &worker,
                &worker,
                &BoottimeDeadline::start(1).unwrap(),
                &AtomicBool::new(false),
            ),
            Err(ControllerExecError::PrelaunchExpired)
        ));
    }
}
