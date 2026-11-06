//! Fresh user-wide process/thread headroom without spawning a measurement tool.
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const MESSAGE: &str =
    "The desktop process budget could not be measured; protected execution was not started.";

pub(crate) fn evaluate(deadline: Instant) -> Value {
    if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
        return json!({"value":64});
    }
    let deadline = deadline.min(Instant::now() + Duration::from_secs(3));
    match measure(deadline).and_then(ceiling) {
        Ok(value) => json!({"value":value}),
        Err(()) => json!({"reason_code":"pytest_restricted_sandbox_unavailable","message":MESSAGE}),
    }
}

fn ceiling(existing: u64) -> Result<u64, ()> {
    // The old `ps -U` snapshot included its own one-process measurement probe.
    // Retain that slot while preserving the original 64-unit execution margin.
    existing
        .checked_add(1)
        .and_then(|v| v.checked_add(64))
        .ok_or(())
}

#[cfg(target_os = "macos")]
fn measure(deadline: Instant) -> Result<u64, ()> {
    let pids = libproc::processes::pids_by_type(libproc::processes::ProcFilter::ByRealUID {
        ruid: nix::unistd::getuid().as_raw(),
    })
    .map_err(|_| ())?;
    if Instant::now() >= deadline || pids.is_empty() {
        return Err(());
    }
    Ok(pids.len() as u64)
}

#[cfg(target_os = "linux")]
fn status_bytes(reader: impl std::io::Read) -> Result<Option<Vec<u8>>, ()> {
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(reader, 65537);
    match std::io::Read::read_to_end(&mut bounded, &mut bytes) {
        Ok(_) if bytes.len() <= 65536 => Ok(Some(bytes)),
        Err(error)
            if error.raw_os_error() == Some(libc::ESRCH)
                || error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        _ => Err(()),
    }
}

#[cfg(target_os = "linux")]
fn status_threads(bytes: &[u8], uid: u32) -> Result<Option<u64>, ()> {
    let field = |prefix: &[u8]| {
        bytes
            .split(|byte| *byte == b'\n')
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|line| std::str::from_utf8(line).ok())
    };
    let real_uid = field(b"Uid:")
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(())?;
    if real_uid != uid {
        return Ok(None);
    }
    field(b"Threads:")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Some)
        .ok_or(())
}

#[cfg(target_os = "linux")]
fn measure(deadline: Instant) -> Result<u64, ()> {
    use std::fs::File;
    let uid = nix::unistd::getuid().as_raw();
    let mut total = 0u64;
    for entry in std::fs::read_dir("/proc").map_err(|_| ())? {
        if Instant::now() >= deadline {
            return Err(());
        }
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|v| v.is_ascii_digit()) {
            continue;
        }
        let file = match File::open(entry.path().join("status")) {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue
            }
            Err(_) => return Err(()),
        };
        let Some(bytes) = status_bytes(file)? else {
            continue;
        };
        let Some(threads) = status_threads(&bytes, uid)? else {
            continue;
        };
        total = total.checked_add(threads).ok_or(())?;
    }
    if total == 0 || Instant::now() >= deadline {
        return Err(());
    }
    Ok(total)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn measure(_deadline: Instant) -> Result<u64, ()> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_process_snapshot_headroom() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../guard-command/tests/fixtures/contained_execution_parity.json"
        ))
        .unwrap();
        let mut count = 0;
        for case in vectors["cases"].as_array().unwrap() {
            if case["operation"] == "process_ceiling_snapshot" {
                assert_eq!(
                    json!({"value":ceiling(case["input"]["existing"].as_u64().unwrap()).unwrap()}),
                    case["expected"]
                );
                count += 1;
            }
        }
        assert!(count >= 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exiting_process_is_omitted_but_io_errors_and_oversized_status_fail_closed() {
        struct FailedRead(i32);
        impl std::io::Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(self.0))
            }
        }
        assert!(status_bytes(FailedRead(libc::ESRCH)).unwrap().is_none());
        assert!(status_bytes(FailedRead(libc::ENOENT)).unwrap().is_none());
        assert!(status_bytes(FailedRead(libc::EIO)).is_err());
        assert!(status_bytes(std::io::repeat(b'a')).is_err());
        assert_eq!(
            status_bytes(&b"Uid:\t1000\nThreads:\t2\n"[..])
                .unwrap()
                .unwrap(),
            b"Uid:\t1000\nThreads:\t2\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_names_do_not_change_numeric_status_evidence() {
        let status = b"Name:\tbroken-\xf0\x9f\nUid:\t1000\t1000\t1000\t1000\nThreads:\t2\n";
        assert_eq!(status_threads(status, 1000), Ok(Some(2)));
        assert_eq!(status_threads(status, 1001), Ok(None));
        assert_eq!(
            status_threads(b"Name:\xff\nUid:\t1001\nThreads:\xff\n", 1000),
            Ok(None)
        );
        assert!(status_threads(b"Name:\xff\nThreads:\t2\n", 1000).is_err());
        assert!(status_threads(b"Uid:\xff\nThreads:\t2\n", 1000).is_err());
        assert!(status_threads(b"Uid:\t1000\nThreads:\xff\n", 1000).is_err());
        assert!(status_threads(b"Uid:\t1000\n", 1000).is_err());
    }
}
