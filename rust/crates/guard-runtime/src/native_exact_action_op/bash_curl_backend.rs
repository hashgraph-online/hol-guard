//! A bounded metadata probe of the immutable system image. It runs no script
//! and has no network or user-file contents access. Cache only backend availability,
//! never permission, risk, request contents or mutable configuration.
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{atomic::AtomicBool, Mutex, OnceLock};
use std::time::{Duration, Instant};

use guard_contained_process::{Isolation, PinnedCommand};

const UNAVAILABLE: &str = "bash_curl_backend_unavailable";

pub(super) fn verify(
    image: &PinnedCommand,
    cwd: &Path,
    deadline: Instant,
) -> Result<(), &'static str> {
    static KNOWN: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let cache = KNOWN.get_or_init(Mutex::default);
    if !image.has_readonly_system_image().map_err(|_| UNAVAILABLE)?
        || image.effective_executable_path() != Path::new("/usr/bin/curl")
    {
        return Err(UNAVAILABLE);
    }
    // A single cold metadata probe serves concurrent captures of this
    // immutable image, rather than launching duplicate inspection processes.
    let mut known = cache.lock().map_err(|_| UNAVAILABLE)?;
    if known.contains(&image.executable_digest) {
        return Ok(());
    }
    let cwd_literal =
        serde_json::to_string(cwd.to_str().ok_or(UNAVAILABLE)?).map_err(|_| UNAVAILABLE)?;
    let profile = format!(
        r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec (literal "/usr/bin/curl"))
(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/dev") (literal "/usr/bin/curl"))
(allow file-read-metadata)
(allow file-read-data (literal {cwd_literal}))
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") (literal "/usr/bin/curl"))
(allow sysctl-read)
(allow mach-lookup)"#
    );
    let command = PinnedCommand::new(
        Path::new("/usr/bin/curl"),
        &[OsStr::new("-q"), OsStr::new("--version")],
        cwd,
        &[
            ("CURL_SSL_BACKEND".into(), "secure-transport".into()),
            ("LANG".into(), "C".into()),
        ],
    )
    .map_err(|_| UNAVAILABLE)?;
    if command.executable_digest != image.executable_digest
        || !command
            .has_readonly_system_image()
            .map_err(|_| UNAVAILABLE)?
    {
        return Err(UNAVAILABLE);
    }
    let result = command
        .capture(
            &[],
            8192,
            deadline.min(Instant::now() + Duration::from_millis(500)),
            &AtomicBool::new(false),
            Isolation {
                seatbelt: Some(profile),
                ..Default::default()
            },
        )
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                "bash_curl_backend_probe_deadline"
            } else {
                "bash_curl_backend_probe_failed"
            }
        })?;
    if result.timed_out {
        return Err("bash_curl_backend_probe_deadline");
    }
    let text = std::str::from_utf8(&result.stdout).map_err(|_| UNAVAILABLE)?;
    if result.exit_code != Some(0)
        || result.timed_out
        || result.cancelled
        || result.output_limited
        || !result.stderr.is_empty()
        || !text
            .lines()
            .next()
            .is_some_and(|line| line.contains(" SecureTransport "))
        || !text.lines().any(|line| {
            line.starts_with("Features:") && line.split_whitespace().any(|word| word == "MultiSSL")
        })
    {
        return Err(UNAVAILABLE);
    }
    if known.len() >= 16 {
        known.clear();
    }
    known.insert(image.executable_digest.clone());
    Ok(())
}
