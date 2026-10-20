#![forbid(unsafe_code)]

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const MAX_RUNTIME_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) fn executable_missing(path: &Path) -> bool {
    path.metadata()
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(windows)]
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    guard_runtime_windows_process::process_start_marker(process_id)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

/// Start marker of a process that has not exited. On Windows an exited process
/// keeps answering `process_start_marker` while any handle to it is open.
#[cfg(windows)]
pub(crate) fn running_process_start_marker(process_id: u32) -> Result<String, String> {
    guard_runtime_windows_process::running_process_start_marker(process_id)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(not(windows))]
pub(crate) fn running_process_start_marker(process_id: u32) -> Result<String, String> {
    process_start_marker(process_id)
}

/// Return the parent captured while a legacy supervisor is starting.
///
/// The current launcher passes an explicit owner identity. This fallback keeps
/// older seven-argument supervisor invocations bounded to the one-shot
/// launcher that created them, instead of making the supervisor its own
/// lifetime owner after that launcher exits.
pub(crate) fn parent_process_id() -> Option<u32> {
    process_parent_id(std::process::id())
}

/// Return the current parent of any process, if it is still running.
fn process_parent_id(process_id: u32) -> Option<u32> {
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system
        .process(pid)
        .and_then(|process| process.parent())
        .map(|parent| parent.as_u32())
        .filter(|parent| *parent > 0)
}

#[cfg(not(windows))]
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    if let Some(marker) = linux_process_start_marker(process_id) {
        return Ok(marker);
    }
    #[cfg(target_os = "macos")]
    if let Some(marker) = darwin_process_start_marker(process_id) {
        return Ok(marker);
    }
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always),
    );
    let process = system
        .process(pid)
        .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())?;
    Ok(format!("posix:{}", process.start_time()))
}

/// Prove that a process no longer exists without treating identity lookup
/// errors as proof of death.
#[cfg(unix)]
pub(crate) fn process_is_definitively_gone(process_id: u32) -> Result<bool, String> {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    if process_id == 0 || process_id > i32::MAX as u32 {
        return Ok(true);
    }
    match kill(Pid::from_raw(process_id as i32), None) {
        Ok(()) | Err(Errno::EPERM) | Err(Errno::EACCES) => Ok(false),
        Err(Errno::ESRCH) => Ok(true),
        Err(_) => Err("native_resident_process_identity_unavailable".to_owned()),
    }
}

#[cfg(windows)]
pub(crate) fn process_is_definitively_gone(process_id: u32) -> Result<bool, String> {
    guard_runtime_windows_process::wait_for_process_exit(process_id, std::time::Duration::ZERO)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn process_is_definitively_gone(_process_id: u32) -> Result<bool, String> {
    Err("native_resident_process_identity_unavailable".to_owned())
}

#[cfg(target_os = "macos")]
fn darwin_process_start_marker(process_id: u32) -> Option<String> {
    let info =
        libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(process_id as i32, 0).ok()?;
    Some(format!(
        "darwin:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(target_os = "linux")]
fn linux_process_start_marker(process_id: u32) -> Option<String> {
    let contents = fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
    let (_, suffix) = contents.rsplit_once(')')?;
    let start_ticks = suffix.split_whitespace().nth(19)?.parse::<u64>().ok()?;
    Some(format!("linux:{start_ticks}"))
}

pub(crate) fn validate_package_process_identity(
    process_id: u32,
    expected_start_marker: &str,
) -> Result<(), String> {
    let process_path = process_executable_path(process_id)?;
    let expected_path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    if process_path != expected_path {
        // Onefile launchers extract identical signed runtimes into distinct
        // directories. Bind to the runtime bytes, not that temporary path.
        return crate::resident_runtime_verification::validate_process_runtime_digest(
            process_id,
            expected_start_marker,
            process_path,
            &crate::resident_state::runtime_digest()?,
        );
    }
    validate_process_start_marker(process_id, expected_start_marker)
}

/// The process runs the same runtime as this caller and started as recorded.
///
/// Unlike `validate_package_process_identity` this never hashes a runtime, so
/// a short-lived caller on the hook path can afford it. The process qualifies
/// by running this very executable path, or by being recorded under the digest
/// that this executable's own durable copy is published as.
pub(crate) fn validate_direct_lane_process_identity(
    process_id: u32,
    expected_start_marker: &str,
    state_runtime_digest: &str,
    durable_digest: Option<&str>,
) -> Result<(), String> {
    let process_path = process_executable_path(process_id)?;
    let expected_path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    if process_path != expected_path
        && !durable_digest.is_some_and(|digest| {
            crate::constant_time_eq(digest.as_bytes(), state_runtime_digest.as_bytes())
        })
    {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    validate_process_start_marker(process_id, expected_start_marker)
}

/// This executable's runtime digest when it runs as a durable copy published
/// directly under `state_base`, read from the copy's directory name.
///
/// An installed frozen Guard names `<guard_home>/native-runtime/<digest>/…` in
/// every harness hook command, because a onefile extraction directory vanishes
/// with its launcher and an application bundle moves between updates. The
/// resident those hooks are meant to reach is started from the bundle itself,
/// so both processes run identical bytes from different paths and a path
/// comparison rejects every resident. The directory holding the copy is the
/// owner-only state root that already carries that resident's endpoint and
/// token, so the name it was published under identifies the copy's bytes as
/// well as hashing the file would, and costs no read.
pub(crate) fn durable_runtime_digest(state_base: &Path) -> Option<String> {
    let executable = std::env::current_exe().and_then(fs::canonicalize).ok()?;
    durable_digest_for(&executable, state_base)
}

fn durable_digest_for(executable: &Path, state_base: &Path) -> Option<String> {
    let directory = executable.parent()?;
    let digest = directory.file_name()?.to_str()?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let base = fs::canonicalize(state_base).ok()?;
    (directory.parent()? == base.as_path()).then(|| digest.to_ascii_lowercase())
}

pub(crate) fn validate_runtime_process_identity(
    process_id: u32,
    expected_start_marker: &str,
    expected_digest: &str,
) -> Result<(), String> {
    let process_path = process_executable_path(process_id)?;
    crate::resident_runtime_verification::validate_process_runtime_digest(
        process_id,
        expected_start_marker,
        process_path,
        expected_digest,
    )
}

pub(crate) fn validate_process_start_marker(
    process_id: u32,
    expected_start_marker: &str,
) -> Result<(), String> {
    let actual_start_marker = process_start_marker(process_id)?;
    if !crate::constant_time_eq(
        actual_start_marker.as_bytes(),
        expected_start_marker.as_bytes(),
    ) {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    let path = libproc::proc_pid::pidpath(process_id as i32)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    fs::canonicalize(path).map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    fs::canonicalize(format!("/proc/{process_id}/exe"))
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(windows)]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    let executable = guard_runtime_windows_process::running_process_image_path(process_id)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    fs::canonicalize(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always),
    );
    let executable = system
        .process(pid)
        .and_then(|process| process.exe())
        .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())?;
    fs::canonicalize(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

pub(crate) fn executable_digest(executable: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || (metadata.len() > MAX_RUNTIME_BYTES && !cfg!(test))
    {
        return Err("native_resident_process_identity_unavailable".to_owned());
    }
    let mut file = File::open(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    crate::resident_state_encoding::sha256_hex_from_reader(&mut file)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(all(test, unix))]
mod direct_lane_identity_tests {
    use super::{
        process_executable_path, process_start_marker, validate_direct_lane_process_identity,
    };
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const DIGEST: &str = "c29d7715f8a2bcfc00112233445566778899aabbccddeeff0011223344556677";
    const OTHER: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    struct Sleeper(Child);

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for_executable(
        expected: &Path,
        timeout: Duration,
        mut executable: impl FnMut() -> Result<PathBuf, String>,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            let actual = executable();
            if actual.as_deref() == Ok(expected) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "child executable did not become ready: {actual:?}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    // Process metadata can still expose the forked test executable after spawn.
    // Require the final executable before making identity assertions.
    fn sleeper() -> Sleeper {
        let sleeper = Sleeper(
            Command::new("/bin/sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn a process running another executable"),
        );
        let expected = std::fs::canonicalize("/bin/sleep").expect("resolve sleep executable");
        wait_for_executable(&expected, Duration::from_secs(2), || {
            process_executable_path(sleeper.0.id())
        });
        sleeper
    }

    #[test]
    fn readiness_waits_for_the_final_executable_after_transient_metadata() {
        let expected = PathBuf::from("final-executable");
        let mut states = std::collections::VecDeque::from([
            Err("executable not visible yet".to_owned()),
            Ok(PathBuf::from("inherited-executable")),
            Ok(expected.clone()),
        ]);
        wait_for_executable(&expected, Duration::from_secs(2), || {
            states
                .pop_front()
                .expect("polled beyond the final executable")
        });
        assert!(states.is_empty());
    }

    #[test]
    fn readiness_refuses_to_succeed_when_the_executable_never_matches() {
        let result = std::panic::catch_unwind(|| {
            wait_for_executable(Path::new("final-executable"), Duration::ZERO, || {
                Ok(PathBuf::from("inherited-executable"))
            });
        });
        assert!(result.is_err());
    }

    #[test]
    fn accepts_another_executable_recorded_under_this_durable_digest() {
        let sleeper = sleeper();
        let process_id = sleeper.0.id();
        let marker = process_start_marker(process_id).expect("read the start marker");
        assert_eq!(
            validate_direct_lane_process_identity(process_id, &marker, DIGEST, Some(DIGEST)),
            Ok(())
        );
    }

    #[test]
    fn refuses_another_executable_without_a_matching_durable_digest() {
        let sleeper = sleeper();
        let process_id = sleeper.0.id();
        let marker = process_start_marker(process_id).expect("read the start marker");
        for durable in [None, Some(OTHER)] {
            assert_eq!(
                validate_direct_lane_process_identity(process_id, &marker, DIGEST, durable),
                Err("native_resident_process_identity_mismatch".to_owned())
            );
        }
    }

    #[test]
    fn refuses_a_recorded_start_marker_that_no_longer_matches() {
        let sleeper = sleeper();
        let process_id = sleeper.0.id();
        assert_eq!(
            validate_direct_lane_process_identity(process_id, "darwin:0:0", DIGEST, Some(DIGEST)),
            Err("native_resident_process_identity_mismatch".to_owned())
        );
    }
}

#[cfg(test)]
mod durable_digest_tests {
    use super::durable_digest_for;
    use std::fs;
    use std::path::{Path, PathBuf};

    const DIGEST: &str = "c29d7715f8a2bcfc00112233445566778899aabbccddeeff0011223344556677";

    /// A copy under `base`, named `directory`, as the canonicalized
    /// `current_exe` of `durable_runtime_digest` reaches the function: a
    /// temporary directory is itself a symlink on macOS, and a verbatim path
    /// on Windows, so an executable built from the raw path never has the
    /// canonical base as its grandparent.
    fn published(base: &Path, directory: &str) -> PathBuf {
        let root = fs::canonicalize(base).expect("canonicalize state base");
        let parent = root.join(directory);
        fs::create_dir(&parent).expect("create runtime directory");
        let executable = parent.join("hol-guard-runtime");
        fs::write(&executable, b"runtime").expect("write runtime copy");
        executable
    }

    #[test]
    fn names_the_digest_of_a_copy_published_under_the_state_base() {
        let base = tempfile::tempdir().expect("create state base");
        let executable = published(base.path(), DIGEST);
        assert_eq!(
            durable_digest_for(&executable, base.path()).as_deref(),
            Some(DIGEST)
        );
    }

    #[test]
    fn refuses_a_copy_outside_the_state_base_or_without_a_digest_name() {
        let base = tempfile::tempdir().expect("create state base");
        let elsewhere = tempfile::tempdir().expect("create bundle directory");
        let runtime = published(elsewhere.path(), DIGEST);
        assert_eq!(durable_digest_for(&runtime, base.path()), None);

        let bundled = published(base.path(), "native");
        assert_eq!(durable_digest_for(&bundled, base.path()), None);
    }
}
