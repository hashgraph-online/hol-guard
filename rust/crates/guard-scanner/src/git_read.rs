//! Bounded `git` subprocess helper shared by the repository/staged scanners
//! and the pre-commit hook installer.
//!
//! Port of `secret_repository_scanner._run_git`
//! (`src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py`).
//! The Python helper wraps `subprocess.run(["git", *args], cwd=root,
//! capture_output=True, timeout=_GIT_TIMEOUT_SECONDS, check=True)` and callers
//! catch `(OSError, subprocess.SubprocessError)` around it. [`run_git`] folds
//! those failure modes into [`GitError`]: `Ok` means `returncode == 0` exactly
//! like the Python `check=True` contract, so callers map `Err(_)` the same way
//! they map `except`/non-zero-returncode early exits.
//!
//! stdout/stderr are drained on dedicated threads while the child runs: a
//! `git` invocation whose output exceeds the pipe buffer cannot deadlock the
//! poll loop, and the timeout path kills the child before collecting partial
//! output.

use std::error::Error;
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// `_GIT_TIMEOUT_SECONDS` from the Python module.
pub const GIT_TIMEOUT_SECONDS: u64 = 20;

/// Poll cadence for the manual timeout loop; small enough that a deadline
/// lands within ~10 ms of expiry without busy-spinning.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Mirror of `subprocess.CompletedProcess[bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedOutput {
    /// The spawned argv: `["git", *args]`.
    pub args: Vec<String>,
    /// Exit status with Python `Popen.returncode` semantics: the exit code,
    /// or `-signal` when the child was killed by a signal (POSIX only).
    pub returncode: i32,
    /// Captured stdout bytes.
    ///
    /// `git cat-file blob` hands back a file's whole contents, so this buffer
    /// is plaintext. Wrapping it wipes it on every drop, including the ones a
    /// caller never sees, and keeps the derived `Debug` from printing it.
    pub stdout: Zeroizing<Vec<u8>>,
    /// Captured stderr bytes, wrapped for the same reason as `stdout`.
    pub stderr: Zeroizing<Vec<u8>>,
}

/// Failure modes of [`run_git`], mirroring the exceptions Python callers
/// already catch around `subprocess.run(..., check=True)`.
#[derive(Debug)]
pub enum GitError {
    /// `OSError` raised by spawn/wait/read plumbing (`io::Error` is Rust's
    /// `OSError`).
    Spawn(io::Error),
    /// `subprocess.TimeoutExpired`; the child was killed and reaped.
    Timeout,
    /// Non-zero exit status, mirroring `CalledProcessError` (`check=True` with
    /// `returncode != 0`): carries the code and the captured stderr.
    NonZero {
        code: i32,
        stderr: Zeroizing<Vec<u8>>,
    },
    /// Catch-all for `subprocess.SubprocessError`-style failures (e.g. a
    /// drained-pipe reader thread panicking).
    Subprocess(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "git spawn failed: {error}"),
            Self::Timeout => formatter.write_str("git subprocess timed out"),
            Self::NonZero { code, stderr } => write!(
                formatter,
                "git exited with status {code}: {}",
                String::from_utf8_lossy(stderr).trim()
            ),
            Self::Subprocess(message) => {
                write!(formatter, "git subprocess failure: {message}")
            }
        }
    }
}

impl Error for GitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            _ => None,
        }
    }
}

/// Python `Popen.returncode`: `-signal` when the child died to a signal.
#[cfg(unix)]
fn raw_returncode(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(code) => code,
        None => -(status.signal().unwrap_or(0)),
    }
}

/// Non-POSIX systems cannot report the `-signal` convention; `-1` keeps the
/// `!= 0` semantics callers rely on.
#[cfg(not(unix))]
fn raw_returncode(status: &std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

/// Read a pipe to its end without leaving partial copies in freed memory.
///
/// `read_to_end` grows its buffer by reallocating, and every growth frees an
/// allocation that still holds the bytes read so far. `git cat-file blob`
/// hands back a file's plaintext, so those freed allocations are exactly what
/// a crash dump would carry. Reading into fixed chunks never reallocates a
/// filled buffer, each chunk is wiped when it drops, and the result is
/// allocated once at the size the chunks already add up to.
///
/// The result is wrapped rather than handed back bare because the caller is
/// not the only one who drops it: the timeout path, a failed sibling drain and
/// a non-zero exit all discard an assembled buffer, and each of those is a
/// full copy of the plaintext that would otherwise be freed intact.
fn read_whole_pipe(pipe: &mut impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    const CHUNK_BYTES: usize = 64 * 1024;
    let mut chunks: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut last_used = 0usize;
    loop {
        let mut chunk = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
        let mut used = 0usize;
        while used < CHUNK_BYTES {
            // `read_to_end` retried an interrupted read; propagating it here
            // would fail a whole git call on a signal an embedding Python
            // interpreter installs without `SA_RESTART`.
            let read = match pipe.read(&mut chunk[used..]) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if read == 0 {
                break;
            }
            used += read;
        }
        let filled = used == CHUNK_BYTES;
        if used > 0 {
            chunks.push(chunk);
            last_used = used;
        }
        if !filled {
            break;
        }
    }
    let total = chunks.len().saturating_sub(1) * CHUNK_BYTES + last_used;
    let mut whole = Vec::with_capacity(total);
    for (index, chunk) in chunks.iter().enumerate() {
        let used = if index + 1 == chunks.len() {
            last_used
        } else {
            CHUNK_BYTES
        };
        whole.extend_from_slice(&chunk[..used]);
    }
    Ok(Zeroizing::new(whole))
}

/// Drain one piped stream into the `Ok(stdout)`/`Ok(stderr)` buffers, mapping
/// reader failures the same way Python maps `OSError`.
fn drain(
    reader: Option<JoinHandle<io::Result<Zeroizing<Vec<u8>>>>>,
) -> Result<Zeroizing<Vec<u8>>, GitError> {
    match reader {
        Some(handle) => handle
            .join()
            .map_err(|_| GitError::Subprocess("pipe reader thread panicked".to_string()))?
            .map_err(GitError::Spawn),
        None => Ok(Zeroizing::new(Vec::new())),
    }
}

/// Spawn `program` with captured output and a wall-clock deadline. `run_git`
/// is the only public entry point; tests use this directly to exercise the
/// timeout path with `sleep` (the contract's "sleep command with 1s timeout").
fn run_program(
    program: &str,
    root: &Path,
    args: &[std::ffi::OsString],
    timeout_secs: u64,
) -> Result<CompletedOutput, GitError> {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GitError::Spawn)?;

    // Drain both pipes concurrently with the poll loop: `try_wait` alone
    // would leave a child blocked on a full pipe buffer past the deadline.
    let stdout_reader = child
        .stdout
        .take()
        .map(|mut pipe| thread::spawn(move || read_whole_pipe(&mut pipe)));
    let stderr_reader = child
        .stderr
        .take()
        .map(|mut pipe| thread::spawn(move || read_whole_pipe(&mut pipe)));

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                // `TimeoutExpired`: kill, reap, and release the pipes.
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.map(JoinHandle::join);
                let _ = stderr_reader.map(JoinHandle::join);
                return Err(GitError::Timeout);
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.map(JoinHandle::join);
                let _ = stderr_reader.map(JoinHandle::join);
                return Err(GitError::Spawn(error));
            }
        }
    };

    let stdout = drain(stdout_reader)?;
    let stderr = drain(stderr_reader)?;
    let completed = CompletedOutput {
        args: std::iter::once(program.to_string())
            .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
            .collect(),
        returncode: raw_returncode(&status),
        stdout,
        stderr,
    };
    if completed.returncode == 0 {
        Ok(completed)
    } else {
        Err(GitError::NonZero {
            code: completed.returncode,
            stderr: completed.stderr,
        })
    }
}

/// Python `_run_git(root, args)`: run `git <args>` in `root` with captured
/// stdout/stderr and a `timeout_secs` wall-clock deadline.
///
/// `Ok` is returned only for `returncode == 0` (the `check=True` shape in the
/// port contract); every other outcome is one of the [`GitError`] variants so
/// callers keep Python's `except (OSError, subprocess.SubprocessError)` /
/// `returncode != 0` degradation.
pub fn run_git(root: &Path, args: &[&str], timeout_secs: u64) -> Result<CompletedOutput, GitError> {
    let owned: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
    run_program("git", root, &owned, timeout_secs)
}

/// Byte-exact argument variant for staged/path specs: `git` accepts arbitrary
/// non-NUL bytes in argv on POSIX, which preserves `surrogateescape` parity
/// for non-UTF-8 staged paths that `&str` cannot represent.
pub fn run_git_os(
    root: &Path,
    args: &[std::ffi::OsString],
    timeout_secs: u64,
) -> Result<CompletedOutput, GitError> {
    run_program("git", root, args, timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workdir() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn git_version_succeeds_with_zero_returncode() {
        let output = run_git(&workdir(), &["--version"], GIT_TIMEOUT_SECONDS).unwrap();
        assert_eq!(output.returncode, 0);
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("git version"));
        assert_eq!(output.args, ["git", "--version"]);
    }

    #[test]
    fn unknown_subcommand_maps_to_non_zero() {
        let error = run_git(
            &workdir(),
            &["nonexistent-subcommand-xyz"],
            GIT_TIMEOUT_SECONDS,
        )
        .unwrap_err();
        match error {
            GitError::NonZero { code, stderr } => {
                assert_ne!(code, 0);
                assert!(String::from_utf8_lossy(&stderr).contains("nonexistent-subcommand-xyz"));
            }
            other => panic!("expected GitError::NonZero, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn sleeping_child_is_killed_at_deadline() {
        let start = Instant::now();
        let error = run_program("sleep", &workdir(), &["30".into()], 1).unwrap_err();
        assert!(matches!(error, GitError::Timeout));
        // Poll cadence + kill should land well under the sleep duration.
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn missing_binary_maps_to_spawn() {
        let error = run_program(
            "guard-scanner-nonexistent-binary-xyz",
            &workdir(),
            &[],
            GIT_TIMEOUT_SECONDS,
        )
        .unwrap_err();
        assert!(matches!(error, GitError::Spawn(_)));
    }

    #[test]
    fn a_pipe_longer_than_one_chunk_is_read_whole() {
        let source: Vec<u8> = (0..200_000usize).map(|index| (index % 251) as u8).collect();
        let mut cursor = std::io::Cursor::new(source.clone());
        let read = read_whole_pipe(&mut cursor).unwrap();
        assert_eq!(*read, source);
        assert_eq!(read.capacity(), source.len());
    }

    #[test]
    fn an_empty_pipe_reads_as_no_bytes() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(read_whole_pipe(&mut cursor).unwrap().is_empty());
    }

    /// A signal handler installed without `SA_RESTART` interrupts a blocked
    /// read; `read_to_end` retried that, so the chunked reader must too.
    #[test]
    fn an_interrupted_read_is_retried_rather_than_failing_the_call() {
        struct InterruptsOnce {
            interrupted: bool,
            left: usize,
        }
        impl Read for InterruptsOnce {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                let wrote = buffer.len().min(self.left);
                buffer[..wrote].fill(b'x');
                self.left -= wrote;
                Ok(wrote)
            }
        }
        let mut pipe = InterruptsOnce {
            interrupted: false,
            left: 7,
        };
        let read = read_whole_pipe(&mut pipe).unwrap();
        assert_eq!(*read, vec![b'x'; 7]);
    }
}
