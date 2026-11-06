//! Bounded, non-interactive Git subprocess probes with an explicit environment.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::git_execution_safety_config::Environment;

const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const OUTPUT_LIMIT: u64 = 8 * 1024 * 1024;
/// Environment names a probe may inherit from the caller's snapshot. Anything
/// else is dropped so ambient state cannot redirect the query.
const PROBE_ENVIRONMENT: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "SYSTEMROOT",
    "WINDIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

#[derive(Clone)]
pub(crate) struct ProbeOutput {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    /// Captured only by [`Prober::run_capturing_stderr`]; empty otherwise.
    pub(crate) stderr: Vec<u8>,
}

impl ProbeOutput {
    pub(crate) fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub(crate) fn text(&self) -> Option<&str> {
        std::str::from_utf8(&self.stdout).ok()
    }
}

/// The branch `git push origin <branch>` sends, given the branch checked out
/// now. Without a `reference`, `branch` must be that branch or `HEAD`, which
/// pushes the checked-out branch to the same name. A `reference` of `HEAD`
/// says the same command first creates `branch` at the checked-out commit and
/// switches to it (`git switch -c`), so `branch` must not exist yet, locally
/// or as a known `origin` branch the push would move.
pub(crate) fn pushed_branch<'a>(
    prober: &Prober<'_>,
    current: &'a str,
    branch: &'a str,
    reference: Option<&str>,
) -> Option<&'a str> {
    match reference {
        None => (branch == "HEAD" || branch == current).then_some(current),
        Some("HEAD") if branch != "HEAD" && branch != current => {
            let absent = |reference: String| {
                prober
                    .run(&["rev-parse", "--verify", "--quiet", &reference])
                    .is_some_and(|found| found.code == Some(1))
            };
            (absent(format!("refs/heads/{branch}"))
                && absent(format!("refs/remotes/origin/{branch}")))
            .then_some(branch)
        }
        Some(_) => None,
    }
}

pub(crate) struct Prober<'a> {
    pub(crate) git: &'a Path,
    pub(crate) cwd: &'a Path,
    pub(crate) environment: &'a Environment,
}

impl Prober<'_> {
    pub(crate) fn run(&self, arguments: &[&str]) -> Option<ProbeOutput> {
        self.run_with_input(arguments, None)
    }

    /// Like [`Prober::run`], but keeps stderr as well (bounded the same way).
    pub(crate) fn run_capturing_stderr(&self, arguments: &[&str]) -> Option<ProbeOutput> {
        self.execute(arguments, None, true)
    }

    pub(crate) fn run_with_input(
        &self,
        arguments: &[&str],
        input: Option<Vec<u8>>,
    ) -> Option<ProbeOutput> {
        self.execute(arguments, input, false)
    }

    fn execute(
        &self,
        arguments: &[&str],
        input: Option<Vec<u8>>,
        capture_stderr: bool,
    ) -> Option<ProbeOutput> {
        let mut command = Command::new(self.git);
        command
            .args(arguments)
            .current_dir(self.cwd)
            .env_clear()
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(if capture_stderr {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        for name in PROBE_ENVIRONMENT {
            if let Some(value) = self.environment.get(*name) {
                command.env(name, value);
            }
        }
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let mut child = command.spawn().ok()?;
        let writer = input.and_then(|bytes| {
            let mut stdin = child.stdin.take()?;
            Some(std::thread::spawn(move || {
                // A child that exits early closes the pipe; the exit status
                // and output decide the result, not this write.
                let _ = stdin.write_all(&bytes);
            }))
        });
        let stdout = child.stdout.take()?;
        let read_bounded = move |stream: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stream.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes).ok()?;
                (bytes.len() as u64 <= OUTPUT_LIMIT).then_some(bytes)
            })
        };
        let stderr_reader = child
            .stderr
            .take()
            .map(|stream| read_bounded(Box::new(stream)));
        let reader = read_bounded(Box::new(stdout));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let stdout = reader.join().ok()??;
        let stderr = match stderr_reader {
            Some(reader) => reader.join().ok()??,
            None => Vec::new(),
        };
        Some(ProbeOutput {
            code: status?.code(),
            stdout,
            stderr,
        })
    }
}
