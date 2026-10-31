//! The output filters a peeled wrapper runs over its core's captured output,
//! as Guard's own sink runs them.
//!
//! Native authority chose the chain: at most three `head`, `tail`, `grep` or
//! `rg` stages, each reading only standard input. Head and tail cut the text
//! in process, by lines or by bytes. A matcher runs as the installed binary,
//! located by ownership rather than by the caller's `PATH`, with an
//! environment built here, on the text the core already produced. The text
//! stays bytes throughout, so a cut in the middle of a character reaches the
//! next stage, and the output, exactly as the pipeline would have left it.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use guard_command::pretool::ContainedOutput;
use nix::unistd::{access, getuid, AccessFlags};

use super::output::Shaping;
use super::{Failure, Outcome};

const GREP_BINARIES: [&str; 2] = ["/usr/bin/grep", "/bin/grep"];
/// ripgrep ships from a package manager rather than the system image, so it
/// is looked for in the ordinary install directories.
const RG_DIRECTORIES: [&str; 6] = [
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
    "/home/linuxbrew/.linuxbrew/bin",
];
const LOCALE: [&str; 4] = ["LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE"];
const FILTER_TIMEOUT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(10);
const FILTER_FAILED: &str = "contained_output_filter_failed";

/// Write `captured` as `output` keeps it, as display text, and the chain's
/// own status for a `pipe`. A matcher's diagnostics go to standard error first.
/// A `cut` capture is noted after the result.
pub(super) fn emit(
    output: &ContainedOutput,
    (captured, cut): (&[u8], bool),
    shaping: &Shaping,
) -> Outcome<Option<i32>> {
    if output.kind == "pipe" {
        let (text, diagnostics, status) = apply(captured, &output.stages)?;
        if !diagnostics.is_empty() {
            shaping.err(&diagnostics);
        }
        shaping.show(&text, cut);
        return Ok(Some(status));
    }
    let count = usize::try_from(output.count).unwrap_or(usize::MAX);
    shaping.show(&keep(&lines(captured), output.kind, count).concat(), cut);
    Ok(None)
}

/// Run the chain over `text`: the output, the matchers' diagnostics, and
/// the last stage's status.
pub(super) fn apply(text: &[u8], stages: &[Vec<String>]) -> Outcome<(Vec<u8>, Vec<u8>, i32)> {
    let mut text = text.to_vec();
    let mut diagnostics = Vec::new();
    let mut status = 0;
    for stage in stages {
        let program = stage.first().map(String::as_str).unwrap_or_default();
        if matches!(program, "head" | "tail") {
            let (count, bytes) = match stage.as_slice() {
                [_, flag, count] if flag == "-c" => (count, true),
                [_, count] => (count, false),
                _ => return Err(unsupported()),
            };
            let count: usize = count.parse().map_err(|_| unsupported())?;
            text = if bytes {
                keep(&text, program, count).to_vec()
            } else {
                keep(&lines(&text), program, count).concat()
            };
            status = 0;
            continue;
        }
        let arguments = stage.get(1..).unwrap_or_default();
        let (output, error, code) = matched(&text, program, arguments)?;
        text = output;
        diagnostics.extend_from_slice(&error);
        status = code;
    }
    Ok((text, diagnostics, status))
}

/// The first or last `count` items, as `head` and `tail` keep them: a count
/// larger than the input keeps all of it, and a zero count keeps nothing.
pub(super) fn keep<'a, T>(items: &'a [T], kind: &str, count: usize) -> &'a [T] {
    let count = count.min(items.len());
    if kind == "head" {
        &items[..count]
    } else {
        &items[items.len() - count..]
    }
}

/// `text` split after each line boundary Python's `str.splitlines` breaks
/// at, each line keeping its ending. The two- and three-byte boundaries
/// start with a byte that never continues a character, so reading them from
/// the bytes finds exactly the boundaries the decoded text has.
pub(super) fn lines(text: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut index) = (0, 0);
    while index < text.len() {
        let rest = &text[index..];
        let ending = match rest {
            [b'\r', b'\n', ..] | [0xc2, 0x85, ..] => 2,
            [0xe2, 0x80, 0xa8 | 0xa9, ..] => 3,
            [b'\n' | b'\r' | 0x0b | 0x0c | 0x1c | 0x1d | 0x1e, ..] => 1,
            _ => 0,
        };
        if ending == 0 {
            index += 1;
            continue;
        }
        index += ending;
        lines.push(&text[start..index]);
        start = index;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// One matcher stage over `text`. A matcher this host does not have exits
/// as a shell's missing program does: the core has already run.
fn matched(text: &[u8], program: &str, arguments: &[String]) -> Outcome<(Vec<u8>, Vec<u8>, i32)> {
    let located = match program {
        "rg" => trusted_ripgrep().map(|binary| (binary, None)),
        "grep" => trusted_grep().map(|binary| (binary, None)),
        "egrep" => trusted_grep().map(|binary| (binary, Some("-E"))),
        "fgrep" => trusted_grep().map(|binary| (binary, Some("-F"))),
        _ => return Err(unsupported()),
    };
    let Some((binary, switch)) = located else {
        let missing = format!("hol-guard: {program}: not found\n");
        return Ok((Vec::new(), missing.into_bytes(), 127));
    };
    let mut command = Command::new(binary);
    command
        .args(switch)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(
            LOCALE
                .iter()
                .filter_map(|name| Some((name, std::env::var_os(name)?))),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (stdout, stderr, code) = run(command, text)?;
    let stderr = String::from_utf8_lossy(&stderr).into_owned().into_bytes();
    Ok((stdout, stderr, code))
}

/// Run `command` with `input` on its standard input, within the filter's
/// deadline: its output, its error output and its status, negative for a
/// signal.
fn run(mut command: Command, input: &[u8]) -> Outcome<(Vec<u8>, Vec<u8>, i32)> {
    let mut child = command.spawn().map_err(|_| failed())?;
    let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(failed());
    };
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + FILTER_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => break None,
        }
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = (writer.join(), reader.join(), errors.join());
        return Err(failed());
    };
    let _ = writer.join();
    let stdout = reader.join().map_err(|_| failed())?;
    let stderr = errors.join().map_err(|_| failed())?;
    let code = status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .unwrap_or(1);
    Ok((stdout, stderr, code))
}

/// The system grep: a root-owned regular file nobody else can rewrite.
fn trusted_grep() -> Option<PathBuf> {
    GREP_BINARIES.iter().map(PathBuf::from).find(|candidate| {
        std::fs::metadata(candidate)
            .is_ok_and(|info| info.is_file() && info.uid() == 0 && info.mode() & 0o022 == 0)
    })
}

/// The installed ripgrep: an executable regular file that only root or
/// this user owns and nobody else can rewrite, searched for in turn.
fn trusted_ripgrep() -> Option<PathBuf> {
    let owners = [0, getuid().as_raw()];
    RG_DIRECTORIES.iter().find_map(|directory| {
        let resolved = std::fs::canonicalize(Path::new(directory).join("rg")).ok()?;
        let info = std::fs::metadata(&resolved).ok()?;
        (info.is_file()
            && owners.contains(&info.uid())
            && info.mode() & 0o022 == 0
            && access(&resolved, AccessFlags::X_OK).is_ok())
        .then_some(resolved)
    })
}

fn unsupported() -> Failure {
    Failure::new(FILTER_FAILED, "Unsupported output filter.")
}

fn failed() -> Failure {
    Failure::new(FILTER_FAILED, "The output filter did not finish.")
}

#[cfg(test)]
#[path = "contained_workspace_sink_filters_tests.rs"]
mod tests;
