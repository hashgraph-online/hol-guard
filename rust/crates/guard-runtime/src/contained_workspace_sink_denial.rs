//! The note a failed contained run gets when its output names a denial.
//!
//! The note names what the sandbox blocked: a write outside the workspace,
//! starting a program outside the allowed roots, a network connection, a read
//! outside the workspace, a pseudo-terminal, or the Docker socket. The first
//! output line that names one of those picks it; a denial with no clearer
//! cause gets the generic note. Every note ends with the scope sentence, so an
//! agent can plan: programs the command starts, including children of an
//! interpreter, ran contained, and only commands Guard proves safe run
//! directly. Markers match whole words, so a path such as `/usr/libexec` or
//! `rewrite.log` names no cause, and only errors a sandbox denial produces name
//! one alone. Python keeps the same notes and markers in
//! `contained_denial_note.py`, byte for byte, in the same order.

pub(super) const WRITE_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which blocked a write outside the workspace. Only the workspace, $TMPDIR and a private scratch $HOME are writable, apart from protected paths such as Git configuration. Keep files the command writes inside the workspace or $TMPDIR. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
pub(super) const EXEC_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which blocked starting a program outside the locations it allows. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
pub(super) const CONNECT_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which blocked a network connection. The sandbox has no network access. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
pub(super) const READ_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which blocked a read outside the workspace, such as the home directory. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
pub(super) const PTY_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which blocked opening a pseudo-terminal. The sandbox has no PTY, so a program that needs an interactive terminal cannot run contained; use its non-interactive form. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
pub(super) const DOCKER_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which blocked access to the Docker socket. The sandbox never allows Docker, so a command that needs a container runtime cannot run contained. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
pub(super) const GENERIC_NOTE: &str = "This command ran inside HOL Guard's workspace sandbox, which denied an operation. Only the workspace, $TMPDIR and a private scratch $HOME are writable, and there is no network, real home directory, PTY or Docker socket access. This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox.";
/// Words that make a line a denial at all.
const DENIAL_WORDS: [&[u8]; 4] = [
    b"eperm",
    b"eacces",
    b"operation not permitted",
    b"permission denied",
];
/// Per cause, in order: its note, markers that name it alone, then words
/// that name it on a line that also holds a denial word.
type Cause = (
    &'static str,
    &'static [&'static [u8]],
    &'static [&'static [u8]],
);
const CAUSES: [Cause; 6] = [
    (DOCKER_NOTE, &[], &[b"docker daemon"]),
    (
        PTY_NOTE,
        &[b"out of pty devices"],
        &[b"/dev/ptmx", b"openpty", b"forkpty", b"posix_openpt"],
    ),
    (
        EXEC_NOTE,
        &[b"spawn eperm", b"spawn eacces"],
        &[b"exec", b"execve", b"posix_spawn"],
    ),
    (
        CONNECT_NOTE,
        &[
            b"connect eperm",
            b"connect eacces",
            b"network is unreachable",
            b"enetunreach",
            b"getaddrinfo enotfound",
            b"could not resolve host",
            b"nodename nor servname",
        ],
        &[b"connect", b"socket"],
    ),
    (
        WRITE_NOTE,
        &[b"erofs", b"read-only file system"],
        &[
            b"mkdir",
            b"rename",
            b"unlink",
            b"rmdir",
            b"symlink",
            b"copyfile",
            b"write",
            b"utime",
            b"chmod",
        ],
    ),
    (
        READ_NOTE,
        &[],
        &[
            b"scandir",
            b"opendir",
            b"readdir",
            b"lstat",
            b"stat '",
            b"readlink",
        ],
    ),
];

/// Whether `marker` appears in `line` with no word or path characters joined
/// to either end.
fn holds(line: &[u8], marker: &[u8]) -> bool {
    let (Some(&first), Some(&last)) = (marker.first(), marker.last()) else {
        return false;
    };
    line.windows(marker.len())
        .enumerate()
        .any(|(start, window)| {
            let end = start + marker.len();
            window == marker
                && (start == 0 || !(word_byte(first) && word_byte(line[start - 1])))
                && (end == line.len() || !(word_byte(last) && word_byte(line[end])))
        })
}

fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"/._-".contains(&byte)
}

fn line_note(line: &[u8]) -> Option<&'static str> {
    let denial = DENIAL_WORDS.iter().any(|word| holds(line, word));
    CAUSES
        .iter()
        .find(|(_, alone, with_denial)| {
            alone.iter().any(|marker| holds(line, marker))
                || (denial && with_denial.iter().any(|word| holds(line, word)))
        })
        .map(|(note, _, _)| *note)
}

/// The note for `outputs`, read in order, or `None` when none names a denial.
pub(super) fn denial_note(outputs: &[&[u8]]) -> Option<&'static str> {
    let mut denied = false;
    for output in outputs {
        let lowered = output.to_ascii_lowercase();
        for line in lowered.split(|byte| *byte == b'\n') {
            if let Some(note) = line_note(line) {
                return Some(note);
            }
            denied = denied || DENIAL_WORDS.iter().any(|word| holds(line, word));
        }
    }
    denied.then_some(GENERIC_NOTE)
}

/// Addresses that make a blocked connection one to this machine.
const LOOPBACK_MARKERS: [&[u8]; 3] = [b"127.0.0.1", b"localhost", b"::1"];

/// Whether a line of `outputs` names a blocked connection to this machine.
pub(super) fn loopback_denied(outputs: &[&[u8]]) -> bool {
    outputs.iter().any(|output| {
        output
            .to_ascii_lowercase()
            .split(|byte| *byte == b'\n')
            .any(|line| {
                line_note(line) == Some(CONNECT_NOTE)
                    && LOOPBACK_MARKERS
                        .iter()
                        .any(|marker| holds_address(line, marker))
            })
    })
}

/// Like `holds`, but `::1` may not continue another IPv6 address: inside
/// `fe80::1` or `2001:db8::1:443` it names a remote host.
fn holds_address(line: &[u8], marker: &[u8]) -> bool {
    let ipv6 = marker.first() == Some(&b':');
    line.windows(marker.len())
        .enumerate()
        .any(|(start, window)| {
            let end = start + marker.len();
            let before = start.checked_sub(1).map(|index| line[index]);
            let after = line.get(end).copied();
            window == marker
                && before.is_none_or(|byte| {
                    !word_byte(byte) && !(ipv6 && (byte == b':' || byte.is_ascii_hexdigit()))
                })
                && if ipv6 && before == Some(b'[') {
                    // A bracketed address must close right after the marker.
                    after == Some(b']')
                } else {
                    after.is_none_or(|byte| !word_byte(byte))
                }
        })
}

#[cfg(test)]
#[path = "contained_workspace_sink_denial_tests.rs"]
mod tests;
