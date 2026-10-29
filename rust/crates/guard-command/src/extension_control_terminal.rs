//! Native port of the local-terminal verdict in `runtime/extension_control_proof.py`.
//!
//! First enrollment hands one actor permanent control over which extensions
//! Guard trusts, so it is confirmed at the keyboard of the machine being
//! enrolled and nowhere else. Deciding whether the caller really is at that
//! keyboard is authority: a session that is in fact an SSH pipe or an RDP
//! console must never be read as local.
//!
//! The caller runs the probes, because only it holds the descriptors and the
//! environment of the session in question, and sends what they returned
//! verbatim — `who`'s output, `loginctl`'s answer, the terminal's owner, the
//! Windows session metrics. Every reading of those bytes happens here.
//!
//! Each probe fails closed. An unreadable login name, a `who` that could not
//! run, a `loginctl` that refused, a Windows API that returned nothing: none
//! of them is evidence of a local session, so each leaves the verdict at
//! "not proven local".

use guard_contracts::{
    ExtensionControlTerminalVerdictV1, PosixTerminalSignalsV1, WindowsTerminalSignalsV1,
};

/// Environment variables a remote terminal sets on itself.
///
/// `_REMOTE_TERMINAL_ENVIRONMENT` (extension_control_proof.py:37).
pub const REMOTE_TERMINAL_ENVIRONMENT: [&str; 4] =
    ["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "MOSH_CONNECTION"];

/// Windows session names that name a remote-session provider.
///
/// `_WINDOWS_REMOTE_SESSION_NAME_PREFIXES` (extension_control_proof.py:40).
const WINDOWS_REMOTE_SESSION_NAME_PREFIXES: [&str; 4] = ["rdp-tcp", "ica-", "pcoip-", "blast-"];

/// The device path relative to `/dev` (`pts/7`, `ttys020`).
///
/// `_normalized_terminal_id` (extension_control_proof.py:137).
fn normalized_terminal_id(name: &str) -> &str {
    name.strip_prefix("/dev/").unwrap_or(name)
}

/// The last `/`-separated segment, as `pathlib.Path(...).name` gives it.
fn terminal_basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Whether a `who` record's host column names somewhere else.
///
/// `who` wraps a remote host in parentheses and prints nothing at all for a
/// local login, so a bare final column is the local case.
fn record_is_remote(last_field: &str) -> bool {
    last_field.starts_with('(') && last_field.ends_with(')')
}

/// Whether a login record or a user-owned desktop PTY proves a local session.
///
/// `_terminal_session_is_local` (extension_control_proof.py:143).
fn terminal_session_is_local(signals: &PosixTerminalSignalsV1) -> bool {
    let Some(login_name) = signals.login_name.as_deref() else {
        return false;
    };
    // Linux `who` prints `pts/7` while macOS prints `ttys020`; compare the
    // `/dev`-relative form and keep the bare basename for single-segment names.
    let terminal_ids = [
        normalized_terminal_id(&signals.terminal_name),
        terminal_basename(&signals.terminal_name),
    ];
    if let Some(output) = signals.who_output.as_deref() {
        for line in output.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [user, terminal, ..] = fields.as_slice() else {
                continue;
            };
            if *user != login_name || !terminal_ids.contains(&normalized_terminal_id(terminal)) {
                continue;
            }
            // `fields` is non-empty here, so the last column always exists.
            return !record_is_remote(fields[fields.len() - 1]);
        }
    }
    // GNOME and other desktop terminal emulators often do not create utmp
    // records. systemd-logind provides the session origin independently of
    // mutable child-process environment variables.
    let Some(remote) = signals.logind_remote.as_deref() else {
        return false;
    };
    if !remote.trim().eq_ignore_ascii_case("no") {
        return false;
    }
    let (Some(owner_uid), Some(is_char_device)) =
        (signals.terminal_owner_uid, signals.terminal_is_char_device)
    else {
        return false;
    };
    owner_uid == signals.effective_uid && is_char_device
}

/// Whether the Windows session APIs identify a direct local session.
///
/// `_windows_session_is_local` (extension_control_proof.py:229).
fn windows_session_is_local(signals: &WindowsTerminalSignalsV1) -> bool {
    let session_name = signals.session_name.trim().to_ascii_lowercase();
    if WINDOWS_REMOTE_SESSION_NAME_PREFIXES
        .iter()
        .any(|prefix| session_name.starts_with(prefix))
    {
        return false;
    }
    // RDP and several other remote-terminal providers expose CLIENTNAME even
    // when they do not use the standard RDP-Tcp session name.
    if !signals.client_name.trim().is_empty() {
        return false;
    }
    if signals.remote_session_metric != Some(false) {
        return false;
    }
    // WTSClientProtocolType is zero for the local console and nonzero for
    // RDP/ICA/other remote session protocols.
    signals.wts_protocol_type == Some(0)
}

/// The POSIX branch of `_require_local_terminal_confirmation`
/// (extension_control_proof.py:330).
fn posix_verdict(signals: &PosixTerminalSignalsV1) -> ExtensionControlTerminalVerdictV1 {
    if !signals.controlling_terminal_opened {
        return ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal;
    }
    // Opening /dev/tty can preserve that alias rather than returning the
    // concrete /dev/pts or /dev/ttys device. stdin identifies the same
    // controlling terminal for an interactive CLI invocation.
    if signals.stdin_is_tty && signals.descriptors_share_session != Some(true) {
        return ExtensionControlTerminalVerdictV1::SingleTerminal;
    }
    if !signals.controlling_terminal_is_tty || !terminal_session_is_local(signals) {
        return ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal;
    }
    ExtensionControlTerminalVerdictV1::Local
}

/// The Windows branch, `_require_windows_local_terminal_confirmation`
/// (extension_control_proof.py:302).
fn windows_verdict(signals: &WindowsTerminalSignalsV1) -> ExtensionControlTerminalVerdictV1 {
    if !signals.stdio_is_tty {
        return ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal;
    }
    if !windows_session_is_local(signals) {
        return ExtensionControlTerminalVerdictV1::RemoteTerminal;
    }
    if !signals.console_descriptors_interactive {
        return ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal;
    }
    ExtensionControlTerminalVerdictV1::Local
}

/// A request that does not name exactly one platform's probes.
///
/// Neither block means the caller collected nothing; both mean it claims to be
/// on two platforms at once. Either way there is no reading to judge, so the
/// op publishes its own invalid-request reason rather than a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSignalsMalformed;

/// Whether this session may confirm a first extension-control enrollment.
///
/// `remote_environment` names the remote-terminal variables the caller found
/// set and non-empty. Exactly one of `posix` and `windows` carries the probes
/// for the platform the caller is on; neither, or both, is a malformed request
/// and is refused rather than guessed at.
pub fn extension_control_terminal_verdict(
    remote_environment: &[String],
    posix: Option<&PosixTerminalSignalsV1>,
    windows: Option<&WindowsTerminalSignalsV1>,
) -> Result<ExtensionControlTerminalVerdictV1, TerminalSignalsMalformed> {
    if !remote_environment.is_empty() {
        return Ok(ExtensionControlTerminalVerdictV1::RemoteTerminal);
    }
    match (posix, windows) {
        (Some(signals), None) => Ok(posix_verdict(signals)),
        (None, Some(signals)) => Ok(windows_verdict(signals)),
        _ => Err(TerminalSignalsMalformed),
    }
}

#[cfg(test)]
#[path = "extension_control_terminal_tests.rs"]
mod tests;
