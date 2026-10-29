use super::*;
use guard_contracts::{PosixTerminalSignalsV1, WindowsTerminalSignalsV1};

fn posix() -> PosixTerminalSignalsV1 {
    PosixTerminalSignalsV1 {
        controlling_terminal_opened: true,
        controlling_terminal_is_tty: true,
        stdin_is_tty: true,
        descriptors_share_session: Some(true),
        terminal_name: "/dev/ttys020".to_string(),
        login_name: Some("operator".to_string()),
        who_output: Some("operator ttys020  Oct 27 09:14\n".to_string()),
        logind_remote: None,
        terminal_owner_uid: Some(501),
        terminal_is_char_device: Some(true),
        effective_uid: 501,
    }
}

fn windows() -> WindowsTerminalSignalsV1 {
    WindowsTerminalSignalsV1 {
        stdio_is_tty: true,
        console_descriptors_interactive: true,
        session_name: "Console".to_string(),
        client_name: String::new(),
        remote_session_metric: Some(false),
        wts_protocol_type: Some(0),
    }
}

fn verdict(signals: &PosixTerminalSignalsV1) -> ExtensionControlTerminalVerdictV1 {
    extension_control_terminal_verdict(&[], Some(signals), None).expect("one platform block")
}

fn windows_verdict_of(signals: &WindowsTerminalSignalsV1) -> ExtensionControlTerminalVerdictV1 {
    extension_control_terminal_verdict(&[], None, Some(signals)).expect("one platform block")
}

#[test]
fn a_matching_login_record_without_a_host_proves_a_local_session() {
    assert_eq!(verdict(&posix()), ExtensionControlTerminalVerdictV1::Local);
}

#[test]
fn a_linux_pts_record_matches_the_dev_relative_terminal_name() {
    let mut signals = posix();
    signals.terminal_name = "/dev/pts/7".to_string();
    signals.who_output = Some("operator pts/7        2026-10-27 09:14\n".to_string());
    assert_eq!(verdict(&signals), ExtensionControlTerminalVerdictV1::Local);
}

#[test]
fn a_login_record_naming_a_host_is_a_remote_session() {
    let mut signals = posix();
    signals.who_output = Some("operator ttys020  Oct 27 09:14 (198.51.100.4)\n".to_string());
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn another_users_login_record_on_the_same_terminal_is_not_the_callers() {
    let mut signals = posix();
    signals.who_output = Some("someone-else ttys020  Oct 27 09:14\n".to_string());
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn the_first_matching_record_decides_and_later_records_do_not_rescue_it() {
    let mut signals = posix();
    signals.who_output = Some(
        "operator ttys020  Oct 27 09:14 (198.51.100.4)\noperator ttys020  Oct 27 09:20\n"
            .to_string(),
    );
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn a_who_record_decides_before_logind_is_consulted() {
    let mut signals = posix();
    // A desktop session that logind calls remote still has a local utmp record
    // here; the record is the stronger evidence and answers first.
    signals.logind_remote = Some("yes\n".to_string());
    assert_eq!(verdict(&signals), ExtensionControlTerminalVerdictV1::Local);
}

#[test]
fn an_owned_desktop_pty_without_a_login_record_is_local() {
    let mut signals = posix();
    signals.who_output = Some(String::new());
    signals.logind_remote = Some("no\n".to_string());
    assert_eq!(verdict(&signals), ExtensionControlTerminalVerdictV1::Local);
}

#[test]
fn an_unreadable_who_still_allows_the_logind_path() {
    let mut signals = posix();
    signals.who_output = None;
    signals.logind_remote = Some("no\n".to_string());
    assert_eq!(verdict(&signals), ExtensionControlTerminalVerdictV1::Local);
}

#[test]
fn a_desktop_pty_owned_by_another_user_is_refused() {
    let mut signals = posix();
    signals.who_output = Some(String::new());
    signals.logind_remote = Some("no\n".to_string());
    signals.terminal_owner_uid = Some(0);
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn a_terminal_that_is_not_a_character_device_is_refused() {
    let mut signals = posix();
    signals.who_output = Some(String::new());
    signals.logind_remote = Some("no\n".to_string());
    signals.terminal_is_char_device = Some(false);
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn an_unstattable_terminal_is_refused() {
    let mut signals = posix();
    signals.who_output = Some(String::new());
    signals.logind_remote = Some("no\n".to_string());
    signals.terminal_owner_uid = None;
    signals.terminal_is_char_device = None;
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn a_remote_logind_session_is_refused() {
    let mut signals = posix();
    signals.who_output = Some(String::new());
    signals.logind_remote = Some("yes\n".to_string());
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn an_unreadable_logind_answer_is_refused() {
    let mut signals = posix();
    signals.who_output = Some(String::new());
    signals.logind_remote = None;
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn an_unknown_login_name_is_refused() {
    let mut signals = posix();
    signals.login_name = None;
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn a_remote_environment_variable_refuses_before_any_probe() {
    let remote = vec!["SSH_CONNECTION".to_string()];
    assert_eq!(
        extension_control_terminal_verdict(&remote, Some(&posix()), None),
        Ok(ExtensionControlTerminalVerdictV1::RemoteTerminal)
    );
}

#[test]
fn a_closed_controlling_terminal_has_nothing_to_confirm_through() {
    let mut signals = posix();
    signals.controlling_terminal_opened = false;
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn a_controlling_terminal_that_is_not_a_tty_is_refused() {
    let mut signals = posix();
    signals.controlling_terminal_is_tty = false;
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn stdin_from_a_different_session_is_refused_as_two_terminals() {
    let mut signals = posix();
    signals.descriptors_share_session = Some(false);
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::SingleTerminal
    );
}

#[test]
fn an_unanswerable_session_comparison_is_refused_as_two_terminals() {
    let mut signals = posix();
    signals.descriptors_share_session = None;
    assert_eq!(
        verdict(&signals),
        ExtensionControlTerminalVerdictV1::SingleTerminal
    );
}

#[test]
fn a_redirected_stdin_leaves_the_controlling_terminal_to_decide() {
    let mut signals = posix();
    signals.stdin_is_tty = false;
    signals.descriptors_share_session = None;
    assert_eq!(verdict(&signals), ExtensionControlTerminalVerdictV1::Local);
}

#[test]
fn a_windows_console_session_is_local() {
    assert_eq!(
        windows_verdict_of(&windows()),
        ExtensionControlTerminalVerdictV1::Local
    );
}

#[test]
fn a_windows_rdp_session_name_is_remote() {
    let mut signals = windows();
    signals.session_name = "RDP-Tcp#7".to_string();
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::RemoteTerminal
    );
}

#[test]
fn every_windows_remote_session_prefix_is_remote() {
    for prefix in WINDOWS_REMOTE_SESSION_NAME_PREFIXES {
        let mut signals = windows();
        signals.session_name = format!("{prefix}42");
        assert_eq!(
            windows_verdict_of(&signals),
            ExtensionControlTerminalVerdictV1::RemoteTerminal,
            "{prefix}"
        );
    }
}

#[test]
fn a_windows_client_name_is_remote_even_with_a_console_session_name() {
    let mut signals = windows();
    signals.client_name = "DESKTOP-REMOTE".to_string();
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::RemoteTerminal
    );
}

#[test]
fn a_set_windows_remote_session_metric_is_remote() {
    let mut signals = windows();
    signals.remote_session_metric = Some(true);
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::RemoteTerminal
    );
}

#[test]
fn an_unreadable_windows_remote_session_metric_is_remote() {
    let mut signals = windows();
    signals.remote_session_metric = None;
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::RemoteTerminal
    );
}

#[test]
fn a_nonzero_windows_protocol_type_is_remote() {
    let mut signals = windows();
    signals.wts_protocol_type = Some(2);
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::RemoteTerminal
    );
}

#[test]
fn an_unanswered_windows_protocol_query_is_remote() {
    let mut signals = windows();
    signals.wts_protocol_type = None;
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::RemoteTerminal
    );
}

#[test]
fn windows_stdio_that_is_not_a_terminal_has_nothing_to_confirm_through() {
    let mut signals = windows();
    signals.stdio_is_tty = false;
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn windows_console_descriptors_that_do_not_answer_are_not_interactive() {
    let mut signals = windows();
    signals.console_descriptors_interactive = false;
    assert_eq!(
        windows_verdict_of(&signals),
        ExtensionControlTerminalVerdictV1::InteractiveLocalTerminal
    );
}

#[test]
fn a_request_without_a_platform_block_is_malformed() {
    assert_eq!(
        extension_control_terminal_verdict(&[], None, None),
        Err(TerminalSignalsMalformed)
    );
}

#[test]
fn a_request_naming_both_platforms_is_malformed() {
    assert_eq!(
        extension_control_terminal_verdict(&[], Some(&posix()), Some(&windows())),
        Err(TerminalSignalsMalformed)
    );
}
