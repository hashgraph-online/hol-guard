use super::*;

fn note(output: &str) -> Option<&'static str> {
    denial_note(&[output.as_bytes()])
}

#[test]
fn each_cause_gets_its_own_note() {
    assert_eq!(
        note("Error: EPERM: operation not permitted, mkdir '/opt/lanectl/cache'"),
        Some(WRITE_NOTE)
    );
    assert_eq!(
        note("OSError: [Errno 30] Read-only file system: 'out'"),
        Some(WRITE_NOTE)
    );
    assert_eq!(note("Error: spawn EACCES"), Some(EXEC_NOTE));
    assert_eq!(
        note("Error: EACCES: permission denied, posix_spawn '/opt/lanectl/bin/lanectl'"),
        Some(EXEC_NOTE)
    );
    assert_eq!(
        note("Error: connect EPERM 203.0.113.7:443"),
        Some(CONNECT_NOTE)
    );
    assert_eq!(
        note("curl: (6) Could not resolve host: echo-mcp.invalid"),
        Some(CONNECT_NOTE)
    );
    assert_eq!(
        note("Error: EPERM: operation not permitted, scandir '/home/dev'"),
        Some(READ_NOTE)
    );
    assert_eq!(
        note("OSError: [Errno 1] Operation not permitted: '/dev/ptmx'"),
        Some(PTY_NOTE)
    );
    assert_eq!(note("OSError: out of pty devices"), Some(PTY_NOTE));
    assert_eq!(
        note("Error: EACCES: permission denied, openpty"),
        Some(PTY_NOTE)
    );
    assert_eq!(
        note("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"),
        None
    );
    assert_eq!(
        note("permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"),
        Some(DOCKER_NOTE)
    );
}

#[test]
fn the_first_line_with_a_cause_picks_the_note() {
    let output = b"Error: connect EPERM 127.0.0.1:8080\nError: EROFS: read-only file system";
    assert_eq!(denial_note(&[&output[..]]), Some(CONNECT_NOTE));
    assert_eq!(
        denial_note(&[
            "PermissionError: [Errno 13] Permission denied".as_bytes(),
            "spawn EPERM".as_bytes(),
        ]),
        Some(EXEC_NOTE)
    );
}

#[test]
fn markers_match_whole_words_and_sandbox_errors_only() {
    assert_eq!(
        note("Error: EPERM: operation not permitted, mkdir '/usr/libexec/lanectl'"),
        Some(WRITE_NOTE)
    );
    assert_eq!(
        note("Error: EACCES: permission denied, open '/opt/exec-cache/rewrite.log'"),
        Some(GENERIC_NOTE)
    );
    assert_eq!(
        note("sh: /opt/lanectl/bin/lanectl: cannot execute binary file"),
        None
    );
    assert_eq!(note("Error: connect ECONNREFUSED 127.0.0.1:8080"), None);
}

#[test]
fn a_denial_with_no_clear_cause_gets_the_generic_note() {
    assert_eq!(
        note("OSError: [Errno 1] Operation not permitted: 'data'"),
        Some(GENERIC_NOTE)
    );
    assert_eq!(
        note("Error: \u{201c}EPERM\u{201d} returned"),
        Some(GENERIC_NOTE)
    );
    assert_eq!(note("all tests passed"), None);
    assert_eq!(denial_note(&[]), None);
}

#[test]
fn notes_carry_no_link_or_approval_request() {
    for note in [
        WRITE_NOTE,
        EXEC_NOTE,
        CONNECT_NOTE,
        READ_NOTE,
        PTY_NOTE,
        DOCKER_NOTE,
        GENERIC_NOTE,
    ] {
        assert!(note.contains("HOL Guard's workspace sandbox"));
        assert!(note.ends_with(
            " This applies to every program the command starts, including children of an interpreter; only commands Guard proves safe run directly, outside the sandbox."
        ));
        assert!(!note.contains("http"));
        assert!(!note.to_ascii_lowercase().contains("approv"));
    }
}

#[test]
fn only_a_blocked_connection_to_this_machine_counts_as_loopback() {
    let denied = |output: &str| loopback_denied(&[b"", output.as_bytes()]);
    assert!(denied("Error: connect EPERM 127.0.0.1:8080"));
    assert!(denied(
        "curl: (7) Failed to connect to localhost port 8080: Operation not permitted"
    ));
    assert!(denied("Error: connect EPERM ::1:8080"));
    assert!(denied("Error: connect EPERM [::1]:8080"));
    assert!(denied("Error: connect EPERM ::1"));
    assert!(!denied("Error: connect EPERM fe80::1"));
    assert!(!denied("Error: connect EPERM 2001:db8::1:443"));
    assert!(!denied("Error: connect EPERM ::10:443"));
    assert!(!denied("Error: connect EPERM [::1:abcd]:443"));
    assert!(!denied("Error: connect EPERM 203.0.113.7:443"));
    assert!(!denied("getaddrinfo ENOTFOUND mcp.example.test"));
    assert!(!denied(
        "EPERM: operation not permitted, mkdir '/tmp/localhost'"
    ));
    assert!(!denied("listening on 127.0.0.1:8080"));
}
