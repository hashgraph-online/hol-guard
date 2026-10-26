//! The Windows process start token behind `current_process_identity`:
//! `windows:<creation time>`, where the creation time is the process's
//! `GetProcessTimes` creation FILETIME as a decimal integer, exactly as
//! `windows_process_creation_time` in `windows_paths.py` reports it.

/// The runtime's own start marker renders the same FILETIME as
/// `windows:<16 lowercase hex digits>`.
const MARKER_PREFIX: &str = "windows:";
const MARKER_HEX_DIGITS: usize = 16;

/// The Python token for a runtime start marker: the same creation FILETIME
/// in decimal. Anything that is not a well-formed marker yields `None`.
pub(crate) fn token_from_start_marker(marker: &str) -> Option<String> {
    let hex = marker.strip_prefix(MARKER_PREFIX)?;
    if hex.len() != MARKER_HEX_DIGITS || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let creation = u64::from_str_radix(hex, 16).ok()?;
    Some(format!("{MARKER_PREFIX}{creation}"))
}

/// `_process_start_token(pid)` without a deadline. Like Python, it opens the
/// process with `PROCESS_QUERY_LIMITED_INFORMATION`, reads its creation time
/// whether or not it has exited, and answers `None` when either step fails.
#[cfg(windows)]
pub(crate) fn process_start_token(pid: u32) -> Option<String> {
    let marker = crate::resident_process_identity::process_start_marker(pid).ok()?;
    token_from_start_marker(&marker)
}

#[cfg(test)]
mod tests {
    use super::token_from_start_marker;

    #[test]
    fn the_token_is_the_creation_time_in_decimal() {
        assert_eq!(
            token_from_start_marker("windows:01db1234abcdef00").as_deref(),
            Some("windows:133720631367560960")
        );
        assert_eq!(
            token_from_start_marker("windows:0000000000000000").as_deref(),
            Some("windows:0")
        );
        assert_eq!(
            token_from_start_marker("windows:ffffffffffffffff").as_deref(),
            Some("windows:18446744073709551615")
        );
    }

    #[test]
    fn a_malformed_marker_yields_no_token() {
        for marker in [
            "",
            "windows:",
            "windows:01db1234abcdef0",
            "windows:01db1234abcdef000",
            "windows:01db1234abcdef0g",
            "windows:+1db1234abcdef00",
            "linux:01db1234abcdef00",
            "WINDOWS:01db1234abcdef00",
        ] {
            assert_eq!(token_from_start_marker(marker), None, "{marker}");
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::process_start_token;

    #[test]
    fn own_identity_is_present_and_stable() {
        let (pid, token) =
            crate::codex_hook_identity::current_process_identity().expect("identity");
        assert_eq!(pid, std::process::id());
        let creation = token.strip_prefix("windows:").expect("prefix");
        assert!(creation.parse::<u64>().is_ok(), "{token}");
        assert_eq!(process_start_token(pid), Some(token));
    }

    #[test]
    fn pid_zero_has_no_token() {
        assert_eq!(process_start_token(0), None);
    }
}
