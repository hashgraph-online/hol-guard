use std::path::{Path, PathBuf};

use super::*;

const MARKER: &str = "HOL Guard blocked this action under the native command extension policy.";
const BARE: &str =
    " Run `hol-guard command controls recover-authority` in a terminal to restore the protected control floor.";

fn home() -> PathBuf {
    PathBuf::from("/Users/casey")
}

/// A block from the home the bare command would find keeps that command.
#[test]
fn the_default_home_keeps_the_short_command() {
    let guard_home = home().join(".hol-guard");
    assert_eq!(
        remediation_for_home(Some(&guard_home), Some(&home()), false),
        BARE
    );
}

/// A bridge reading a home the bare command would not find names it, so the
/// person repairs the install that is blocking them rather than another one.
#[test]
fn another_home_is_named_on_the_command() {
    assert_eq!(
        remediation_for_home(Some(Path::new("/opt/guards/ci")), Some(&home()), false),
        " Run `hol-guard command --guard-home /opt/guards/ci controls recover-authority` in a terminal to restore the protected control floor."
    );
}

/// The named home is pasted into a shell, so it is quoted for one.
#[test]
fn a_named_home_is_quoted_for_the_shell() {
    assert_eq!(
        remediation_for_home(
            Some(Path::new("/opt/shared guards/.hol-guard")),
            Some(&home()),
            false
        ),
        " Run `hol-guard command --guard-home '/opt/shared guards/.hol-guard' controls recover-authority` in a terminal to restore the protected control floor."
    );
}

/// With either side unknown there is nothing to compare, and a runtime that
/// cannot tell the two apart has nothing to add to the command.
#[test]
fn an_unknown_home_on_either_side_keeps_the_short_command() {
    assert_eq!(remediation_for_home(None, Some(&home()), false), BARE);
    assert_eq!(remediation_for_home(None, None, false), BARE);
    assert_eq!(
        remediation_for_home(Some(Path::new("/opt/guards/ci")), None, false),
        BARE
    );
}

/// The whole sentence travels with the block, naming the home the bridge read.
#[test]
fn an_authority_block_carries_the_recovery_command() {
    assert_eq!(
        zcode_authority_block_reason(MARKER, None),
        format!("{MARKER}{BARE}")
    );
}

/// A reason that is not an authority block, and one that already offers the
/// command, are both left exactly as the daemon wrote them.
#[test]
fn other_reasons_are_left_alone() {
    assert_eq!(
        zcode_authority_block_reason("HOL Guard blocked this action.", None),
        "HOL Guard blocked this action."
    );
    let offered = format!("{MARKER} Run `hol-guard command controls recover-authority`.");
    assert_eq!(zcode_authority_block_reason(&offered, None), offered);
}

/// A Windows block is pasted into `cmd.exe` or PowerShell, which both read a
/// single-quoted path as part of the path itself. The plain path carries no
/// quotes at all, and one with a space is double-quoted, which both shells
/// read literally, backslashes included.
#[test]
fn a_windows_home_is_quoted_for_a_windows_shell() {
    let windows_home = Path::new("C:\\Users\\casey");
    assert_eq!(
        remediation_for_home(Some(Path::new("C:\\guards\\ci")), Some(windows_home), true),
        " Run `hol-guard command --guard-home C:\\guards\\ci controls recover-authority` in a terminal to restore the protected control floor."
    );
    assert_eq!(
        remediation_for_home(
            Some(Path::new("C:\\Program Files\\guard\\.hol-guard")),
            Some(windows_home),
            true
        ),
        " Run `hol-guard command --guard-home \"C:\\Program Files\\guard\\.hol-guard\" controls recover-authority` in a terminal to restore the protected control floor."
    );
}

/// The same path renders differently for the two shells, which is the whole
/// point of carrying the platform rather than reading it from `cfg!`.
#[test]
fn the_two_shells_get_their_own_spelling() {
    let spaced = Path::new("/opt/shared guards/.hol-guard");
    let posix = remediation_for_home(Some(spaced), Some(&home()), false);
    let windows = remediation_for_home(Some(spaced), Some(&home()), true);
    assert!(posix.contains("'/opt/shared guards/.hol-guard'"), "{posix}");
    assert!(
        windows.contains("\"/opt/shared guards/.hol-guard\""),
        "{windows}"
    );
}

/// A Windows home holding `$`, `%`, a backtick or `!` survives no rendering:
/// the double quotes both shells would need let PowerShell expand `$name` and
/// `cmd.exe` expand `%VAR%` and, under delayed expansion, `!name!` too, while
/// single quotes become part of the path in `cmd.exe`. All four are legal in a
/// Windows file name, so each names a home someone can really hold. Naming it
/// would send the person to repair whatever the shell rewrote it into while
/// this install stays blocked, so the block keeps the short command, which at
/// least repairs the default store.
#[test]
fn a_windows_home_the_shells_would_rewrite_keeps_the_short_command() {
    let windows_home = Path::new("C:\\Users\\casey");
    for home in [
        "C:\\guards\\$ci",
        "C:\\guards\\%CI%",
        "C:\\guards\\`ci",
        "C:\\guards\\!ci",
        "C:\\Program Files\\guard$\\.hol-guard",
    ] {
        assert_eq!(quote_home(home, true), None, "{home}");
        assert_eq!(
            remediation_for_home(Some(Path::new(home)), Some(windows_home), true),
            BARE,
            "{home}"
        );
    }
}

/// A POSIX shell is told the same characters are literal by single quotes, so
/// the same home is still named there.
#[test]
fn a_posix_home_holding_those_characters_is_still_named() {
    let named = remediation_for_home(Some(Path::new("/opt/g$x/ci")), Some(&home()), false);
    assert!(
        named.contains("--guard-home '/opt/g$x/ci' controls"),
        "{named}"
    );
}
