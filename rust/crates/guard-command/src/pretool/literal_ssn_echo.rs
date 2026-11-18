//! A bare `echo` or `printf` that prints a US Social Security number.
//!
//! The literal-secret screen reviews a command that spells out a key or a
//! password, but a printed SSN passed: nothing in it is a program Guard
//! watches. The shape is kept to a single print with no pipe, redirect,
//! substitution or second command, so a test that feeds a sample number to a
//! redaction tool, or a search for one in a fixture, is never asked about.
//! Only numbers the Social Security Administration could have issued count:
//! area 001-899 except 666, group 01-99, serial 0001-9999.

use std::sync::LazyLock;

use regex::Regex;

static SSN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9A-Za-z_.\-/:])([0-9]{3})-([0-9]{2})-([0-9]{4})(?:$|[^0-9A-Za-z_\-/:])")
        .expect("ssn pattern")
});

const PRINTERS: [&str; 2] = ["echo", "printf"];
const SHELL_SYNTAX: [char; 11] = ['|', ';', '&', '<', '>', '$', '`', '\n', '\r', '(', ')'];

fn issuable(area: &str, group: &str, serial: &str) -> bool {
    let area_ok = area != "000" && area != "666" && !area.starts_with('9');
    area_ok && group != "00" && serial != "0000"
}

/// Whether `command` is a single `echo`/`printf` that prints an SSN.
pub(super) fn echoes_ssn(command: &str) -> bool {
    let trimmed = command.trim();
    let program = trimmed.split_whitespace().next().unwrap_or("");
    if !PRINTERS.contains(&program) || trimmed.contains(SHELL_SYNTAX) {
        return false;
    }
    SSN.captures_iter(trimmed)
        .any(|found| issuable(&found[1], &found[2], &found[3]))
}

#[cfg(test)]
#[path = "literal_ssn_echo_tests.rs"]
mod tests;
