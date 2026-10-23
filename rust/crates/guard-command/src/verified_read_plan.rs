//! Rust port of the argv grammar in `runtime/verified_read_execution.py`.
//!
//! The cohort itself is decided in `command_verified_read_candidates`; this is
//! the stricter grammar the executor is held to once a read has been admitted.
//! It names the operation, the one target and the bounded slice, and it refuses
//! anything else, so no Python caller has to agree with it about how much of a
//! file a verified read may show.

use std::path::Path;

use guard_contracts::{VerifiedReadPlanV1, VerifiedReadSelectionV1};

/// `_MAX_COUNT` (:23).
const MAX_COUNT: u32 = 1_000;
/// `_dynamic` (:424): a target carrying any of these is not a static path.
const DYNAMIC: &[char] = &['$', '`', '<', '>', '|', ';', '&', '*', '?', '[', '\0'];

/// Derive the one bounded read `argv` asks for, or say why there is none.
pub fn verified_read_plan(argv: &[String]) -> Result<VerifiedReadPlanV1, &'static str> {
    if argv.is_empty() {
        return Err("argv must be a non-empty tuple");
    }
    if argv
        .iter()
        .any(|value| value.is_empty() || value.contains('\0'))
    {
        return Err("argv must contain exact non-empty strings");
    }
    let name = argv[0].as_str();
    // `Path(name).name != name` (:161): a bare file name, never a path.
    // `file_name` answers `None` for `..`, where `PurePath.name` answers `..`
    // itself, so that one spelling is left to fall out of the cohort below.
    let bare =
        name == ".." || Path::new(name).file_name().and_then(|base| base.to_str()) == Some(name);
    if !bare {
        return Err("verified reads do not launch caller-selected executables");
    }
    let rest = &argv[1..];
    match name {
        "pwd" if rest.is_empty() => Ok(VerifiedReadPlanV1 {
            operation_id: "working-directory".to_owned(),
            target: None,
            selection: VerifiedReadSelectionV1::WorkingDirectory {},
        }),
        "head" | "tail" => head_tail(name, rest),
        "sed" => sed(rest),
        _ => Err("operation is outside the verified-read cohort"),
    }
}

/// `_head_tail` (:173).
fn head_tail(name: &str, rest: &[String]) -> Result<VerifiedReadPlanV1, &'static str> {
    let [bound, target] = rest else {
        return Err("head and tail require one bound and one file");
    };
    let count = line_count(bound)?;
    let selection = if name == "head" {
        VerifiedReadSelectionV1::LeadingLines { count }
    } else {
        VerifiedReadSelectionV1::TrailingLines { count }
    };
    Ok(VerifiedReadPlanV1 {
        operation_id: format!("bounded-{name}"),
        target: Some(static_relative_target(target)?),
        selection,
    })
}

/// `_sed` (:183).
fn sed(rest: &[String]) -> Result<VerifiedReadPlanV1, &'static str> {
    let [flag, expression, target] = rest else {
        return Err("sed requires one bounded print expression and one file");
    };
    if flag != "-n" {
        return Err("sed requires one bounded print expression and one file");
    }
    let (start, end) = sed_range(expression)?;
    if !(1 <= start && start <= end && end <= MAX_COUNT) {
        return Err("sed range exceeds the bound");
    }
    Ok(VerifiedReadPlanV1 {
        operation_id: "bounded-source-view".to_owned(),
        target: Some(static_relative_target(target)?),
        selection: VerifiedReadSelectionV1::LineRange { start, end },
    })
}

/// `_SED_RANGE` (:25) as an explicit scan: `N p` or `N , M p`, each at most six
/// digits. A regex engine would answer the same question, and reading the digits
/// here keeps the only number parsing in this module.
fn sed_range(expression: &str) -> Result<(u32, u32), &'static str> {
    let invalid = "sed expression is outside the verified grammar";
    let body = expression.strip_suffix('p').ok_or(invalid)?;
    let (first, second) = match body.split_once(',') {
        Some((first, second)) => (first, Some(second)),
        None => (body, None),
    };
    let start = bounded_digits(first, 6).ok_or(invalid)?;
    let end = match second {
        Some(value) => bounded_digits(value, 6).ok_or(invalid)?,
        None => start,
    };
    Ok((start, end))
}

/// `_line_count` (:365). The count is written as `-N`, `--lines=N` or `N`,
/// and the two prefixes are stripped in turn, as `removeprefix` chains there.
fn line_count(value: &str) -> Result<u32, &'static str> {
    let normalized = value.strip_prefix("--lines=").unwrap_or(value);
    let normalized = normalized.strip_prefix('-').unwrap_or(normalized);
    let bound = "line count exceeds the bound";
    // `int` reads leading zeros as padding, so `0000000001` is one line; only
    // the significant digits count toward the overflow guard.
    if normalized.is_empty() || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(bound);
    }
    let significant = normalized.trim_start_matches('0');
    let count = if significant.is_empty() {
        0
    } else {
        bounded_digits(significant, 9).ok_or(bound)?
    };
    if !(1..=MAX_COUNT).contains(&count) {
        return Err(bound);
    }
    Ok(count)
}

/// ASCII digits, no more than `limit` of them so a long run cannot overflow.
/// Python reads these with `int`, which also accepts other Unicode decimal
/// digits; `head`, `tail` and `sed` read ASCII only, and so does this.
fn bounded_digits(value: &str, limit: usize) -> Option<u32> {
    if value.is_empty() || value.len() > limit || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// The target half of `_resolve_target` (:281) that reads the argument alone.
/// Where it points, and whether that is a secret or a symlink, is answered
/// against the filesystem by the executor.
fn static_relative_target(value: &str) -> Result<String, &'static str> {
    if Path::new(value).is_absolute() || anchored(value) || value.contains(DYNAMIC) {
        return Err("target must be a static relative path");
    }
    Ok(value.to_owned())
}

/// A spelling that names a root, a drive or a stream rather than a path below
/// the working directory. `Path::is_absolute` answers by the host's rules, so
/// on Windows it lets `/etc/passwd` (root-relative), `C:x` (drive-relative)
/// and `x:stream` (an alternate data stream) through, and on Unix it lets
/// `\\server\share` through. None of them is relative on every platform.
fn anchored(value: &str) -> bool {
    let bytes = value.as_bytes();
    if matches!(bytes.first(), Some(b'/' | b'\\')) {
        return true;
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    cfg!(windows) && value.contains(':')
}
