//! Small Python-semantics shims shared by the GitHub body-file and Actions
//! read-workflow checks: `tempfile.gettempdir`, `Path.resolve`, `os.getuid`,
//! `os.access` and decimal `str.isdigit`/`int` handling.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;
use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;

static DECIMAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A\p{Nd}\z").expect("decimal digit pattern"));

fn is_decimal(character: char) -> bool {
    let mut buffer = [0u8; 4];
    DECIMAL.is_match(character.encode_utf8(&mut buffer))
}

/// The digit value of a Unicode decimal digit: Nd characters come in
/// contiguous runs whose length is a multiple of ten starting at zero.
fn decimal_value(character: char) -> Option<u32> {
    if !is_decimal(character) {
        return None;
    }
    let mut start = u32::from(character);
    while start > 0 && char::from_u32(start - 1).is_some_and(is_decimal) {
        start -= 1;
    }
    Some((u32::from(character) - start) % 10)
}

/// `int(text)` for text that `str.isdecimal()` accepts, saturating at
/// `u64::MAX`. `None` is the empty string, a non-decimal character (where
/// Python's `isdigit` and `int` disagree or the text is not a number at all).
pub(crate) fn decimal_digits_value(text: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for character in text.chars() {
        let digit = decimal_value(character)?;
        value = value.saturating_mul(10).saturating_add(u64::from(digit));
    }
    Some(value)
}

/// `os.getuid()` from the host. `None` is "no user ids" on Windows and a
/// fail-closed refusal on Unix hosts that cannot report one.
pub(crate) fn current_uid(ctx: &Ctx) -> Option<u32> {
    ctx.host.current_uid()
}

/// `os.access(path, os.X_OK)`.
pub(crate) fn is_executable(path: &str) -> bool {
    #[cfg(unix)]
    {
        nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
    }
    #[cfg(not(unix))]
    {
        fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
    }
}

#[cfg(unix)]
fn directory_is_writable(path: &str) -> bool {
    nix::unistd::access(
        path,
        nix::unistd::AccessFlags::W_OK | nix::unistd::AccessFlags::X_OK,
    )
    .is_ok()
}

#[cfg(not(unix))]
fn directory_is_writable(path: &str) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_dir() && !metadata.permissions().readonly())
}

/// `tempfile.gettempdir()`: the first usable of `TMPDIR`, `TEMP`, `TMP`, the
/// platform defaults and the working directory. `None` is the
/// `FileNotFoundError` Python raises when none is usable.
pub(crate) fn gettempdir(ctx: &Ctx) -> Option<PyPath> {
    let mut candidates: Vec<String> = ["TMPDIR", "TEMP", "TMP"]
        .iter()
        .filter_map(|name| ctx.host.env(name))
        .filter(|value| !value.is_empty())
        .collect();
    if cfg!(windows) {
        candidates.extend(["c:\\temp", "c:\\tmp", "\\temp", "\\tmp"].map(str::to_owned));
    } else {
        candidates.extend(["/tmp", "/var/tmp", "/usr/tmp"].map(str::to_owned));
    }
    let process_cwd = ctx.process_cwd.to_string();
    candidates.push(process_cwd.clone());
    for candidate in candidates {
        let absolute = if candidate == "." || candidate.starts_with('/') {
            PyPath::new(&candidate)
        } else {
            ctx.process_cwd.join(&candidate)
        };
        if directory_is_writable(&absolute.to_string()) {
            return Some(absolute);
        }
    }
    None
}

/// `Path.resolve(strict=False)`; `None` is the `OSError`/`RuntimeError` path.
pub(crate) fn resolve_lenient(path: &PyPath, ctx: &Ctx) -> Option<PyPath> {
    if path.is_absolute() {
        return pyfs::resolve(path);
    }
    pyfs::resolve(&ctx.process_cwd.join(&path.to_string()))
}

/// `Path.resolve(strict=True)`; `None` is the `OSError`/`RuntimeError` path.
pub(crate) fn resolve_existing(path: &PyPath) -> Option<PyPath> {
    // Lexical-plus-readlink resolution (no on-disk case folding, unlike
    // `fs::canonicalize` on macOS), then the strict existence check.
    let resolved = pyfs::resolve(path)?;
    fs::metadata(resolved.to_string()).ok()?;
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_values_follow_unicode_digit_runs() {
        assert_eq!(decimal_digits_value("0042"), Some(42));
        assert_eq!(decimal_digits_value("\u{661}\u{662}"), Some(12));
        assert_eq!(decimal_digits_value("\u{1d7d8}\u{1d7e3}"), Some(1));
        assert_eq!(decimal_digits_value("\u{b2}"), None);
        assert_eq!(decimal_digits_value(""), None);
        assert_eq!(decimal_digits_value("1a"), None);
        assert_eq!(
            decimal_digits_value("99999999999999999999999"),
            Some(u64::MAX)
        );
    }
}
