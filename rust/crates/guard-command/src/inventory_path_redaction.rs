//! `inventory_contract_redaction` path half — `redact_local_path`,
//! `_redact_known_path` and `_redact_command_value`, the three functions that
//! decide which parts of a local path and an exported command string leave the
//! machine.
//!
//! Four CPython behaviours decide the output and none is the Rust default:
//!
//! * `pathlib.Path` is `PurePosixPath` on unix and `PureWindowsPath` on
//!   Windows. The flavour is not cosmetic here: a Windows path parsed with
//!   POSIX rules keeps `C:\Users\someone` as one component, so `relative_to`
//!   never matches the home prefix and the `path.name` fallback would export
//!   the whole private path as a "name". [`PyNativePath`] parses the way the
//!   runtime platform's `pathlib` does.
//! * `Path.resolve()` is non-strict: it canonicalizes the longest existing
//!   prefix, resolves symlinks along it and invents the rest. Rust's
//!   `canonicalize` fails outright on a missing component. The unix side
//!   reuses [`crate::codex_output_fs::resolve`], CPython's
//!   `posixpath._joinrealpath` port, so a symlink loop stays the
//!   `RuntimeError` these callers catch.
//! * `relative_to` compares components, and on Windows `pathlib` compares them
//!   case-insensitively, so `C:\USERS\me\x` is inside `C:\Users\me`.
//! * CPython `re` treats `\s`/`\S` as `Py_UNICODE_ISSPACE` (U+001C..U+001F
//!   included) and folds `İ`/`ı` onto `i` under `re.IGNORECASE`, so a naive
//!   port of the command-value patterns leaks `--token\u{1d}abc` and
//!   `ap\u{131}_key=abc`.
//!
//! One divergence is deliberate. [`crate::codex_output_fs::resolve`] does not
//! model the POSIX double-slash root, so a `//`-rooted candidate resolves to
//! `None` here and takes the bare-name fallback where CPython would have kept
//! the `{home}/` or `{workspace}/` form. That drops context rather than
//! exporting a private prefix, which is the safe direction for this caller;
//! `double_slash_root_falls_back_to_the_bare_name` pins it so the fallback
//! cannot quietly turn into an export.
//!
//! `scripts/ci/generate_inventory_path_parity.py` records the corpus in
//! `testdata/inventory_path_parity.json` that pins every case below.

use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

use serde_json::{Map, Value};

use crate::inventory_contract::InventoryRedactionApi;
use crate::inventory_redaction::{
    assert_serialized_inventory_payload_safe, redact_url, safe_json, safe_source_detail,
    substitute_sensitive_values, PYTHON_SPACE_CLASS, PYTHON_WORD_CLASS,
};

/// CPython `re.IGNORECASE` folds `İ` (U+0130) and `ı` (U+0131) onto `i`;
/// Rust's simple case folding leaves both alone. The serializer half folds the
/// subject before matching, but these patterns substitute into the subject, so
/// the equivalents are spelled into the pattern instead. `ſ` needs no help:
/// Rust folds it onto `s` already, as CPython does.
const PYTHON_I: &str = r"[i\x{130}\x{131}]";

/// `pathlib.PurePath` on the runtime platform's flavour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PyNativePath {
    drive: String,
    root: String,
    comps: Vec<String>,
}

impl PyNativePath {
    pub(crate) fn new(text: &str) -> Self {
        let (drive, root, comps) = parse_native(text);
        Self { drive, root, comps }
    }

    /// `PurePath.is_absolute()`: a POSIX root, or a Windows drive *and* root.
    pub(crate) fn is_absolute(&self) -> bool {
        if cfg!(windows) {
            !self.drive.is_empty() && !self.root.is_empty()
        } else {
            !self.root.is_empty()
        }
    }

    /// `PurePath.name`.
    pub(crate) fn name(&self) -> &str {
        self.comps.last().map_or("", String::as_str)
    }

    /// `PurePath.parts`: the drive and root fused into one anchor, then the
    /// components. Only the parity tests read it; the ported functions reach
    /// for [`Self::name`] and [`Self::relative_to`].
    #[cfg(test)]
    pub(crate) fn parts(&self) -> Vec<String> {
        let anchor = format!("{}{}", self.drive, self.root);
        let mut parts = Vec::with_capacity(self.comps.len() + 1);
        if !anchor.is_empty() {
            parts.push(anchor);
        }
        parts.extend(self.comps.iter().cloned());
        parts
    }

    /// `Path.relative_to` as a component list; `None` is the `ValueError`.
    pub(crate) fn relative_to(&self, base: &Self) -> Option<Vec<String>> {
        if normcase(&self.drive) != normcase(&base.drive) || self.root != base.root {
            return None;
        }
        if self.comps.len() < base.comps.len() {
            return None;
        }
        let matches = self
            .comps
            .iter()
            .zip(base.comps.iter())
            .all(|(mine, theirs)| normcase(mine) == normcase(theirs));
        if !matches {
            return None;
        }
        Some(self.comps[base.comps.len()..].to_vec())
    }
}

/// `PurePath.as_posix()` of a relative path; `Path('.')` for the empty one,
/// which is what `relative_to` returns when the two paths are equal.
fn relative_as_posix(parts: &[String]) -> String {
    if parts.is_empty() {
        return ".".to_owned();
    }
    parts.join("/")
}

/// `os.path.normcase`: identity on POSIX, lower-case on Windows, which is how
/// `pathlib` compares Windows path components.
fn normcase(text: &str) -> String {
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.to_owned()
    }
}

#[cfg(not(windows))]
fn parse_native(text: &str) -> (String, String, Vec<String>) {
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    (
        String::new(),
        root.to_owned(),
        split_components(text, false),
    )
}

#[cfg(windows)]
fn parse_native(text: &str) -> (String, String, Vec<String>) {
    let (drive, mut root, rest) = split_root(text);
    // `PurePath._parse_path`'s fix-up: a bare `\\\\server\\share` or
    // `\\\\?\\UNC\\server\\share` drive is rooted even though `splitroot` found
    // no separator after it, which is what makes it absolute and what lets
    // `relative_to` match it against a path below it.
    if root.is_empty() && drive.starts_with('\\') && !drive.ends_with('\\') {
        let drive_parts: Vec<&str> = drive.split('\\').collect();
        let rooted = match drive_parts.len() {
            // `"x" in "?."` is CPython's test, so the empty string and `?.`
            // itself count as the device prefixes it excludes.
            4 => !"?.".contains(drive_parts[2]),
            6 => true,
            _ => false,
        };
        if rooted {
            root = "\\".to_owned();
        }
    }
    (drive, root, split_components(&rest, true))
}

/// `ntpath.splitroot`: the drive, the single separator that makes the path
/// rooted, and the remainder.
///
/// The degenerate cases are the ones that matter. `\\\\server\\share` is a drive
/// with no root, so `PureWindowsPath` calls it relative; `///` is a drive of
/// three separators and no root at all; and `C:///x` has a one-separator root
/// however many separators were typed.
///
/// Only the Windows build parses paths with it, but every build compiles it
/// under `cfg(test)` so its parity tests run on the platforms CI covers rather
/// than sitting unbuilt behind `cfg(windows)`.
#[cfg(any(windows, test))]
fn split_root(text: &str) -> (String, String, String) {
    let normalized = text.replace('/', "\\");
    let bytes = normalized.as_bytes();
    let separator = |index: usize| bytes.get(index) == Some(&b'\\');
    if separator(0) {
        if !separator(1) {
            return (String::new(), "\\".to_owned(), normalized[1..].to_owned());
        }
        // `\\?\UNC\server\share` keeps the whole prefix as the drive.
        // `ntpath.splitroot` upper-cases the first eight characters before
        // comparing, so `\\?\unc\server\share` is the same prefix. Matching
        // only the upper-case spelling would leave `share` as the file name,
        // and the name fallback in this module exports a file name.
        let start = if normalized
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\UNC\"))
        {
            8
        } else {
            2
        };
        let whole = (normalized.clone(), String::new(), String::new());
        let Some(server_end) = normalized.get(start..).and_then(|rest| rest.find('\\')) else {
            return whole;
        };
        let server_end = start + server_end;
        let Some(share_end) = normalized
            .get(server_end + 1..)
            .and_then(|rest| rest.find('\\'))
        else {
            return whole;
        };
        let share_end = server_end + 1 + share_end;
        return (
            normalized[..share_end].to_owned(),
            "\\".to_owned(),
            normalized[share_end + 1..].to_owned(),
        );
    }
    // `ntpath.splitroot` tests the second *character* for the colon, so a drive
    // letter may be any character, not only an ASCII one. Reading byte 1 would
    // see a continuation byte for a path like `\u{e9}:\\Users\\alice` and call an
    // absolute path relative, which would send it back unredacted.
    if let Some((colon, ':')) = normalized.char_indices().nth(1) {
        let drive_end = colon + 1;
        if separator(drive_end) {
            return (
                normalized[..drive_end].to_owned(),
                "\\".to_owned(),
                normalized[drive_end + 1..].to_owned(),
            );
        }
        return (
            normalized[..drive_end].to_owned(),
            String::new(),
            normalized[drive_end..].to_owned(),
        );
    }
    (String::new(), String::new(), normalized)
}

/// The components `pathlib` keeps: separator-delimited, minus the empty ones
/// and `.`. `..` survives, which is why `Path('a/..').name` is `'..'`.
fn split_components(text: &str, windows: bool) -> Vec<String> {
    text.split(|c| c == '/' || (windows && c == '\\'))
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect()
}

/// `Path.resolve()` against `cwd`. `None` is the `OSError`/`RuntimeError` the
/// Python callers catch, including a symlink loop.
///
/// `cwd` replaces CPython's `os.getcwd()`: the resident resolves a request
/// against the working directory the request context proved, not the
/// runtime's own. An empty `cwd` is the caller stating it has none, because
/// its own directory was deleted and `os.getcwd()` would have raised. A
/// relative value is then unresolvable, exactly as it was for the Python this
/// replaces; resolving it against the resident's directory would answer about
/// a directory the caller never stood in.
#[cfg(not(windows))]
fn resolve(text: &str, cwd: &Path) -> Option<String> {
    use crate::codex_output_py::PyPath;

    let candidate = PyPath::new(text);
    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        if cwd.as_os_str().is_empty() {
            return None;
        }
        PyPath::new(&cwd.to_string_lossy()).join(text)
    };
    crate::codex_output_fs::resolve(&absolute).map(|resolved| resolved.to_string())
}

#[cfg(windows)]
fn resolve(text: &str, cwd: &Path) -> Option<String> {
    let candidate = if PyNativePath::new(text).is_absolute() {
        PathBuf::from(text)
    } else {
        if cwd.as_os_str().is_empty() {
            return None;
        }
        cwd.join(text)
    };
    weak_canonicalize(&candidate).map(|resolved| resolved.to_string_lossy().into_owned())
}

/// `Path.resolve(strict=False)`: canonicalize the deepest existing prefix and
/// append the remainder, collapsing the `..` segments `realpath` would.
#[cfg(windows)]
fn weak_canonicalize(path: &Path) -> Option<PathBuf> {
    use crate::runtime_read_paths::canonicalize_text;

    if let Ok(resolved) = canonicalize_text(path) {
        return Some(resolved);
    }
    let mut prefix = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(resolved) = canonicalize_text(&prefix) {
            let mut out = resolved;
            for part in tail.iter().rev() {
                if part == ".." {
                    out.pop();
                    continue;
                }
                if part == "." {
                    continue;
                }
                out.push(part);
            }
            return Some(out);
        }
        let name = prefix.file_name()?.to_os_string();
        tail.push(name);
        if !prefix.pop() {
            return None;
        }
    }
}

/// `redact_local_path` (:22-31) — the home boundary, or just the file name.
pub fn redact_local_path(path: &str, home_dir: Option<&Path>, cwd: &Path) -> String {
    let candidate = PyNativePath::new(path);
    let Some(home_dir) = home_dir else {
        return candidate.name().to_owned();
    };
    let fallback = || candidate.name().to_owned();
    let (Some(resolved), Some(home)) = (
        resolve(path, cwd),
        resolve(&home_dir.to_string_lossy(), cwd),
    ) else {
        return fallback();
    };
    match PyNativePath::new(&resolved).relative_to(&PyNativePath::new(&home)) {
        Some(parts) => format!("{{home}}/{}", relative_as_posix(&parts)),
        None => fallback(),
    }
}

/// `_redact_known_path` (:155-169) — home first, then the workspace, then the
/// bare file name. A relative path is already free of the private prefix.
pub fn redact_known_path(
    value: &str,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
    cwd: &Path,
) -> String {
    let path = PyNativePath::new(value);
    if !path.is_absolute() {
        return value.to_owned();
    }
    let home_redacted = redact_local_path(value, Some(home_dir), cwd);
    if home_redacted.starts_with("{home}/") {
        return home_redacted;
    }
    let Some(workspace_dir) = workspace_dir else {
        return path.name().to_owned();
    };
    let (Some(resolved), Some(workspace)) = (
        resolve(value, cwd),
        resolve(&workspace_dir.to_string_lossy(), cwd),
    ) else {
        return path.name().to_owned();
    };
    match PyNativePath::new(&resolved).relative_to(&PyNativePath::new(&workspace)) {
        Some(parts) => format!("{{workspace}}/{}", relative_as_posix(&parts)),
        None => path.name().to_owned(),
    }
}

/// `\b[a-z][a-z0-9+.-]*://[^\s]+` — every URL inside the command text. The
/// scheme classes carry the `I`-like characters because CPython's `(?i)[a-z]`
/// matches `\u{130}` and `\u{131}` and Rust's does not.
static COMMAND_URL_RE: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(&format!(
        r"(?i)(?<![{word}])[a-z{extras}][a-z0-9+.\-{extras}]*://[^{space}]+",
        word = PYTHON_WORD_CLASS,
        extras = r"\x{130}\x{131}",
        space = PYTHON_SPACE_CLASS,
    ))
    .expect("command url pattern")
});

/// `(^|\s)(/[^\s]+)` — an absolute POSIX path argument.
static COMMAND_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(^|[{PYTHON_SPACE_CLASS}])(/[^{PYTHON_SPACE_CLASS}]+)",
    ))
    .expect("command path pattern")
});

/// `(?i)(authorization:\s*bearer\s+)\S+`.
static COMMAND_BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)(author{PYTHON_I}zat{PYTHON_I}on:[{PYTHON_SPACE_CLASS}]*bearer[{PYTHON_SPACE_CLASS}]+)[^{PYTHON_SPACE_CLASS}]+",
    ))
    .expect("command bearer pattern")
});

/// `(?i)((?:api[_-]?key|auth|password|secret|token)=)\S+`.
static COMMAND_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)((?:ap{PYTHON_I}[_-]?key|auth|password|secret|token)=)[^{PYTHON_SPACE_CLASS}]+",
    ))
    .expect("command assignment pattern")
});

/// `(?i)((?:--)?(?:api[_-]?key|auth|password|secret|token)\s+)\S+`.
static COMMAND_OPTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)((?:--)?(?:ap{PYTHON_I}[_-]?key|auth|password|secret|token)[{PYTHON_SPACE_CLASS}]+)[^{PYTHON_SPACE_CLASS}]+",
    ))
    .expect("command option pattern")
});

/// `_redact_command_value` (:172-198) — the four `re.sub` passes, in order.
pub fn redact_command_value(
    value: &str,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
    cwd: &Path,
) -> String {
    let redacted = substitute_urls(value);
    let redacted = COMMAND_PATH_RE.replace_all(&redacted, |captures: &regex::Captures<'_>| {
        format!(
            "{}{}",
            &captures[1],
            redact_known_path(&captures[2], home_dir, workspace_dir, cwd)
        )
    });
    let redacted = COMMAND_BEARER_RE.replace_all(&redacted, "${1}redacted");
    let redacted = COMMAND_ASSIGNMENT_RE.replace_all(&redacted, "${1}redacted");
    COMMAND_OPTION_RE
        .replace_all(&redacted, "${1}redacted")
        .into_owned()
}

/// `re.sub` with a lookbehind pattern: non-overlapping, left to right.
///
/// A backtracking bound cannot happen in CPython's `re.sub`, so there is no
/// faithful text to fall back to; the rest of the value is dropped rather than
/// emitted unredacted.
fn substitute_urls(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0;
    for found in COMMAND_URL_RE.find_iter(value) {
        let Ok(found) = found else {
            return out;
        };
        out.push_str(&value[cursor..found.start()]);
        out.push_str(&redact_url(found.as_str()));
        cursor = found.end();
    }
    out.push_str(&value[cursor..]);
    out
}

/// `_safe_finding_text(value, *, home_dir, workspace_dir)`.
///
/// The slice is `value[:500]` in CPython, which counts characters, so the
/// truncation is taken over `char_indices` rather than bytes.
pub fn safe_finding_text(
    value: &str,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
    cwd: &Path,
) -> String {
    let redacted = substitute_sensitive_values(value);
    let redacted = redact_command_value(&redacted, home_dir, workspace_dir, cwd);
    match redacted.char_indices().nth(500) {
        Some((boundary, _)) => redacted[..boundary].to_string(),
        None => redacted,
    }
}

/// The native `InventoryRedactionApi` seam for
/// [`crate::inventory_contract::InventoryDeps`].
///
/// `cwd` is the directory CPython's `Path.resolve()` would have resolved a
/// relative candidate against. The inventory callers only ever hand these
/// functions absolute paths, so it decides nothing for them, but the seam
/// carries it rather than inventing one per call.
#[derive(Debug, Clone, Copy)]
pub struct NativeInventoryRedaction<'a> {
    pub cwd: &'a Path,
}

impl InventoryRedactionApi for NativeInventoryRedaction<'_> {
    fn redact_local_path(&self, path: &Path, home_dir: Option<&Path>) -> String {
        redact_local_path(&path.to_string_lossy(), home_dir, self.cwd)
    }

    fn _redact_known_path(
        &self,
        value: &str,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
    ) -> String {
        redact_known_path(value, home_dir, workspace_dir, self.cwd)
    }

    fn _safe_finding_text(
        &self,
        value: &str,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
    ) -> String {
        safe_finding_text(value, home_dir, workspace_dir, self.cwd)
    }

    fn _safe_source_detail(&self, run: &Map<String, Value>) -> String {
        safe_source_detail(run)
    }

    fn _safe_json(&self, value: &Value, parent_key: &str, parent_sensitive: bool) -> Value {
        safe_json(value, parent_key, parent_sensitive)
    }

    fn _assert_serialized_inventory_payload_safe(&self, payload: &Value) -> Result<(), String> {
        assert_serialized_inventory_payload_safe(payload)
    }
}

#[cfg(test)]
#[path = "inventory_path_redaction_tests.rs"]
mod tests;
