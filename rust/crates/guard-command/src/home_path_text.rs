//! Shared home-expansion and cwd normalization for path text
//! (`runtime/home_path_text.py`, 23 lines — verbatim).

use std::path::Path;

/// `expand_home` (:9-15).
///
/// Python reaches the home directory through `str(base / suffix)`, so pathlib
/// decides the answer: it drops empty and `.` components, keeps `..` where it
/// stands, lets an anchored suffix replace the base, and writes `.` for a path
/// left with nothing. `Path::join` does none of that, so the two helpers below
/// spell out pathlib's rules for each platform.
pub fn expand_home(value: &str, home_dir: Option<&Path>) -> String {
    if value != "~" && !value.starts_with("~/") && !value.starts_with("~\\") {
        return value.to_owned();
    }
    let home = home_dir
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(default_home);
    #[cfg(windows)]
    {
        expand_home_nt(value, &home)
    }
    #[cfg(not(windows))]
    {
        expand_home_posix(value, &home)
    }
}

/// `str(PurePosixPath(text))`.
#[cfg(any(not(windows), test))]
pub(crate) fn pure_posix(text: &str) -> String {
    let bytes = text.as_bytes();
    // pathlib keeps exactly two leading slashes; one, or three or more, is `/`.
    let root = if bytes.first() != Some(&b'/') {
        ""
    } else if bytes.len() > 1 && bytes[1] == b'/' && !(bytes.len() > 2 && bytes[2] == b'/') {
        "//"
    } else {
        "/"
    };
    let tail: Vec<&str> = text
        .split('/')
        .filter(|comp| !comp.is_empty() && *comp != ".")
        .collect();
    let formatted = format!("{root}{}", tail.join("/"));
    if formatted.is_empty() {
        ".".to_owned()
    } else {
        formatted
    }
}

/// `expand_home` where `Path` is `PurePosixPath`.
#[cfg(any(not(windows), test))]
pub(crate) fn expand_home_posix(value: &str, home: &str) -> String {
    if value == "~" {
        return pure_posix(home);
    }
    let Some(suffix) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    else {
        return value.to_owned();
    };
    // `base / suffix`: an anchored suffix replaces the base outright, and a
    // base of `PurePosixPath("")` leaves the suffix standing on its own.
    if suffix.starts_with('/') || home.is_empty() {
        return pure_posix(suffix);
    }
    // Append to the base's own text, where the leading slashes are already the
    // one or two pathlib keeps, so the join cannot invent a third or a second.
    let base = pure_posix(home);
    if base.ends_with('/') {
        return pure_posix(&format!("{base}{suffix}"));
    }
    pure_posix(&format!("{base}/{suffix}"))
}

/// `(drive, root, components)` as pathlib reads them, from backslash-only text.
#[cfg(any(windows, test))]
fn parse_nt(text: &str) -> (&str, &str, Vec<&str>) {
    let (drive, root, rest) = split_root_nt(text);
    // pathlib gives a UNC share a root of its own; `splitroot` leaves it empty.
    let root = if root.is_empty() && drive.starts_with("\\\\") {
        "\\"
    } else {
        root
    };
    let tail: Vec<&str> = rest
        .split('\\')
        .filter(|comp| !comp.is_empty() && *comp != ".")
        .collect();
    (drive, root, tail)
}

#[cfg(any(windows, test))]
fn format_nt(drive: &str, root: &str, tail: &[&str]) -> String {
    let formatted = format!("{drive}{root}{}", tail.join("\\"));
    if formatted.is_empty() {
        ".".to_owned()
    } else {
        formatted
    }
}

/// `str(PureWindowsPath(text))`.
#[cfg(any(windows, test))]
pub(crate) fn pure_nt(text: &str) -> String {
    let replaced = text.replace('/', "\\");
    let (drive, root, tail) = parse_nt(&replaced);
    format_nt(drive, root, &tail)
}

/// `expand_home` where `Path` is `PureWindowsPath`.
#[cfg(any(windows, test))]
pub(crate) fn expand_home_nt(value: &str, home: &str) -> String {
    if value == "~" {
        return pure_nt(home);
    }
    let Some(suffix) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    else {
        return value.to_owned();
    };
    let base_text = home.replace('/', "\\");
    let suffix_text = suffix.replace('/', "\\");
    let (base_drive, base_root, base_tail) = parse_nt(&base_text);
    let (suffix_drive, suffix_root, suffix_tail) = parse_nt(&suffix_text);
    if !suffix_drive.is_empty() {
        // A suffix naming the base's own drive keeps the base's components and
        // the suffix's spelling of the drive; any other drive replaces the base.
        if suffix_root.is_empty() && suffix_drive.to_lowercase() == base_drive.to_lowercase() {
            let mut tail = base_tail;
            tail.extend(suffix_tail);
            return format_nt(suffix_drive, base_root, &tail);
        }
        return format_nt(suffix_drive, suffix_root, &suffix_tail);
    }
    if !suffix_root.is_empty() {
        // Rooted but driveless: the base keeps only its drive.
        return format_nt(base_drive, suffix_root, &suffix_tail);
    }
    let mut tail = base_tail;
    tail.extend(suffix_tail);
    format_nt(base_drive, base_root, &tail)
}

/// `normalize_path` (:18-23). `os.path.isabs`/`normpath`/`join` on the runtime
/// platform; on POSIX these reduce to the string ops mirrored here.
pub fn normalize_path(value: &str, cwd: Option<&Path>) -> String {
    let joined = if is_abs(value) {
        value.to_owned()
    } else if let Some(cwd) = cwd {
        cwd.join(value).to_string_lossy().into_owned()
    } else {
        value.to_owned()
    };
    normpath(&joined)
}

fn is_abs(value: &str) -> bool {
    #[cfg(unix)]
    {
        value.starts_with('/')
    }
    #[cfg(windows)]
    {
        value.len() >= 3
            && value.as_bytes()[1] == b':'
            && (value.as_bytes()[2] == b'\\' || value.as_bytes()[2] == b'/')
            || value.starts_with("\\\\")
    }
}

fn default_home() -> String {
    // `Path.home()`: `HOME` on POSIX, `USERPROFILE` on Windows.
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned())
}

/// `ntpath.normpath` (Python 3.12 algorithm): forward slashes become
/// backslashes, `splitroot` keeps a drive or UNC prefix and its root, `.` and
/// empty components collapse, and `..` pops lexically (a `..` at the start of
/// a rooted path is dropped, one at the start of a relative path is kept).
/// Device and verbatim prefixes (`\\?\`, `\\.\`) are split like any other
/// drive, matching Python 3.13 and later.
#[cfg(any(windows, test))]
pub(crate) fn normpath_nt(path: &str) -> String {
    let text = path.replace('/', "\\");
    let (drive, root, tail) = split_root_nt(&text);
    let mut comps: Vec<&str> = Vec::new();
    for comp in tail.split('\\') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if comps.last().is_some_and(|last| *last != "..") {
                comps.pop();
            } else if root.is_empty() {
                comps.push("..");
            }
            continue;
        }
        comps.push(comp);
    }
    if drive.is_empty() && root.is_empty() && comps.is_empty() {
        return ".".to_owned();
    }
    format!("{drive}{root}{}", comps.join("\\"))
}

/// `ntpath.splitroot` on a backslash-only text: `(drive, root, tail)`.
pub(crate) fn split_root_nt(text: &str) -> (&str, &str, &str) {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'\\') {
        // `splitroot` reads the drive as the first two characters, and neither
        // has to be ASCII, so the colon is looked for at the second character
        // rather than the second byte. In `é:\home` the second byte is the
        // trailing half of `é`, so a byte index misses the drive entirely and
        // the text behind a `~` joins as a plain component.
        if let Some((index, ':')) = text.char_indices().nth(1) {
            let (drive, rest) = text.split_at(index + 1);
            return match rest.strip_prefix('\\') {
                Some(tail) => (drive, "\\", tail),
                None => (drive, "", rest),
            };
        }
        return ("", "", text);
    }
    if bytes.get(1) != Some(&b'\\') {
        return ("", "\\", &text[1..]);
    }
    // Compare bytes: a character may straddle byte 8, and `text[..8]` would panic.
    let start = if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"\\\\?\\UNC\\") {
        8
    } else {
        2
    };
    let Some(index) = text[start..].find('\\').map(|i| i + start) else {
        return (text, "", "");
    };
    let index2 = text[index + 1..]
        .find('\\')
        .map_or(text.len(), |i| i + index + 1);
    if index2 >= text.len() {
        return (text, "", "");
    }
    (
        &text[..index2],
        &text[index2..index2 + 1],
        &text[index2 + 1..],
    )
}

fn normpath(path: &str) -> String {
    #[cfg(windows)]
    {
        normpath_nt(path)
    }
    #[cfg(not(windows))]
    {
        normpath_posix(path)
    }
}

/// `os.path.normpath` (POSIX): collapse `.`/empty, resolve `..` lexically,
/// preserve leading `//` special-casing and trailing-root semantics.
#[cfg(any(not(windows), test))]
pub(crate) fn normpath_posix(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    // posixpath: prefix is "//" iff leading double-slash (not triple+), else "/"
    // iff absolute, else "".
    let bytes = path.as_bytes();
    let prefix: &str = if bytes.is_empty() || bytes[0] != b'/' {
        ""
    } else if bytes.len() > 1 && bytes[1] == b'/' && !(bytes.len() > 2 && bytes[2] == b'/') {
        "//"
    } else {
        "/"
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            // posixpath: keep ".." when it stays a leading relative climb
            // (no prefix) or already a ".." run; otherwise pop if nonempty.
            if prefix.is_empty() && (comps.is_empty() || comps.last() == Some(&"..")) {
                comps.push("..");
            } else if !comps.is_empty() {
                comps.pop();
            }
            continue;
        }
        comps.push(comp);
    }
    let joined = comps.join("/");
    let formatted = format!("{prefix}{joined}");
    // posixpath ends with `return path or '.'`: a relative path whose
    // components all collapse is the current directory, not the empty string.
    if formatted.is_empty() {
        ".".to_owned()
    } else {
        formatted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The expansion runs through the host's own pure path, so on Windows a
    /// home spelled with forward slashes comes back spelled with backslashes.
    /// `PathBuf::from` keeps the text it is handed and `join` only adds the
    /// platform's separator, so neither rebuilds that answer: the home and the
    /// separator are spelled out per platform instead.
    #[cfg(unix)]
    const HOME: &str = "/home/u";
    #[cfg(unix)]
    const SEP: &str = "/";
    #[cfg(windows)]
    const HOME: &str = "\\home\\u";
    #[cfg(windows)]
    const SEP: &str = "\\";

    #[test]
    fn expand_home_tilde() {
        let home = PathBuf::from(HOME);
        assert_eq!(expand_home("~", Some(&home)), HOME);
        assert_eq!(expand_home("~/x", Some(&home)), format!("{HOME}{SEP}x"));
        assert_eq!(expand_home("plain", Some(&home)), "plain");
    }

    #[cfg(unix)]
    #[test]
    fn normpath_collapses() {
        assert_eq!(normpath("/a//b/./c/../d"), "/a/b/d");
        assert_eq!(normpath("a/../b"), "b");
        assert_eq!(normpath(""), ".");
    }

    #[test]
    fn split_root_nt_never_panics_on_multibyte_unc_prefix() {
        // Vector from `ntpath.splitroot` on the old Python implementation.
        assert_eq!(
            split_root_nt("\\\\s\\a\u{e9}\u{e9}\\file.txt"),
            ("\\\\s\\a\u{e9}\u{e9}", "\\", "file.txt")
        );
        assert_eq!(
            split_root_nt("\\\\?\\UNC\\h\\s\\f"),
            ("\\\\?\\UNC\\h\\s", "\\", "f")
        );
        assert_eq!(
            split_root_nt("\\\\\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"),
            ("\\\\\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", "", "")
        );
    }

    #[test]
    fn matches_python_oracle() {
        let home = PathBuf::from(HOME);
        assert_eq!(expand_home("~", Some(&home)), HOME);
        assert_eq!(
            expand_home("~/a/b", Some(&home)),
            format!("{HOME}{SEP}a{SEP}b")
        );
        assert_eq!(expand_home("~\\w", Some(&home)), format!("{HOME}{SEP}w"));
        assert_eq!(expand_home("plain", Some(&home)), "plain");
        assert_eq!(expand_home("/abs", Some(&home)), "/abs");

        #[cfg(unix)]
        {
            let cwd = PathBuf::from("/cwd");
            assert_eq!(normalize_path("/a//b/./c/../d", Some(&cwd)), "/a/b/d");
            assert_eq!(normalize_path("a/../b", Some(&cwd)), "/cwd/b");
            assert_eq!(normalize_path("", Some(&cwd)), "/cwd");
            assert_eq!(normalize_path("./x", Some(&cwd)), "/cwd/x");
            assert_eq!(normalize_path("//p//q", Some(&cwd)), "//p/q");
            assert_eq!(normalize_path("a/b/../..", Some(&cwd)), "/cwd");
            assert_eq!(normalize_path("../up", Some(&cwd)), "/up");
            assert_eq!(normalize_path("..", Some(&cwd)), "/");
        }
    }

    /// Recorded from Python's `ntpath.normpath`; runs on every host because the
    /// Windows normalizer is plain text logic.
    #[test]
    fn normpath_nt_matches_recorded_ntpath_vectors() {
        const VECTORS: &[(&str, &str)] = &[
            ("", "."),
            (".", "."),
            ("..", ".."),
            ("\\", "\\"),
            ("/", "\\"),
            ("C:", "C:"),
            ("C:\\", "C:\\"),
            ("C:/", "C:\\"),
            ("c:foo", "c:foo"),
            ("C:\\a\\b", "C:\\a\\b"),
            ("C:/a//b/./c/../d", "C:\\a\\b\\d"),
            ("C:\\a\\..\\..\\b", "C:\\b"),
            ("C:a\\..\\..\\b", "C:..\\b"),
            ("a\\b\\..\\c", "a\\c"),
            ("..\\up", "..\\up"),
            ("a\\..", "."),
            ("a\\..\\..", ".."),
            ("\\a\\..\\..\\b", "\\b"),
            ("/a/b/", "\\a\\b"),
            ("\\\\srv\\shr", "\\\\srv\\shr"),
            ("\\\\srv\\shr\\", "\\\\srv\\shr\\"),
            ("\\\\srv\\shr\\x\\..\\y", "\\\\srv\\shr\\y"),
            ("\\\\srv", "\\\\srv"),
            ("\\\\srv\\", "\\\\srv\\"),
            ("\\\\?\\C:\\a\\..\\b", "\\\\?\\C:\\b"),
            ("\\\\.\\pipe\\x", "\\\\.\\pipe\\x"),
            ("\\\\?\\UNC\\srv\\shr\\a\\..\\b", "\\\\?\\UNC\\srv\\shr\\b"),
            ("C:\\Users\\Me\\.ssh\\..\\.env", "C:\\Users\\Me\\.env"),
            ("C:\\x\\.\\y\\", "C:\\x\\y"),
            ("c:\\A\\B", "c:\\A\\B"),
            ("\\\\srv\\shr\\..\\x", "\\\\srv\\shr\\x"),
            ("x/y\\z", "x\\y\\z"),
            ("C:..\\x", "C:..\\x"),
            ("C:\\..\\x", "C:\\x"),
            ("\\\\\\a", "\\\\\\a"),
            ("a\\\\b", "a\\b"),
            ("C:\\\\a", "C:\\a"),
        ];
        for (input, expected) in VECTORS {
            assert_eq!(super::normpath_nt(input), *expected, "{input:?}");
        }
    }
}
