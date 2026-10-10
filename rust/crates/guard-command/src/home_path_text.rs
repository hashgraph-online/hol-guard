//! Shared home-expansion and cwd normalization for path text
//! (`runtime/home_path_text.py`, 23 lines — verbatim).

use std::path::Path;

/// `expand_home` (:9-15).
pub fn expand_home(value: &str, home_dir: Option<&Path>) -> String {
    if value == "~" {
        return home_dir
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(default_home);
    }
    if value.starts_with("~/") || value.starts_with("~\\") {
        let base = home_dir
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(default_home);
        // Normalize forward slashes in the suffix to the platform separator.
        let suffix = value[2..].replace('/', std::path::MAIN_SEPARATOR_STR);
        return Path::new(&base).join(suffix).to_string_lossy().into_owned();
    }
    value.to_owned()
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
fn normpath_nt(path: &str) -> String {
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
#[cfg(any(windows, test))]
fn split_root_nt(text: &str) -> (&str, &str, &str) {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'\\') {
        if bytes.get(1) == Some(&b':') {
            // The drive is the first two characters; they may not be ASCII.
            let split = text.char_indices().nth(2).map_or(text.len(), |(i, _)| i);
            let (drive, rest) = text.split_at(split);
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
    let start = if text.len() >= 8 && text[..8].eq_ignore_ascii_case("\\\\?\\UNC\\") {
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

#[cfg(windows)]
fn normpath(path: &str) -> String {
    normpath_nt(path)
}

/// `os.path.normpath` (POSIX): collapse `.`/empty, resolve `..` lexically,
/// preserve leading `//` special-casing and trailing-root semantics.
#[cfg(not(windows))]
fn normpath(path: &str) -> String {
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
    format!("{prefix}{joined}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn expand_home_tilde() {
        let home = PathBuf::from("/home/u");
        assert_eq!(
            expand_home("~", Some(&home)),
            home.to_string_lossy().into_owned()
        );
        assert_eq!(
            expand_home("~/x", Some(&home)),
            home.join("x").to_string_lossy().into_owned()
        );
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
    fn matches_python_oracle() {
        let home = PathBuf::from("/home/u");
        assert_eq!(
            expand_home("~", Some(&home)),
            home.to_string_lossy().into_owned()
        );
        assert_eq!(
            expand_home("~/a/b", Some(&home)),
            home.join("a").join("b").to_string_lossy().into_owned()
        );
        assert_eq!(
            expand_home("~\\w", Some(&home)),
            home.join("w").to_string_lossy().into_owned()
        );
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
