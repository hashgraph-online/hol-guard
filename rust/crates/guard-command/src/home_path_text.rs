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
    std::env::var_os("HOME")
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned())
}

/// `os.path.normpath` (POSIX): collapse `.`/empty, resolve `..` lexically,
/// preserve leading `//` special-casing and trailing-root semantics.
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
}
