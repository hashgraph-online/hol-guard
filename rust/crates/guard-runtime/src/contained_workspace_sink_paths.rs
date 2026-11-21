//! Paths as `guard execute-contained-test` spelled them, so the plan the
//! operations return compares with what the sink computes.

use std::path::Path;

/// `PATH`, each entry made absolute, as the operations search it.
pub(super) fn search_path() -> String {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".to_owned());
    path.split(':')
        .map(|item| absolute(&py_normal(item)))
        .collect::<Vec<_>>()
        .join(":")
}

/// `str(path.expanduser().absolute())`.
pub(super) fn wire_path(path: &Path) -> String {
    absolute(&py_normal(&expand_user(&path.to_string_lossy())))
}

/// `os.path.expanduser` for `~` and `~/...`.
pub(super) fn expand_user(text: &str) -> String {
    let home = || {
        crate::claude_hook_bridge::home_directory()
            .map(|home| home.to_string_lossy().into_owned())
            .unwrap_or_else(|| "~".to_owned())
    };
    if text == "~" {
        return home();
    }
    match text.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home().trim_end_matches('/')),
        None => text.to_owned(),
    }
}

/// `str(Path(text))`: repeated and trailing slashes and `.` parts dropped.
pub(super) fn py_normal(text: &str) -> String {
    if text.is_empty() {
        return ".".to_owned();
    }
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = parts.join("/");
    match (root, joined.is_empty()) {
        ("", true) => ".".to_owned(),
        (root, _) => format!("{root}{joined}"),
    }
}

/// `Path.absolute()` of a normalized path: relative paths join the current
/// directory.
fn absolute(normal: &str) -> String {
    if normal.starts_with('/') {
        return normal.to_owned();
    }
    let cwd = std::env::current_dir()
        .map(|cwd| cwd.to_string_lossy().into_owned())
        .unwrap_or_default();
    if normal == "." {
        cwd
    } else {
        format!("{}/{normal}", cwd.trim_end_matches('/'))
    }
}
