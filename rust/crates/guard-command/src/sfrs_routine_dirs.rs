//! Proof-gated classification for routine local directory creation
//! (`routine_directory_creation.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_shlex::{split_with, STRICT_LEXER};
use crate::shell_secret_read_support::classify_request_secret_path;

const DYNAMIC_PATH_MARKERS: &[char] = &['$', '`', '*', '?', '[', ']', '{', '}', '\0'];
const SHELL_CONTROL_CHARACTERS: &[char] = &[';', '&', '|', '<', '>', '(', ')', '\r', '\n'];
const PROTECTED_DIRECTORY_NAMES: &[&str] = &[
    ".aws",
    ".codex",
    ".docker",
    ".git",
    ".gnupg",
    ".hol-guard",
    ".kube",
    ".ssh",
];

/// `str.casefold` for the names compared here: lower-casing plus the two
/// characters whose full case fold is ASCII (long s and sharp s).
fn casefold(part: &str) -> String {
    part.to_lowercase().replace('ſ', "s").replace('ß', "ss")
}

/// `Path.resolve(strict=False)`; `None` is the `OSError`/`RuntimeError` path.
fn resolve(path: &PyPath) -> Option<PyPath> {
    if path.is_absolute() {
        return pyfs::resolve(path);
    }
    let process_cwd = std::env::current_dir().ok()?;
    pyfs::resolve(&PyPath::new(&process_cwd.to_string_lossy()).join(&path.to_string()))
}

/// `is_safe_routine_directory_creation`: exact parents-only `mkdir` calls with
/// bounded literal targets.
pub(crate) fn is_safe_routine_directory_creation(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    if command_text.contains('\n') || command_text.contains('\r') {
        return false;
    }
    let Ok(parts) = split_with(STRICT_LEXER, command_text) else {
        return false;
    };
    if parts.len() < 3 || parts[0] != "mkdir" || !matches!(parts[1].as_str(), "-p" | "--parents") {
        return false;
    }
    let targets = &parts[2..];
    if targets
        .iter()
        .any(|target| target.starts_with('-') || target.contains(SHELL_CONTROL_CHARACTERS))
    {
        return false;
    }
    if targets
        .iter()
        .any(|target| target.contains(DYNAMIC_PATH_MARKERS))
    {
        return false;
    }
    let mut allowed_roots = Vec::new();
    for root in [cwd, home_dir].into_iter().flatten() {
        match resolve(&PyPath::new(&root.to_string_lossy())) {
            Some(resolved) => allowed_roots.push(resolved),
            None => return false,
        }
    }
    if allowed_roots.is_empty() {
        return false;
    }
    for target in targets {
        let candidate = if target == "~" {
            let Some(home) = home_dir else { return false };
            PyPath::new(&home.to_string_lossy())
        } else if let Some(rest) = target.strip_prefix("~/") {
            let Some(home) = home_dir else { return false };
            PyPath::new(&home.to_string_lossy()).join(rest)
        } else if target.starts_with('~') {
            return false;
        } else {
            PyPath::new(target)
        };
        let candidate = if candidate.is_absolute() {
            candidate
        } else {
            let Some(cwd) = cwd else { return false };
            if candidate.parts().iter().any(|part| part == "..") {
                return false;
            }
            PyPath::new(&cwd.to_string_lossy()).join(&candidate.to_string())
        };
        let Some(resolved) = resolve(&candidate) else {
            return false;
        };
        if !allowed_roots
            .iter()
            .any(|root| resolved.relative_to(root).is_some())
        {
            return false;
        }
        if resolved
            .parts()
            .iter()
            .any(|part| PROTECTED_DIRECTORY_NAMES.contains(&casefold(part).as_str()))
        {
            return false;
        }
        if classify_request_secret_path(&resolved.to_string(), cwd, home_dir).is_some() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe(text: &str, cwd: &Path, home: &Path) -> bool {
        is_safe_routine_directory_creation(text, Some(cwd), Some(home))
    }

    #[test]
    fn parents_only_literal_targets() {
        let dir = std::env::temp_dir().join("sfrs-routine-dirs");
        std::fs::create_dir_all(&dir).expect("dir");
        let home = dir.join("home");
        std::fs::create_dir_all(&home).expect("home");
        // The roots are `PurePosixPath`s (`PyPath`), so a Windows directory is
        // never a proven root and every creation there keeps its review.
        if cfg!(unix) {
            assert!(safe("mkdir -p out/build", &dir, &home));
            assert!(safe("mkdir --parents ~/work", &dir, &home));
        }
        assert!(!safe("mkdir out", &dir, &home));
        assert!(!safe("mkdir -p ../out", &dir, &home));
        assert!(!safe("mkdir -p .ssh", &dir, &home));
        assert!(!safe("mkdir -p a; rm -rf b", &dir, &home));
        assert!(!safe("mkdir -p $HOME/x", &dir, &home));
        assert!(!safe("mkdir -p /etc/x", &dir, &home));
    }
}
