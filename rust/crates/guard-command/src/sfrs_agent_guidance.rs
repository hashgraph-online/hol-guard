//! Narrow allowlist for bounded reads of verified local agent guidance
//! (`agent_guidance_reads.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::false_positive_rules::target_is_known_skill_doc_path;
use crate::shell_execution_context::model_shell_execution_context;

const AGENT_DOC_PATHS: &[&str] = &[
    ".codex/docs/harness-engineering.md",
    ".codex/docs/token-discipline.md",
];

/// `is_benign_agent_guidance_read`.
pub(crate) fn is_benign_agent_guidance_read(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
) -> bool {
    if ["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| command_text.contains(marker))
    {
        return false;
    }
    let context = model_shell_execution_context(command_text, cwd, cwd, Some(home_dir));
    if !context.complete || !(1..=8).contains(&context.segments.len()) {
        return false;
    }
    for segment in &context.segments {
        let controls = segment.control_before.iter().chain(&segment.control_after);
        if controls.into_iter().any(|operator| operator != "&&")
            || segment.directory_operation.is_some()
        {
            return false;
        }
        let Some(target) = bounded_sed_read_target(&segment.tokens) else {
            return false;
        };
        if is_approved_agent_doc_target(target, home_dir)
            || is_guard_safety_doc_target(target, home_dir)
        {
            continue;
        }
        return false;
    }
    true
}

fn line_number(text: &str) -> Option<u32> {
    let valid = (1..=4).contains(&text.len())
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !text.starts_with('0');
    valid.then(|| text.parse().ok()).flatten()
}

/// `_bounded_sed_read_target`.
fn bounded_sed_read_target(parts: &[String]) -> Option<&str> {
    if parts.len() != 4 || parts[0] != "sed" || parts[1] != "-n" {
        return None;
    }
    let range = parts[2].strip_suffix('p')?;
    let (start, end) = range.split_once(',')?;
    let (start, end) = (line_number(start)?, line_number(end)?);
    (start <= end && end - start < 500).then_some(parts[3].as_str())
}

fn home_candidate(target: &str, home_dir: &Path) -> PyPath {
    match target.strip_prefix("~/") {
        Some(rest) => PyPath::new(&home_dir.to_string_lossy()).join(rest),
        None => PyPath::new(target),
    }
}

/// `_is_approved_agent_doc_target`.
fn is_approved_agent_doc_target(target: &str, home_dir: &Path) -> bool {
    let normalized = target.replace('\\', "/");
    if normalized.trim_end_matches('/').ends_with("/SKILL.md") {
        return target_is_known_skill_doc_path(target, Some(home_dir));
    }
    let home = PyPath::new(&home_dir.to_string_lossy());
    let expected = AGENT_DOC_PATHS
        .iter()
        .any(|path| target == format!("~/{path}") || target == home.join(path).to_string());
    expected
        && is_regular_file_without_symlink_components(&home_candidate(target, home_dir), home_dir)
}

/// `_is_guard_safety_doc_target`.
fn is_guard_safety_doc_target(target: &str, home_dir: &Path) -> bool {
    let home = PyPath::new(&home_dir.to_string_lossy());
    let expected = home.join(".hol-support").join("SAFETY.md");
    let candidate = home_candidate(target, home_dir);
    match (absolute(&candidate), absolute(&expected)) {
        (Some(candidate_abs), Some(expected_abs)) if candidate_abs == expected_abs => {
            is_regular_file_without_symlink_components(&expected, home_dir)
        }
        _ => false,
    }
}

/// `Path.absolute()`: a relative path joins the process working directory.
fn absolute(path: &PyPath) -> Option<PyPath> {
    if path.is_absolute() {
        return Some(path.clone());
    }
    let cwd = std::env::current_dir().ok()?;
    Some(PyPath::new(&cwd.to_string_lossy()).join(&path.to_string()))
}

/// `Path.resolve(strict=True)`; `None` is any raised error.
fn resolve_strict(path: &PyPath) -> Option<PyPath> {
    let resolved = pyfs::resolve(&absolute(path)?)?;
    pyfs::exists(&resolved).ok()?.then_some(resolved)
}

/// `_is_regular_file_without_symlink_components`.
fn is_regular_file_without_symlink_components(candidate: &PyPath, home_dir: &Path) -> bool {
    let home = PyPath::new(&home_dir.to_string_lossy());
    let Some(resolved_home) = resolve_strict(&home) else {
        return false;
    };
    let Some(relative) = candidate.relative_to(&home) else {
        return false;
    };
    let mut current = home;
    for part in relative {
        current = current.join(&part);
        match pyfs::is_symlink(&current) {
            Ok(false) => {}
            _ => return false,
        }
    }
    let Some(resolved_candidate) = resolve_strict(candidate) else {
        return false;
    };
    resolved_candidate.relative_to(&resolved_home).is_some()
        && pyfs::is_file(&resolved_candidate) == Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn bounded_sed_reads() {
        let ok = tokens(&["sed", "-n", "1,200p", "doc.md"]);
        assert_eq!(bounded_sed_read_target(&ok), Some("doc.md"));
        for bad in [
            tokens(&["sed", "-n", "0,5p", "doc.md"]),
            tokens(&["sed", "-n", "1,501p", "doc.md"]),
            tokens(&["sed", "-n", "9,3p", "doc.md"]),
            tokens(&["sed", "-n", "1,5p"]),
            tokens(&["sed", "-i", "1,5p", "doc.md"]),
            tokens(&["sed", "-n", "12345,12346p", "doc.md"]),
        ] {
            assert_eq!(bounded_sed_read_target(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rejects_substitutions_before_modelling() {
        let home = Path::new("/");
        assert!(!is_benign_agent_guidance_read(
            "sed -n 1,2p $(x)",
            None,
            home
        ));
    }
}
