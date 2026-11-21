//! Bounded local validation for GitHub pull-request body files: operand
//! parsing, name and location rules (`github_pr_body_file.py`, everything
//! before the descriptor checks in `sfrs_gh_body_file_check`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, PyPath};
use crate::sfrs_gh_pyshim::{decimal_digits_value, gettempdir, resolve_existing, resolve_lenient};

static REPOSITORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z").expect("repository pattern")
});

const SHELL_EXPANSION_MARKERS: [&str; 14] = [
    "$", "`", "*", "?", "[", "]", "{", "}", "(", ")", "<", ">", "^", "#",
];

/// `str.casefold` for the names compared here.
fn casefold(text: &str) -> String {
    caseless::default_case_fold_str(text)
}

/// `static_markdown_pr_edit_body_file_operand`: one body file from a
/// narrowly bounded pull-request edit.
pub(crate) fn static_markdown_pr_edit_body_file_operand(args: &[String]) -> Option<String> {
    let mut selectors: Vec<&str> = Vec::new();
    let mut body_files: Vec<&str> = Vec::new();
    let mut repositories: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if matches!(token, "--body-file" | "-F" | "--repo" | "-R") {
            let value = args.get(index + 1)?.as_str();
            if matches!(token, "--body-file" | "-F") {
                body_files.push(value);
            } else {
                repositories.push(value);
            }
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--body-file=") {
            body_files.push(value);
        } else if let Some(value) = token.strip_prefix("--repo=") {
            repositories.push(value);
        } else if token.starts_with("-F") && token.chars().count() > 2 {
            body_files.push(&token[2..]);
        } else if token.starts_with("-R") && token.chars().count() > 2 {
            repositories.push(&token[2..]);
        } else if token.starts_with('-') {
            return None;
        } else {
            selectors.push(token);
        }
        index += 1;
    }
    if selectors.len() != 1 || !selector_is_positive_number(selectors[0]) {
        return None;
    }
    if body_files.len() != 1 || repositories.len() > 1 {
        return None;
    }
    if repositories
        .first()
        .is_some_and(|value| !REPOSITORY.is_match(value))
    {
        return None;
    }
    let body_file = body_files[0];
    if body_file.is_empty()
        || body_file == "-"
        || body_file.starts_with('=')
        || SHELL_EXPANSION_MARKERS
            .iter()
            .any(|marker| body_file.contains(marker))
        || (body_file.contains('~') && !body_file.starts_with("~/"))
    {
        return None;
    }
    let lowered = body_file.to_lowercase();
    if !(lowered.ends_with(".md") || lowered.ends_with(".markdown")) {
        return None;
    }
    Some(body_file.to_owned())
}

/// `selector.isdigit() and int(selector) >= 1`. Text Python's `int` rejects
/// (superscript and circled digits) raises there and is refused here.
fn selector_is_positive_number(selector: &str) -> bool {
    decimal_digits_value(selector).is_some_and(|value| value >= 1)
}

/// `_resolve_operand`.
pub(crate) fn resolve_operand(operand: &str, cwd: &PyPath, home_dir: &PyPath) -> Option<PyPath> {
    if operand.is_empty() || operand != py_strip(operand) {
        return None;
    }
    let candidate = if operand == "~" {
        home_dir.clone()
    } else if let Some(rest) = operand.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        let candidate = PyPath::new(operand);
        if candidate.is_absolute() {
            candidate
        } else {
            cwd.join(operand)
        }
    };
    if pyfs::is_symlink(&candidate).ok()? {
        return None;
    }
    resolve_existing(&candidate)
}

/// `_is_pr_body_markdown_name`.
pub(crate) fn is_pr_body_markdown_name(name: &str) -> bool {
    let normalized = casefold(name);
    let (stem, suffix) = match normalized.rsplit_once('.') {
        Some((stem, suffix)) => (stem, suffix),
        None => (normalized.as_str(), ""),
    };
    if suffix != "md" && suffix != "markdown" {
        return false;
    }
    stem == "pr-body"
        || stem.ends_with("-pr-body")
        || stem == "pr_body"
        || stem.starts_with("pr_body_")
}

/// `_path_looks_sensitive`.
pub(crate) fn path_looks_sensitive(candidate: &PyPath) -> bool {
    const SENSITIVE_PARTS: [&str; 5] = [".aws", ".docker", ".gnupg", ".kube", ".ssh"];
    const SENSITIVE_PREFIXES: [&str; 6] = [
        ".env",
        "credentials",
        "id_rsa",
        "id_ed25519",
        "secrets",
        "token",
    ];
    if candidate
        .parts()
        .iter()
        .any(|part| SENSITIVE_PARTS.contains(&casefold(part).as_str()))
    {
        return true;
    }
    let name = casefold(candidate.name());
    SENSITIVE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// `_authored_location_root`: the deepest root the candidate lives under.
/// `None` is "no authored root" and the `OSError`/`RuntimeError` paths.
pub(crate) fn authored_location_root(
    candidate: &PyPath,
    cwd: &PyPath,
    home_dir: &PyPath,
    ctx: &Ctx,
) -> Option<PyPath> {
    let mut roots: Vec<PyPath> = Vec::new();
    let mut add = |root: PyPath| {
        if !roots.contains(&root) {
            roots.push(root);
        }
    };
    add(resolve_lenient(cwd, ctx)?);
    add(resolve_lenient(&gettempdir(ctx)?, ctx)?);
    add(resolve_lenient(&PyPath::new("/tmp"), ctx)?);
    add(resolve_lenient(&PyPath::new("/var/tmp"), ctx)?);
    if let Some(root) = cascade_projects_authored_root(candidate, home_dir, ctx)? {
        add(root);
    }
    if let Some(root) = omp_session_authored_root(candidate, home_dir, ctx)? {
        add(root);
    }
    roots.sort_by_key(|root| std::cmp::Reverse(root.parts().len()));
    roots
        .into_iter()
        .find(|root| candidate.relative_to(root).is_some())
}

/// `_cascade_projects_authored_root`; the outer `None` is a resolve failure.
pub(crate) fn cascade_projects_authored_root(
    candidate: &PyPath,
    home_dir: &PyPath,
    ctx: &Ctx,
) -> Option<Option<PyPath>> {
    let projects_root = resolve_lenient(&home_dir.join("CascadeProjects"), ctx)?;
    Some(candidate.relative_to(&projects_root).map(|_| projects_root))
}

/// `_omp_session_authored_root`; the outer `None` is a resolve failure.
pub(crate) fn omp_session_authored_root(
    candidate: &PyPath,
    home_dir: &PyPath,
    ctx: &Ctx,
) -> Option<Option<PyPath>> {
    let resolved_home = resolve_lenient(home_dir, ctx)?;
    let Some(relative) = candidate.relative_to(&resolved_home) else {
        return Some(None);
    };
    let matches = relative.len() == 7
        && relative[..3] == [".omp", "agent", "sessions"]
        && relative[5] == "local";
    Some(matches.then_some(resolved_home))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn edit_operand_requires_one_selector_and_one_markdown_file() {
        let ok = strings(&["12", "--body-file", "pr-body.md"]);
        assert_eq!(
            static_markdown_pr_edit_body_file_operand(&ok).as_deref(),
            Some("pr-body.md")
        );
        for bad in [
            strings(&["0", "-F", "a.md"]),
            strings(&["1", "-F", "a.txt"]),
            strings(&["1", "-F", "~a.md"]),
            strings(&["1", "-F"]),
            strings(&["1", "2", "-F", "a.md"]),
            strings(&["1", "-F", "a.md", "--web"]),
        ] {
            assert_eq!(static_markdown_pr_edit_body_file_operand(&bad), None);
        }
    }

    #[test]
    fn markdown_names_follow_the_pr_body_pattern() {
        for name in [
            "pr-body.md",
            "x-pr-body.MARKDOWN",
            "pr_body.md",
            "pr_body_x.md",
        ] {
            assert!(is_pr_body_markdown_name(name), "{name}");
        }
        for name in ["body.md", "pr-body.txt", "pr-body", "pr_bodyx.md"] {
            assert!(!is_pr_body_markdown_name(name), "{name}");
        }
    }
}
