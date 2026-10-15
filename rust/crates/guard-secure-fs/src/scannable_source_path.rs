use super::{
    classify_source_path, hidden_empty_work_tree_file, hidden_parts_allowed,
    is_source_code_extension, lowered_parts, resolve_candidate, sensitive_external_filename,
    sensitive_path_family, SourcePathDecision, EXTERNAL_SENSITIVE_PARTS,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Admit an explicit file to independent bounded content review, not execution.
/// Pi-family reads may name ordinary files outside a checkout or through a
/// link. Location and suffix do not establish a content risk. The caller must
/// still descriptor-read the canonical leaf and scan both source and output.
pub fn classify_scannable_source_path(
    target: &str,
    cwd: &Path,
    home: Option<&Path>,
    allow_external: bool,
) -> SourcePathDecision {
    let strict = classify_source_path(target, cwd, home, allow_external);
    // Both reasons are reached only after the scope checks passed. An empty
    // marker such as `.keep` in a work tree holds nothing to leak, and
    // PreToolUse already admits reading it under the same bound.
    if matches!(strict.reason_code, "unsafe_hidden_dir" | "not_source_like") {
        if let Some(candidate) = empty_work_tree_marker(target, cwd, home) {
            return SourcePathDecision::allow("empty_hidden_marker", candidate);
        }
    }
    if strict.allowed || !allow_external {
        return strict;
    }
    let stripped = target.trim().trim_matches(['\'', '"']);
    if stripped.is_empty()
        || stripped
            .chars()
            .any(|character| matches!(character, '*' | '?' | '{' | '}' | '\0'))
    {
        return SourcePathDecision::deny("invalid_explicit_source_path");
    }
    let Ok(lexical) = resolve_candidate(stripped, Some(cwd), home.unwrap_or_else(|| Path::new("")))
    else {
        return SourcePathDecision::deny("unresolved_path");
    };
    let Ok(candidate) = fs::canonicalize(&lexical) else {
        return SourcePathDecision::deny("external_target_not_readable");
    };
    for path in [&lexical, &candidate] {
        let parts = lowered_parts(path);
        if sensitive_path_family(path).is_some()
            || credential_named_file(path)
            || parts
                .iter()
                .any(|part| EXTERNAL_SENSITIVE_PARTS.contains(&part.as_str()))
        {
            return SourcePathDecision::deny("sensitive_basename");
        }
        if !hidden_parts_allowed(&parts) && !hidden_empty_work_tree_file(&candidate) {
            return SourcePathDecision::deny("unsafe_hidden_dir");
        }
    }
    if !candidate.is_file() {
        return SourcePathDecision::deny("not_regular_file");
    }
    SourcePathDecision::allow("scannable_explicit_source_path", candidate)
}

/// A file named for credentials, such as `auth.json` or `api-token.txt`.
/// Source code named for them, such as `auth-session.ts`, implements a
/// credential feature rather than storing one, and its content is scanned
/// like any other file; credential directories still apply to it.
fn credential_named_file(path: &Path) -> bool {
    let source_code = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(is_source_code_extension);
    !source_code && sensitive_external_filename(path)
}

fn empty_work_tree_marker(target: &str, cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let stripped = target.trim().trim_matches(['\'', '"']);
    let lexical =
        resolve_candidate(stripped, Some(cwd), home.unwrap_or_else(|| Path::new(""))).ok()?;
    let candidate = fs::canonicalize(&lexical).ok()?;
    (hidden_empty_work_tree_file(&lexical) && hidden_empty_work_tree_file(&candidate))
        .then_some(candidate)
}
