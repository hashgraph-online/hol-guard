use super::{
    classify_source_path, hidden_parts_allowed, lowered_parts, resolve_candidate,
    sensitive_external_filename, sensitive_path_family, SourcePathDecision,
    EXTERNAL_SENSITIVE_PARTS,
};
use std::fs;
use std::path::Path;

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
            || sensitive_external_filename(path)
            || parts
                .iter()
                .any(|part| EXTERNAL_SENSITIVE_PARTS.contains(&part.as_str()))
        {
            return SourcePathDecision::deny("sensitive_basename");
        }
        if !hidden_parts_allowed(&parts) {
            return SourcePathDecision::deny("unsafe_hidden_dir");
        }
    }
    if !candidate.is_file() {
        return SourcePathDecision::deny("not_regular_file");
    }
    SourcePathDecision::allow("scannable_explicit_source_path", candidate)
}
