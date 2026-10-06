//! Gitignore rules for native search-scope proofs.
//!
//! The proof only needs to know whether a host search could reach a
//! sensitive file. Rules that fail to parse therefore never hide a file,
//! and a re-include rule that fails to parse invalidates the proof.

use super::search_scope_glob::glob_matches;
use std::io::Read;
use std::path::Path;

const MAX_IGNORE_FILE_BYTES: u64 = 64 * 1024;
pub(super) const MAX_IGNORE_RULES: usize = 4_096;

#[derive(Debug, Clone)]
pub(super) struct IgnoreRule {
    /// Directory containing the rule source, relative to the repository root.
    base: String,
    pattern: String,
    negated: bool,
    directory_only: bool,
    anchored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScopeUnproven;

/// Parse one ignore file. A missing file has no rules; a link, oversized
/// file, or unreadable file has no trustworthy rules for this proof.
pub(super) fn load_ignore_file(
    path: &Path,
    base: &str,
    rules: &mut Vec<IgnoreRule>,
) -> Result<(), ScopeUnproven> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ScopeUnproven),
    };
    if !metadata.is_file() {
        // Git does not follow a symlinked ignore file. Ignoring it hides no
        // file from this proof, so treating it as absent stays conservative.
        return Ok(());
    }
    if metadata.len() > MAX_IGNORE_FILE_BYTES {
        return Err(ScopeUnproven);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_IGNORE_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| ScopeUnproven)?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        if let Some(rule) = parse_rule(line, base)? {
            rules.push(rule);
            if rules.len() > MAX_IGNORE_RULES {
                return Err(ScopeUnproven);
            }
        }
    }
    Ok(())
}

fn parse_rule(line: &str, base: &str) -> Result<Option<IgnoreRule>, ScopeUnproven> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let line = trim_unescaped_trailing_spaces(line);
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (negated, body) = match line.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (
            false,
            line.strip_prefix('\\')
                .filter(|rest| rest.starts_with(['#', '!']))
                .unwrap_or(line),
        ),
    };
    let (directory_only, body) = match body.strip_suffix('/') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    let anchored = body.contains('/');
    let pattern = body.strip_prefix('/').unwrap_or(body);
    if pattern.is_empty() {
        return if negated {
            Err(ScopeUnproven)
        } else {
            Ok(None)
        };
    }
    Ok(Some(IgnoreRule {
        base: base.to_owned(),
        pattern: pattern.to_owned(),
        negated,
        directory_only,
        anchored,
    }))
}

fn trim_unescaped_trailing_spaces(line: &str) -> &str {
    let mut end = line.len();
    while end > 0 && line.as_bytes()[end - 1] == b' ' {
        if end >= 2 && line.as_bytes()[end - 2] == b'\\' {
            break;
        }
        end -= 1;
    }
    &line[..end]
}

/// Apply git's last-match-wins rule. `relative` is relative to the
/// repository root and uses `/` separators.
pub(super) fn is_ignored(
    rules: &[IgnoreRule],
    relative: &str,
    is_directory: bool,
) -> Result<bool, ScopeUnproven> {
    let mut ignored = false;
    for rule in rules {
        if rule.directory_only && !is_directory {
            continue;
        }
        let Some(local) = path_below_base(relative, &rule.base) else {
            continue;
        };
        let target = if rule.anchored {
            local
        } else {
            local.rsplit('/').next().unwrap_or(local)
        };
        match glob_matches(&rule.pattern, target) {
            Ok(true) => ignored = !rule.negated,
            Ok(false) => {}
            // A re-include rule could expose a file this proof would skip.
            Err(_) if rule.negated => return Err(ScopeUnproven),
            Err(_) => {}
        }
    }
    Ok(ignored)
}

fn path_below_base<'a>(relative: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() {
        return Some(relative);
    }
    relative
        .strip_prefix(base)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|rest| !rest.is_empty())
}
