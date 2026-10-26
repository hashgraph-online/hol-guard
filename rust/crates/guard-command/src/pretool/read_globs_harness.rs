//! Globs with wildcard directories inside the Codex and Claude Code homes.
//!
//! Claude Code keeps one memory index per project, so a session that wants
//! every one of them reads `~/.claude/projects/*/memory/MEMORY.md`. The shell
//! expands each component before the reader starts, so this proof walks the
//! same components over the real tree and admits the word only when every
//! name it can produce is a harness note the literal read already admits.
//!
//! Wildcard components follow the last-component model of the parent: only
//! `*` and `?`, ASCII case ignored, and a hidden or non-ASCII entry that a
//! pattern would match sends the read to review. The last component is read
//! the same way, even when literal, and must name Markdown. Literal
//! directory components are resolved as the shell resolves them, by name.
//! Every match must clear the literal read proof and resolve to a visible,
//! non-transcript Markdown file below a harness home.

use std::path::Path;

// A wildcard match is held to exactly the literal read proof's rule.
use crate::pretool::read_paths::harness_notes as notes;

/// The words the shell passes on for `value`, a `~/.claude` or `~/.codex`
/// glob with at least one wildcard directory, when every one of them is a
/// harness note; `None` otherwise, including when nothing matches.
pub(super) fn harness_directory_glob_matches(
    value: &str,
    context: super::super::super::PathContext<'_>,
) -> Option<Vec<String>> {
    let (root, rest) = harness_root(value, context.home_dir)?;
    let components: Vec<&str> = rest.split('/').collect();
    let (last, directories) = components.split_last()?;
    if !last.ends_with(".md")
        || !directories
            .iter()
            .any(|component| component.contains(['*', '?']))
        || !components
            .iter()
            .all(|component| super::plain_component(component))
        || !super::super::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let mut level = vec![(root.to_owned(), super::directory_path(root, context)?)];
    let mut inspected = 0;
    for (index, component) in components.iter().enumerate() {
        let mut next = Vec::new();
        for (word, path) in &level {
            if index + 1 < components.len() && !component.contains(['*', '?']) {
                let candidate = path.join(component);
                if candidate.is_dir() {
                    next.push((format!("{word}/{component}"), candidate));
                }
                continue;
            }
            let entries = match std::fs::read_dir(path) {
                Ok(entries) => entries,
                // A file or dangling link has nothing below it for the shell
                // to expand either; an unreadable directory stays unproven.
                Err(_) if !path.is_dir() => continue,
                Err(_) => return None,
            };
            for entry in entries {
                inspected += 1;
                if inspected > super::MAX_ENTRIES {
                    return None;
                }
                let name = entry.ok()?.file_name();
                let name = name.to_str()?;
                if !name.is_ascii() {
                    return None;
                }
                if !super::wildcard_matches(component.as_bytes(), name.as_bytes()) {
                    continue;
                }
                if name.starts_with('.') || next.len() >= super::MAX_MATCHES {
                    return None;
                }
                next.push((format!("{word}/{name}"), path.join(name)));
            }
        }
        level = next;
    }
    if level.is_empty() {
        return None;
    }
    level
        .into_iter()
        .map(|(word, path)| harness_note(&word, &path, context).then_some(word))
        .collect()
}

/// `~/.claude` or `~/.codex`, spelled from `~` or from the home directory,
/// and the rest of `value` below it.
fn harness_root<'a>(value: &'a str, home_dir: Option<&str>) -> Option<(&'a str, &'a str)> {
    let home = home_dir?;
    let resolved_home = std::fs::canonicalize(home).ok()?;
    notes::HARNESS_HOMES.iter().find_map(|name| {
        let at = value.find(&format!("/{name}/"))?;
        let prefix = &value[..at];
        (prefix == "~"
            || Path::new(prefix) == Path::new(home)
            || Path::new(prefix) == resolved_home.as_path())
        .then_some((&value[..at + 1 + name.len()], &value[at + 2 + name.len()..]))
    })
}

/// A match is admitted exactly as the literal word, and only as a note.
fn harness_note(word: &str, path: &Path, context: super::super::super::PathContext<'_>) -> bool {
    let (Some((_, name)), Some(base)) = (word.rsplit_once('/'), path.parent()) else {
        return false;
    };
    super::readable_match(word, name, base, context)
        && std::fs::canonicalize(path)
            .is_ok_and(|canonical| notes::harness_home_document(&canonical, context.home_dir))
}
