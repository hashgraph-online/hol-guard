//! Globs with wildcard directories outside the harness homes.
//!
//! `head -5 crates/*/Cargo.toml` reads one manifest per crate, and a Next.js
//! app keeps a dynamic route in a directory of its own, so a session reads
//! `app/api/claims/*/start/route.ts` to see all of them. The shell expands
//! each component before the reader starts, so this proof walks the same
//! components over the real tree and admits the word only when every name it
//! can produce clears the literal read proof, exactly as the last-component
//! model in the parent does.
//!
//! The literal directory before the first wildcard is the root of the walk.
//! It must be a bounded directory read, and none of its components may be
//! hidden, so the harness homes keep their own Markdown-only proof and every
//! other dot directory keeps its review. Wildcard components follow the
//! parent's model: only `*` and `?`, ASCII case ignored, and a hidden or
//! non-ASCII entry a pattern would match sends the read to review. A matched
//! directory name is checked like a matched file name: whitespace or a glob
//! character in it would split or re-expand the word when it passes through
//! an unquoted `$f`, so it keeps the review too. The one exception is a
//! bracketed route directory such as `[id]` matched by a bare `*`, see
//! `bracket_directory`.

use std::path::PathBuf;

/// The words the shell passes on for `value`, a glob with at least one
/// wildcard directory, when every one of them is a bounded, non-sensitive
/// regular file; `None` otherwise, including when nothing matches.
pub(super) fn directory_glob_matches(
    value: &str,
    context: super::super::super::PathContext<'_>,
) -> Option<Vec<String>> {
    let components: Vec<&str> = value.split('/').collect();
    let first_wildcard = components
        .iter()
        .position(|component| component.contains(['*', '?']))?;
    if first_wildcard + 1 >= components.len()
        || !components[first_wildcard..]
            .iter()
            .all(|component| super::plain_component(component))
        || !components[..first_wildcard]
            .iter()
            .enumerate()
            .all(|(index, component)| root_component(index, component))
        || !super::super::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let bare = first_wildcard == 0;
    let root = match components[..first_wildcard].join("/") {
        // `/*/x` walks the filesystem root.
        root if root.is_empty() && !bare => "/".to_owned(),
        root if root.is_empty() => ".".to_owned(),
        root => root,
    };
    if !super::super::bounded_read_target(&root, context.home_dir, context.cwd, true) {
        return None;
    }
    let prefix = |word: &str, name: &str| match (bare, word) {
        (true, "") => name.to_owned(),
        (false, "/") => format!("/{name}"),
        _ => format!("{word}/{name}"),
    };
    let start = if bare { String::new() } else { root.clone() };
    let mut level: Vec<(String, PathBuf)> = vec![(start, super::directory_path(&root, context)?)];
    let mut inspected = 0;
    let rest = &components[first_wildcard..];
    for (index, component) in rest.iter().enumerate() {
        let last = index + 1 == rest.len();
        let mut next = Vec::new();
        for (word, path) in &level {
            if !last && !component.contains(['*', '?']) {
                let candidate = path.join(component);
                if candidate.is_dir() {
                    next.push((prefix(word, component), candidate));
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
                if name.starts_with('.')
                    || name.contains(char::is_whitespace)
                    || name.contains(['*', '?', '\\'])
                    || (name.contains(['[', ']']) && !bracket_directory(component, last))
                    || next.len() >= super::MAX_MATCHES
                {
                    return None;
                }
                next.push((prefix(word, name), path.join(name)));
            }
        }
        level = next;
    }
    if level.is_empty() {
        return None;
    }
    level
        .into_iter()
        .map(|(word, path)| {
            let (Some((_, name)), Some(base)) = (word.rsplit_once('/'), path.parent()) else {
                return None;
            };
            // A bare word starts with the first matched directory, so a
            // directory named `-n` or `FS=x` would reach the reader as an
            // option or an `awk` assignment. One named `~` is opened in the
            // working directory, since the shell never tilde-expands a match,
            // but the read proof would resolve it under the home directory.
            (!(bare && (word.starts_with(['-', '~']) || word.contains('=')))
                && super::readable_name(name, base)
                && literal_read(&word, context))
            .then_some(word)
        })
        .collect()
}

/// A Next.js route keeps a dynamic segment in a directory such as `[id]`.
/// The shell passes an expanded word on without expanding it again, so a
/// reader opens that directory by name. An unquoted `$f` would expand the
/// name once more, but only to entries of the same directory, and a bare `*`
/// component has already walked every one of them under the same rules. A
/// narrower pattern has not, so there the name keeps its review.
fn bracket_directory(component: &str, last: bool) -> bool {
    component == "*" && !last
}

/// The literal read proof for the expanded word; a word holding a bracketed
/// directory is read by that literal spelling.
fn literal_read(word: &str, context: super::super::super::PathContext<'_>) -> bool {
    if word.contains(['[', ']']) {
        crate::pretool::read_paths::bounded_literal_bracket_target(
            word,
            context.home_dir,
            context.cwd,
            false,
        )
    } else {
        super::super::bounded_read_target(word, context.home_dir, context.cwd, false)
    }
}

/// A literal component of the walk's root: the leading empty component of an
/// absolute path, a leading `~`, or a visible name.
fn root_component(index: usize, component: &str) -> bool {
    (index == 0 && (component.is_empty() || component == "~"))
        || (!component.contains(['*', '?']) && super::plain_component(component))
}
