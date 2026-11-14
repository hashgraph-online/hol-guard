//! A program written by its full path that is the very file the bare name
//! finds on the session's `PATH`.
//!
//! The exact-safe proof judges a bare name such as `python3` by its basename,
//! because the shell looks it up on `PATH` and runs whatever the session's own
//! environment puts first. A path spelling such as `/opt/homebrew/bin/python3`
//! names a file instead, so the proof refuses it unless the file sits in a
//! launcher directory nobody but root can write. Homebrew's `bin` belongs to
//! the user, so an agent that wrote the full path got a review for a command
//! that is silent when written bare, even though both run the same file.
//!
//! When the path names the same directory entry that the bare name resolves to
//! on the `PATH` the hook was stamped with, writing it out trusts nothing the
//! bare name does not. Such a segment is judged under its bare name. Anything
//! else keeps the path spelling and the stricter check: a path that is not the
//! first match, a relative `PATH` entry ahead of the match (it would resolve
//! against a directory the agent picks), a missing stamp, or Windows, where
//! `PATHEXT` and the current directory join the lookup.

use crate::CanonicalCommandV1;
use std::path::{Component, Path};

/// `model` reparsed with each path-spelled executable that is exactly the
/// bare name's `PATH` match written as that bare name. `None` when no segment
/// changed, or when the reparsed command differs in anything but those names.
pub(super) fn bare_name_model(
    model: &CanonicalCommandV1,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<CanonicalCommandV1> {
    let environment = environment.filter(|environment| environment.has_valid_shape())?;
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    // Spans count characters of the normalized text.
    let characters: Vec<char> = model.normalized_text.chars().collect();
    let mut edits = Vec::new();
    let mut expected = Vec::with_capacity(model.segments.len());
    for segment in &model.segments {
        let executable = segment.executable.as_deref();
        let Some(name) = executable.and_then(|path| first_path_match(path, &environment.path))
        else {
            expected.push(segment.executable.clone());
            continue;
        };
        let executable = executable?;
        let span = &segment.span;
        if span.source != "normalized" || span.start > span.end || span.end > characters.len() {
            return None;
        }
        let text: String = characters[span.start..span.end].iter().collect();
        let at = text.find(executable)?;
        let start = span.start + text[..at].chars().count();
        edits.push((start, start + executable.chars().count(), name.clone()));
        expected.push(Some(name));
    }
    if edits.is_empty() {
        return None;
    }
    let mut rewritten = String::with_capacity(model.normalized_text.len());
    let mut next = 0;
    for (start, end, name) in edits {
        if start < next {
            return None;
        }
        rewritten.extend(&characters[next..start]);
        rewritten.push_str(&name);
        next = end;
    }
    rewritten.extend(&characters[next..]);
    let parsed = crate::parse_command(&crate::CommandModelRequestV1 {
        command: rewritten,
        dialect: model.dialect.clone(),
        transport: model.transport.clone(),
        extraction_provenance: model.extraction_provenance.clone(),
    })
    .ok()?;
    let same_shape = parsed.confidence == model.confidence
        && parsed.path_overridden == model.path_overridden
        && parsed.wrapper_chain == model.wrapper_chain
        && parsed.segments.len() == model.segments.len()
        && parsed
            .segments
            .iter()
            .zip(&model.segments)
            .zip(&expected)
            .all(|((parsed, original), executable)| {
                parsed.executable == *executable
                    && parsed.arguments == original.arguments
                    && parsed.environment_names == original.environment_names
                    && parsed.wrapper_chain == original.wrapper_chain
                    && parsed.path_overridden == original.path_overridden
                    && parsed.pipeline_index == original.pipeline_index
                    && parsed.execution_context == original.execution_context
            });
    same_shape.then_some(parsed)
}

/// The basename of `executable` when it is an absolute path to the entry a
/// `PATH` lookup of that basename finds first.
#[cfg(unix)]
fn first_path_match(executable: &str, search_path: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new(executable);
    if !executable.starts_with('/')
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let directory = std::fs::canonicalize(path.parent()?).ok()?;
    for entry in std::env::split_paths(search_path) {
        // An empty or relative entry resolves against the working directory.
        if !entry.is_absolute() {
            return None;
        }
        let candidate = entry.join(name);
        // The shell skips an entry that holds no executable file of the name.
        let executable_file = std::fs::metadata(&candidate)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
        if executable_file {
            return (std::fs::canonicalize(&entry).ok()? == directory).then(|| name.to_owned());
        }
    }
    None
}

#[cfg(not(unix))]
fn first_path_match(_executable: &str, _search_path: &str) -> Option<String> {
    None
}

#[cfg(test)]
#[path = "path_lookup_program_tests.rs"]
mod tests;
