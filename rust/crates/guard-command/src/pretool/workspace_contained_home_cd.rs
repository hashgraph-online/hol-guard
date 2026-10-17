//! A leading `cd ~/<dir>` spelled the way an agent types it.
//!
//! The sink expands that `~` itself, from the same declared home the
//! directory proof expands (`_HOME_CD` in `contained_wrapper.py`), peels the
//! `cd` and runs the rest from the directory it reaches. The checks below
//! judge what the sink would run, so the home spelling is projected to that
//! absolute directory before they start and every later check sees one
//! spelling. Only an unquoted leading `~/` is projected: a quoted `~` is a
//! literal directory name, and `~+`, `~-` and `~N` name the directory stack,
//! none of which the proof admits.
use super::super::contained_wrapper::package_dir::Projected;
use super::super::{directory_targets, PathContext};
use crate::{CanonicalCommandV1, CommandModelRequestV1};

/// A word the shell passes through unchanged, so the projected text lexes
/// into the same words it was built from.
fn plain(word: &str) -> bool {
    !word.is_empty()
        && word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'.' | b'_' | b'-' | b'@' | b'+' | b'=' | b':' | b','
                )
        })
}

/// Rewrite `cd ~/<dir> <rest>` into `cd <expanded dir> <rest>`.
pub(in crate::pretool) fn as_absolute_cd(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<Projected> {
    if cfg!(windows)
        || model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return None;
    }
    let first = model.segments.first()?;
    if first.executable.as_deref() != Some("cd")
        || first.pipeline_index != 0
        || !first.environment_names.is_empty()
        || !first.wrapper_chain.is_empty()
        || first.path_overridden
        || !directory_targets::home_targets_unquoted(first)
    {
        return None;
    }
    let [spelled] = first.arguments.as_slice() else {
        return None;
    };
    if !spelled.starts_with("~/") {
        return None;
    }
    // Only plain words, so the segment's source text is exactly `cd <target>`.
    let chars: Vec<char> = model.normalized_text.chars().collect();
    let source: String = chars
        .get(first.span.start..first.span.end)?
        .iter()
        .collect();
    if !chars
        .get(..first.span.start)?
        .iter()
        .all(|character| character.is_whitespace())
        || source.split_whitespace().collect::<Vec<_>>() != ["cd", spelled.as_str()]
    {
        return None;
    }
    // The same proof the `cd` itself faces: the declared home, a target with
    // no alias or glob, and a directory that resolves to that exact spelling.
    let directory = directory_targets::verified_cwd_target(spelled, context)?;
    if !plain(&directory) {
        return None;
    }
    let remainder: String = chars.get(first.span.end..)?.iter().collect();
    let text = format!("cd {directory}{remainder}");
    let projected = crate::parse_command(&CommandModelRequestV1 {
        command: text.clone(),
        dialect: model.dialect.clone(),
        transport: model.transport.clone(),
        extraction_provenance: model.extraction_provenance.clone(),
    })
    .ok()
    .filter(|projected| projected.confidence == "exact")?;
    Some(Projected {
        model: projected,
        text,
    })
}

#[cfg(test)]
#[path = "workspace_contained_home_cd_tests.rs"]
mod tests;
