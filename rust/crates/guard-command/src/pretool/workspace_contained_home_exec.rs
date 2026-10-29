//! A launcher spelled `~/<dir>/<program>`, the way an agent types it.
//!
//! The sink runs the contained text through `/bin/sh`, which expands that
//! `~` from the same declared home the path proofs expand, so `~/bin/run`
//! and the absolute path it names are one command written two ways. The
//! absolute spelling already takes the contained route, and the session
//! PATH grants its directory as an executable root either way, so the home
//! spelling is projected to that path before the checks below start and
//! every later check sees one spelling.
//!
//! Only the program word is projected, and only when the shell expands it:
//! a quoted or escaped `~` is a literal relative path that names a
//! different file, and `~+`, `~-` and `~N` name the directory stack, none
//! of which the proof admits.
use super::super::contained_wrapper::package_dir::Projected;
use super::super::{directory_targets, read_paths, PathContext};
use super::home_cd::plain;
use crate::{CanonicalCommandV1, CommandModelRequestV1, CommandSegmentV1};

/// Rewrite every `~/<dir>/<program>` launcher into the path it expands to.
pub(in crate::pretool) fn as_absolute_program(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<Projected> {
    if cfg!(windows)
        || model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        // An unquoted leading `~` expands from the shell's HOME, so it names
        // the declared home only when that HOME is the declared one.
        || !context.shell_home_matches
    {
        return None;
    }
    let chars: Vec<char> = model.normalized_text.chars().collect();
    // The segments are in the order the text spells them, so the rewrites
    // below are too, and the text is rebuilt in one pass across them.
    let mut rewrites: Vec<(usize, usize, String)> = Vec::new();
    for segment in &model.segments {
        let Some((spelled, program)) = expanded_program(segment, &chars, context) else {
            continue;
        };
        let start = segment.span.start;
        rewrites.push((start, start + spelled.chars().count(), program));
    }
    if rewrites.is_empty() {
        return None;
    }
    let mut text = String::new();
    let mut cursor = 0usize;
    for (start, end, program) in &rewrites {
        text.extend(chars.get(cursor..*start)?.iter());
        text.push_str(program);
        cursor = *end;
    }
    text.extend(chars.get(cursor..)?.iter());
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

/// The home spelling this segment launches and the path the shell expands it to.
fn expanded_program(
    segment: &CommandSegmentV1,
    chars: &[char],
    context: PathContext<'_>,
) -> Option<(String, String)> {
    let spelled = segment.executable.as_deref()?;
    if segment.pipeline_index != 0
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || !spelled.starts_with("~/")
        || !directory_targets::safe_directory_target(spelled)
    {
        return None;
    }
    // The segment's own source must begin with that exact word, so a quoted
    // or escaped spelling the shell keeps literal is refused here.
    let source: String = chars
        .get(segment.span.start..segment.span.end)?
        .iter()
        .collect();
    if source.split_whitespace().next() != Some(spelled) {
        return None;
    }
    let program = read_paths::expand_home_read_path(spelled, context.home_dir)?;
    // A word the shell would re-split or expand could not be substituted at
    // all, `..` would name a directory the spelling does not show, and a
    // program that is not there is not the launcher the agent named.
    if !plain(&program)
        || std::path::Path::new(&program)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || std::fs::symlink_metadata(&program).is_err()
    {
        return None;
    }
    Some((spelled.to_string(), program))
}

#[cfg(all(test, unix))]
#[path = "workspace_contained_home_exec_tests.rs"]
mod tests;
