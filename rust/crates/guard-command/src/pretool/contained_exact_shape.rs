//! The sandbox shape for the exact text about to run.
//!
//! The launcher re-derives a shape from the raw command, so several pre-tool
//! routes need the same derivation to tell whether the text they are about to
//! admit runs as the shape they judged. It sits beside the containment profile
//! it is built from rather than inside the restricted-pytest admission that
//! first needed it.

use super::generic::chain_literals::inert::temp_cd;
use super::generic::{chain_literals, workspace_redirects};
use super::{command_shape, Shape};
use crate::{parse_command, CommandModelRequestV1};
use std::path::Path;

/// How many readings deep a grouped or control-flow command is followed. A
/// loop written inside a conditional needs more than one, and the bound stops
/// a reading another reading rewrites again from running without end. It is
/// the pre-tool pass's own rewrite bound, so the sandbox follows a construct
/// exactly as far as the decision that routed the text here did.
const MAX_READING_ROUNDS: usize = super::MAX_REWRITE_ROUNDS;

/// The sandbox shape for the exact `text` about to run, or `None` when the
/// workspace sandbox cannot bound it. Literal-path redirects are classified
/// without them, chained `$NAME` uses as the literal assigned earlier in the
/// chain, and a `cd "$(mktemp -d)"` as the temporary stand-in; the raw text
/// still runs, so such a shape must run it whole, and the real `mktemp`
/// creates its directory under the sandbox's private `TMPDIR`.
pub(crate) fn exact_shape(text: &str, workspace: &Path) -> Option<Shape> {
    reading_shape(text, workspace, 0)
}

fn reading_shape(text: &str, workspace: &Path, round: usize) -> Option<Shape> {
    // A command that is nothing but a list of groups models no command of its
    // own. It is read as the list it runs below, not here.
    if !crate::parser_segments::command_has_top_level_group_list(text) {
        // A trailing subshell group runs exactly the command list inside it, so
        // the list's shape is the group's. The group text itself models no
        // command, so without this the sandbox could not plan a group the
        // decision already routed to it.
        if let Some(ungrouped) = super::ungrouped_command_list(text) {
            return reading_shape(&ungrouped, workspace, round).filter(runs_whole);
        }
        if let Some(projected) = temp_cd::project(text) {
            return reading_shape(&projected, workspace, round).filter(runs_whole);
        }
        let direct = match chain_literals::substitute(text) {
            Some(substituted) => literal_shape(&substituted, workspace).filter(runs_whole),
            None => literal_shape(text, workspace),
        };
        if direct.is_some() {
            return direct;
        }
    }
    list_reading_shape(text, workspace, round)
}

/// The shape of the command list a grouped or control-flow command runs.
///
/// A list of top-level groups is that list with the brackets blanked; a `for`
/// loop over literal words, a conditional, a `while` body and a wrapped list
/// are the list the pre-tool pass rewrites them to. Both are the readings the
/// decision that sent this text to the sandbox was itself made on, and each
/// names every command the construct can run, so `command_shape` screens the
/// contents on their own merits instead of the wrapper being waved through. A
/// construct neither reading represents still has no shape.
///
/// Neither reading tracks where a group leaves the shell standing, so a plan
/// built from one may name a directory the submitted bytes never reach. The
/// sandbox runs those bytes, so such a plan is taken only where it grants
/// nothing outside the workspace at all: it must run the text whole and name
/// no outside file to read. Everything else the sandbox already bounds.
fn list_reading_shape(text: &str, workspace: &Path, round: usize) -> Option<Shape> {
    if round >= MAX_READING_ROUNDS {
        return None;
    }
    let list = crate::parser_segments::blanked_top_level_group_list(text)
        .or_else(|| super::rewritten_command_list(text))?;
    let shape = reading_shape(&list, workspace, round + 1)?;
    (runs_whole(&shape) && shape.read_files.is_empty()).then_some(shape)
}

pub(crate) fn runs_whole(shape: &Shape) -> bool {
    shape.bootstrap.is_none() && shape.prefix.is_none() && shape.remainder.is_none()
}

fn literal_shape(text: &str, workspace: &Path) -> Option<Shape> {
    match workspace_redirects::project(text) {
        Some(projected) => workspace_redirects::contained_shape(text, &projected, workspace),
        None => {
            let model = parse_command(&CommandModelRequestV1 {
                command: text.to_owned(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .ok()?;
            command_shape(&model, workspace, Some(text))
        }
    }
}

#[cfg(test)]
#[path = "contained_exact_shape_tests.rs"]
mod tests;
