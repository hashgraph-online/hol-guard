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

/// The sandbox shape for the exact `text` about to run, or `None` when the
/// workspace sandbox cannot bound it. Literal-path redirects are classified
/// without them, chained `$NAME` uses as the literal assigned earlier in the
/// chain, and a `cd "$(mktemp -d)"` as the temporary stand-in; the raw text
/// still runs, so such a shape must run it whole, and the real `mktemp`
/// creates its directory under the sandbox's private `TMPDIR`.
pub(crate) fn exact_shape(text: &str, workspace: &Path) -> Option<Shape> {
    // A trailing subshell group runs exactly the command list inside it, so
    // the list's shape is the group's. The group text itself models no
    // command, so without this the sandbox could not plan a group the
    // decision already routed to it.
    if let Some(ungrouped) = super::ungrouped_command_list(text) {
        return exact_shape(&ungrouped, workspace).filter(runs_whole);
    }
    if let Some(projected) = temp_cd::project(text) {
        return exact_shape(&projected, workspace).filter(runs_whole);
    }
    match chain_literals::substitute(text) {
        Some(substituted) => literal_shape(&substituted, workspace).filter(runs_whole),
        None => literal_shape(text, workspace),
    }
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
