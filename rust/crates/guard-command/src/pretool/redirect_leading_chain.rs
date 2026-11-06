//! A read whose output is saved first and then inspected in the same chain:
//! `gh api repos/example/app/pulls/12/comments > .tmp/c.json 2>&1; wc -l .tmp/c.json`.
//!
//! The projection refuses most chains that write a file, because an earlier
//! step could change directory or swap the target for a symlink before the
//! shell opens it, and because a later step was proven before the write
//! landed. This form admits a chain only when neither can matter:
//!
//! * every file is written by the first step, before any separator, group or
//!   command substitution, so nothing else has run when the shell opens it;
//!   the projection's target check proves each target on its own;
//! * every later step only prints, counts or filters, so reading the new file
//!   cannot run it, and none changes directory, renames a file or creates a
//!   link;
//! * the command without its redirects must still earn a plain allow, which
//!   proves the first step a read on its own.

use crate::CanonicalCommandV1;

/// Steps that print, count or filter. None executes a file it reads, changes
/// directory, renames a file or creates a link.
const READERS: &[&str] = &[
    "cat", "cut", "diff", "echo", "grep", "head", "jq", "ls", "nl", "printf", "rg", "sort", "tail",
    "tr", "true", "uniq", "wc",
];

/// Whether every step after the first is a plain reader spelled by name, with
/// no wrapper, environment assignment or path override. The caller has
/// already proven that only the first step writes a file.
pub(super) fn admits(model: &CanonicalCommandV1) -> bool {
    model.wrapper_chain.is_empty()
        && !model.path_overridden
        && model.segments.len() > 1
        && model.segments[1..].iter().all(|segment| {
            segment.wrapper_chain.is_empty()
                && segment.environment_names.is_empty()
                && !segment.path_overridden
                && segment
                    .executable
                    .as_deref()
                    .is_some_and(|executable| READERS.contains(&executable))
        })
}
