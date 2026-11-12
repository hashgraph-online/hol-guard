//! `sed -i` and `perl -i` rewrite files in place, so Guard never proves them
//! (see `sed_workflow_boundaries`). The generic reason told agents only that
//! the command was not read-only; a headless agent then asked a person to
//! approve a one-line rename instead of retrying. Naming the in-place editor
//! and the file edit tool gives the agent a path that Guard can check.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// A review reason for a command with a `sed -i` or `perl -i` step, or `None`.
pub(super) fn inplace_edit_reason(model: &CanonicalCommandV1) -> Option<String> {
    let editor = model.segments.iter().find_map(inplace_editor)?;
    let rest = if model.segments.len() > 1 {
        ", then run the other steps as separate commands"
    } else {
        ""
    };
    Some(format!(
        "HOL Guard requires review because `{editor} -i` rewrites files in place and Guard cannot check what it changes. Make the change with your file edit tool instead (such as Edit, Write or apply_patch), which Guard checks file by file{rest}."
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Editor {
    Sed,
    Perl,
}

enum Cluster {
    InPlace,
    ValueNext,
    Done,
}

fn inplace_editor(segment: &CommandSegmentV1) -> Option<&'static str> {
    let executable = segment.executable.as_deref()?;
    let (editor, name) = match executable.rsplit(['/', '\\']).next()? {
        "sed" | "gsed" => (Editor::Sed, "sed"),
        "perl" => (Editor::Perl, "perl"),
        _ => return None,
    };
    let mut value_next = false;
    for argument in &segment.arguments {
        if std::mem::take(&mut value_next) {
            continue;
        }
        if argument == "--" {
            break;
        }
        let Some(flags) = argument.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
            // An operand. Perl stops reading its own switches at the first one
            // (the script, or an argument after `-e`), so a later `-i` belongs
            // to the script. GNU sed reads options anywhere on the line.
            if editor == Editor::Perl {
                break;
            }
            continue;
        };
        if let Some(long) = flags.strip_prefix('-') {
            if editor == Editor::Sed {
                if long == "in-place" || long.starts_with("in-place=") {
                    return Some(name);
                }
                value_next = matches!(long, "expression" | "file" | "line-length");
            }
            continue;
        }
        match scan_cluster(editor, flags) {
            Cluster::InPlace => return Some(name),
            Cluster::ValueNext => value_next = true,
            Cluster::Done => {}
        }
    }
    None
}

/// Reads one short-flag cluster such as `-pi`, `-Ei.orig` or `-0pi`. A flag
/// that takes a value ends the cluster: the rest, or the next argument when
/// nothing is left, is that value. Perl's `-0` and `-l` take only optional
/// digits, so the switches after those digits still count.
fn scan_cluster(editor: Editor, flags: &str) -> Cluster {
    let mut chars = flags.char_indices().peekable();
    while let Some((index, flag)) = chars.next() {
        let last = index + flag.len_utf8() == flags.len();
        match (editor, flag) {
            (_, 'i') => return Cluster::InPlace,
            (Editor::Sed, 'e' | 'f' | 'l') | (Editor::Perl, 'e' | 'E' | 'I' | 'M' | 'm') => {
                return if last {
                    Cluster::ValueNext
                } else {
                    Cluster::Done
                };
            }
            (Editor::Perl, 'x' | 'C' | 'd' | 'D') => return Cluster::Done,
            (Editor::Perl, '0') if chars.next_if(|(_, c)| *c == 'x').is_some() => {
                while chars.next_if(|(_, c)| c.is_ascii_hexdigit()).is_some() {}
            }
            (Editor::Perl, '0' | 'l') => {
                while chars.next_if(|(_, c)| ('0'..='7').contains(c)).is_some() {}
            }
            _ => {}
        }
    }
    Cluster::Done
}

#[cfg(test)]
#[path = "inplace_edit_reason_tests.rs"]
mod tests;
