//! In-place `sed` substitutions on ordinary workspace files.
//!
//! `sed -i '' 's|old|new|' src/app/page.tsx` is the same bounded file edit an
//! agent's own edit tool makes. Each target gets the edit tool's workspace
//! write screen and stricter checks on top:
//! - an existing regular file inside the current workspace (no linked
//!   worktree, home or temporary directory), not a symlink, not executable;
//! - no hidden component in the spelled or resolved path, which keeps `.git`,
//!   `.github/workflows`, hook directories and dotfiles reviewed;
//! - no agent instruction file such as `AGENTS.md` or `CLAUDE.md`;
//! - no `cd`, link, move, copy, removal, unpack or Git step in the same
//!   command, so the checked path is the path `sed` opens.
//!
//! Every script must be exactly one `s` command with no flag other than `g`,
//! so `e`, `w`, `r`, `R`, `W`, the `e`/`w` substitution flags and any second
//! command stay reviewed.
//!
//! GNU `-i` takes an optional attached suffix and BSD `-i` takes the next
//! word, so the accepted spellings are chosen to mean the same edit to both:
//! - `sed -i '' [-E] SCRIPT FILE...` and `sed -i '' [-E] -e SCRIPT ... FILE...`.
//!   GNU sed reads the empty word as an empty script or a missing file and
//!   changes nothing extra.
//! - `sed -iSUFFIX [-E] SCRIPT FILE...` and the `-e` form, where both keep a
//!   backup named `FILESUFFIX`. The suffix is plain (`.bak`, `~`), and the
//!   backup must be a new or ordinary workspace file under the same rules.
//! - `sed -i [-E] -e SCRIPT FILE...` with one script. BSD sed keeps a backup
//!   named `FILE-e` (or `FILE-E`) next to the edited file.
//! - `sed -i [-E] SCRIPT FILE...` only on Linux. BSD sed would read the first
//!   file name as its script.
//!
//! A chain of plain peers may also edit a scratch copy it stages in a private
//! temporary directory: `cp /tmp/a.ts /tmp/b.ts && sed -i '' 's|x|y|' /tmp/b.ts`.
//! The target is a temporary file the chain proof accepts (absent, or a
//! regular single-link file the user owns), it is not executable, and no
//! backup is kept. No peer links, renames or changes directory, so the path
//! checked is the path `sed` opens. A scratch edit may also add a line with an
//! `a\` or `i\` text command, which only writes the text.

use std::path::{Component, Path};

#[path = "sed_append_scripts.rs"]
mod append_scripts;

const MAX_TARGETS: usize = 16;
const MAX_SCRIPT: usize = 1024;
/// Delimiters that carry no meaning of their own in either regex dialect.
const DELIMITERS: &str = "/|#,:@!%+~_=";
/// Commands that change the directory or what an existing path names.
const PATH_CHANGERS: [&str; 12] = [
    "cd", "pushd", "popd", "ln", "mv", "cp", "rm", "install", "rsync", "tar", "unzip", "git",
];

pub(super) fn safe_in_place_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && shell_text_literal(&segment.text)
        && (workspace_edit_safe(model, segment, context)
            || scratch_edit_safe(model, segment, context))
}

/// An inert substitution in existing ordinary files of the workspace.
fn workspace_edit_safe(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    !model.segments.iter().any(changes_path_meaning)
        && in_place_edit(&segment.arguments).is_some_and(|edit| edits_safe(&edit, context))
}

/// An inert edit of scratch files in a chain of plain peers. Every target is
/// a temporary file the chain proof accepts, so it is absent or a regular
/// single-link file the user owns, and a file that exists is not executable.
/// Nothing in the chain links, renames or changes directory, so the files
/// checked are the files `sed` opens. No backup is kept next to the target.
fn scratch_edit_safe(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    super::chain_temporary::peers_only(model)
        && in_place_edit_with(&segment.arguments, true).is_some_and(|edit| {
            edit.backup_suffix.is_none()
                && script_operand_is_no_file(edit.script_operand, context.cwd)
                && edit.targets.iter().all(|target| {
                    super::chain_temporary::temporary_file_target(
                        target,
                        context.home_dir,
                        context.cwd,
                    ) && !std::fs::symlink_metadata(target)
                        .is_ok_and(|metadata| executable(&metadata))
                })
        })
}

/// GNU sed opens the script of `-i '' SCRIPT FILE` as a file, and no target
/// check covers it. BSD sed (the macOS default) reads it as the script, and on
/// any host a script that names no file leaves nothing to rewrite.
fn script_operand_is_no_file(script: Option<&str>, cwd: Option<&str>) -> bool {
    let Some(script) = script else {
        return true;
    };
    if cfg!(target_os = "macos") {
        return true;
    }
    let Some(cwd) = cwd.filter(|cwd| std::path::Path::new(cwd).is_absolute()) else {
        return false;
    };
    std::fs::symlink_metadata(std::path::Path::new(cwd).join(script))
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// A whole `sed` segment, generic checks included, that the native proof
/// accepts. The compatibility layer uses it so it does not treat the same
/// edit as a destructive shell mutation.
pub(crate) fn proven_in_place_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("sed")
        && in_place_segment(segment)
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

/// A whole `sed` segment that the native proof accepts as a read, such as
/// `sed -n 5,30p note.md`. It writes nothing, so the compatibility layer
/// does not count it as a write to the paths it names.
pub(crate) fn proven_read_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("sed")
        && !in_place_segment(segment)
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

/// The script reaches `sed` as written. A command substitution, parameter
/// expansion or `$'...'` string could add a flag or a second command after the
/// script was checked. `$` is accepted only as the end-of-line anchor right
/// before a delimiter, which no shell expands.
fn shell_text_literal(text: &str) -> bool {
    !text.contains('`')
        && text.match_indices('$').all(|(index, _)| {
            matches!(
                text[index + 1..].chars().next(),
                Some('/' | '|' | ',' | ':')
            )
        })
}

/// A segment that moves the working directory or changes what a path names.
/// The target checks run before the command does, so a `cd`, link, move or
/// copy in the same command would make them describe a different file.
fn changes_path_meaning(segment: &crate::CommandSegmentV1) -> bool {
    segment.executable.as_deref().is_some_and(|executable| {
        let name = executable.rsplit('/').next().unwrap_or(executable);
        PATH_CHANGERS.contains(&name)
    })
}

/// Any `sed` segment that may edit in place.
pub(super) fn in_place_segment(segment: &crate::CommandSegmentV1) -> bool {
    segment.executable.as_deref() == Some("sed")
        && segment
            .arguments
            .iter()
            .any(|argument| argument.starts_with("-i") || argument.starts_with("--in-place"))
}

/// The file operands of an accepted in-place spelling whose scripts are all
/// inert substitutions, and the suffix of any backup `sed` may write next to
/// each of them.
pub(super) struct InPlaceEdit<'a> {
    pub(super) targets: &'a [String],
    pub(super) backup_suffix: Option<&'a str>,
    /// The script, when it follows an empty suffix argument. GNU sed reads
    /// that argument as an empty script and this one as a file to rewrite.
    pub(super) script_operand: Option<&'a str>,
}

pub(super) fn in_place_edit(arguments: &[String]) -> Option<InPlaceEdit<'_>> {
    in_place_edit_with(arguments, false)
}

/// [`in_place_edit`], which with `scratch` also accepts a line insert.
fn in_place_edit_with(arguments: &[String], scratch: bool) -> Option<InPlaceEdit<'_>> {
    let mut rest = arguments;
    let mut extended = false;
    if rest.first().is_some_and(|word| word == "-E") {
        extended = true;
        rest = &rest[1..];
    }
    let (flag, tail) = rest.split_first()?;
    rest = tail;
    // `-iSUFFIX` means the same to GNU and BSD sed. A bare `-i` does not.
    let attached = flag.strip_prefix("-i")?;
    if !attached.is_empty() && !plain_backup_suffix(attached) {
        return None;
    }
    let empty_suffix = attached.is_empty() && rest.first().is_some_and(String::is_empty);
    let backup_suffix = if !attached.is_empty() {
        Some(attached)
    } else if empty_suffix {
        rest = &rest[1..];
        None
    } else {
        // BSD sed takes a following `-e` or `-E` as the suffix.
        rest.first()
            .map(String::as_str)
            .filter(|word| matches!(*word, "-e" | "-E"))
    };
    let portable = empty_suffix || !attached.is_empty();
    if !extended && rest.first().is_some_and(|word| word == "-E") {
        rest = &rest[1..];
    }
    let mut scripts: Vec<&str> = Vec::new();
    let mut script_operand = None;
    while let [flag, script, tail @ ..] = rest {
        if flag != "-e" {
            break;
        }
        scripts.push(script);
        rest = tail;
    }
    if scripts.is_empty() {
        // After a bare `-i`, BSD sed would take this script as the backup
        // suffix and read the first file name as its script.
        if !portable && !cfg!(target_os = "linux") {
            return None;
        }
        let (script, tail) = rest.split_first()?;
        // GNU sed reads `-i '' SCRIPT FILE` as an empty script, so SCRIPT is
        // also rewritten unchanged as a file. Keep that path from climbing out.
        if empty_suffix && script.split('/').any(|part| part == "..") {
            return None;
        }
        // An address such as `/pat/` is an absolute file name to GNU sed,
        // which only BSD sed (the macOS default) reads as a script.
        if empty_suffix && script.starts_with('/') && !cfg!(target_os = "macos") {
            return None;
        }
        scripts.push(script);
        script_operand = empty_suffix.then_some(script.as_str());
        rest = tail;
    } else if !portable && scripts.len() != 1 {
        // After a bare `-i`, BSD sed takes the first `-e` as the suffix and
        // stops reading options at the first script, so a later `-e` becomes
        // a file name.
        return None;
    }
    let targets_plain = !rest.is_empty()
        && rest.len() <= MAX_TARGETS
        && rest
            .iter()
            .all(|target| !target.is_empty() && !target.starts_with('-'));
    let inert = |script: &&str| {
        inert_substitution(script) || (scratch && append_scripts::inert_text_insert(script))
    };
    (targets_plain && scripts.iter().all(inert)).then_some(InPlaceEdit {
        targets: rest,
        backup_suffix,
        script_operand,
    })
}

/// A plain backup suffix such as `.bak` or `~`. GNU sed reads `*` as the file
/// name and `/` as a directory, so neither is accepted.
fn plain_backup_suffix(value: &str) -> bool {
    value.len() <= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~'))
}

/// Exactly one `s` command whose only flag is `g`. Delimiters are counted the
/// way both GNU and BSD sed count them: a backslash escapes the next
/// character, and a delimiter inside a regex bracket expression is refused
/// because only BSD sed treats it as literal.
pub(super) fn inert_substitution(script: &str) -> bool {
    if script.len() > MAX_SCRIPT || script.contains(['\n', '\r', '\0']) {
        return false;
    }
    let mut chars = script.chars().peekable();
    if chars.next() != Some('s') {
        return false;
    }
    let Some(delimiter) = chars.next().filter(|value| DELIMITERS.contains(*value)) else {
        return false;
    };
    let mut part = 0;
    let mut flags = String::new();
    while let Some(value) = chars.next() {
        if part == 2 {
            flags.push(value);
            continue;
        }
        if value == '\\' {
            if chars.next().is_none() {
                return false;
            }
        } else if value == delimiter {
            part += 1;
        } else if value == '[' && part == 0 && !bracket_closed(&mut chars, delimiter) {
            return false;
        }
    }
    // Everything after the third delimiter is the flag list.
    part == 2 && (flags.is_empty() || flags == "g")
}

/// Consumes a bracket expression after its `[`. A leading `^` and a leading
/// `]` are part of the set, and `[:class:]`, `[.coll.]` and `[=equiv=]` are
/// skipped whole. False when the delimiter, a newline or the end comes first.
fn bracket_closed(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, delimiter: char) -> bool {
    if chars.peek() == Some(&'^') {
        chars.next();
    }
    if chars.peek() == Some(&']') {
        chars.next();
    }
    while let Some(value) = chars.next() {
        if value == delimiter {
            return false;
        }
        if value == ']' {
            return true;
        }
        if value == '[' {
            if let Some(&kind) = chars.peek().filter(|kind| matches!(kind, ':' | '.' | '=')) {
                chars.next();
                let mut previous = '\0';
                loop {
                    match chars.next() {
                        Some(next) if next == delimiter => return false,
                        Some(']') if previous == kind => break,
                        Some(next) => previous = next,
                        None => return false,
                    }
                }
            }
        }
    }
    false
}

fn edits_safe(edit: &InPlaceEdit<'_>, context: super::PathContext<'_>) -> bool {
    let (Some(cwd), Some(home)) = (context.cwd, context.home_dir) else {
        return false;
    };
    let (Ok(workspace), Ok(home)) = (std::fs::canonicalize(cwd), std::fs::canonicalize(home))
    else {
        return false;
    };
    // A session rooted at the home directory, or above it, has no workspace
    // boundary narrower than the home.
    if home.starts_with(&workspace) || workspace.parent().is_none() {
        return false;
    }
    edit.targets.iter().all(|target| {
        target_safe(target, &workspace, context)
            && edit
                .backup_suffix
                .is_none_or(|suffix| backup_safe(&format!("{target}{suffix}"), &workspace, context))
    })
}

/// The backup `sed` writes next to a checked target: a new or ordinary
/// workspace file under the same rules, never a link, hook or instruction file.
fn backup_safe(value: &str, workspace: &Path, context: super::PathContext<'_>) -> bool {
    let joined = workspace.join(value);
    match std::fs::symlink_metadata(&joined) {
        Ok(_) => target_safe(value, workspace, context),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            super::safe_writes::bounded_file_write_target(value, context.home_dir, context.cwd)
                && Path::new(value)
                    .strip_prefix(workspace)
                    .map_or(plain_parts(Path::new(value)), plain_parts)
        }
        Err(_) => false,
    }
}

fn target_safe(value: &str, workspace: &Path, context: super::PathContext<'_>) -> bool {
    if value.starts_with('~')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || !super::safe_writes::bounded_file_write_target(value, context.home_dir, context.cwd)
    {
        return false;
    }
    let supplied = Path::new(value);
    let (joined, spelled) = if supplied.is_absolute() {
        let Ok(spelled) = supplied.strip_prefix(workspace) else {
            return false;
        };
        (supplied.to_path_buf(), spelled)
    } else {
        (workspace.join(supplied), supplied)
    };
    // `symlink_metadata` refuses a symlink in the final component; the
    // resolved path below covers symlinked parent directories.
    let Ok(metadata) = std::fs::symlink_metadata(&joined) else {
        return false;
    };
    if !metadata.is_file() || executable(&metadata) {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(&joined) else {
        return false;
    };
    canonical
        .strip_prefix(workspace)
        .is_ok_and(|resolved| plain_parts(resolved) && plain_parts(spelled))
}

/// Every component is a plain name: no `..`, no hidden name and no agent
/// instruction file.
fn plain_parts(path: &Path) -> bool {
    path.components().all(|component| match component {
        Component::CurDir => true,
        Component::Normal(part) => part.to_str().is_some_and(|part| {
            !part.starts_with('.')
                && !crate::harness_config_names::HARNESS_INSTRUCTION_FILES
                    .contains(&part.to_ascii_lowercase().as_str())
        }),
        _ => false,
    })
}

#[cfg(unix)]
fn executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
#[path = "sed_edits_tests.rs"]
mod tests;
