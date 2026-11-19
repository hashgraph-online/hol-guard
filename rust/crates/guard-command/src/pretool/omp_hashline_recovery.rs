//! Oh My Pi's reading of hashline headers Guard's plain parser rejects.
//!
//! Models sometimes leak their reasoning into an `edit` call, and a header
//! line then reads like `[tool/analysis code] ... "[src/app.py#D5E8]`.
//! `omp_hashline_writes` cannot prove which file such a header names, so the
//! edit used to go to review, and the agent sat waiting on an approval for a
//! call that could never apply. Oh My Pi itself reads every line that opens
//! with `[` as a header: it takes the text between the brackets, cuts a
//! trailing `#XXXX` tag, trims and unquotes it and strips `Update File:`-style
//! noise, and opens what is left. A tagged header whose path, read that way,
//! does not exist is a wrong path, so the edit fails in Oh My Pi. Guard can
//! stop it at once and tell the agent how to write the header.
//!
//! The rule only ever turns a review into a block, so it can never let an
//! edit through that Guard would otherwise stop.

use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_MARKERS: [&str; 2] = ["*** End Patch", "*** Abort"];
const SENTINELS: [&str; 2] = ["Begin Patch", "End Patch"];
const TAG_LENGTH: usize = 4;
const SHOWN_CHARS: usize = 120;

/// Reason code for a header that names a missing file, as for any write.
const MISSING_PATH: &str = "native_missing_path";
/// Reason code for an edit whose first header Oh My Pi cannot read.
const UNPARSEABLE_HEADER: &str = "native_omp_edit_header_unreadable";

/// Oh My Pi's `APPLY_PATCH_PATH_NOISE_RE`.
static PATH_NOISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^\*{0,3}\s*(?:(?:update|add|delete|move)[^A-Za-z0-9]*(?:file|to)?[^A-Za-z0-9]*:)?\s*\*{0,3}\s*",
    )
    .expect("static regex")
});

/// A header Guard cannot prove that Oh My Pi reads as a tagged path to a
/// file that does not exist.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct MissingHeader {
    /// The header line as written, shortened for a message.
    pub(super) line: String,
    /// The path Oh My Pi would open.
    pub(super) path: String,
}

/// The first header in `input` that Oh My Pi reads as a tagged path with
/// nothing behind it. The hashline write proof already stops plain missing
/// paths; this also covers headers it rejects and plain ones whose path holds
/// characters such as `?` or `[` that its missing-path check leaves unproven. `None` when the
/// session folder is unknown, when any header line is one Oh My Pi refuses
/// outright, or when every unproven header names a file that exists, is
/// sensitive or is protected.
fn missing_tagged_header(input: &str, cwd: Option<&str>) -> Option<MissingHeader> {
    if input.len() > crate::MAX_COMMAND_BYTES || input.contains('\0') {
        return None;
    }
    let workspace = std::fs::canonicalize(cwd?).ok()?;
    let mut found: Option<MissingHeader> = None;
    for line in input.split('\n') {
        let line = line.trim_end();
        if END_MARKERS.contains(&line) {
            break;
        }
        if line == BEGIN_PATCH || !line.starts_with('[') {
            continue;
        }
        let (path, tagged) = omp_header(line)?;
        if found.is_some() || !tagged {
            continue;
        }
        if missing_target(&path, &workspace) {
            found = Some(MissingHeader {
                line: shown(line),
                path,
            });
        }
    }
    found
}

/// The block reason for a header Oh My Pi reads as a missing file.
fn missing_header_reason(header: &MissingHeader) -> String {
    let named = if header.path.chars().count() <= SHOWN_CHARS
        && !header.path.contains(|c: char| c.is_control() || c == '`')
    {
        format!(" as the file `{}`, which does not exist", header.path)
    } else {
        " as a file that does not exist".to_owned()
    };
    format!(
        "HOL Guard did not run this edit because Oh My Pi reads its header `{}`{named}. Write each header as just the path and the tag the read tool showed, for example `[src/app.py#1A2B]`, with nothing else inside the brackets, and try again.",
        header.line
    )
}

/// The first header of an edit Oh My Pi cannot read at all, shortened for a
/// message.
///
/// Oh My Pi takes the first non-blank line after `*** Begin Patch` as the
/// first file header. When that line opens with `[` but its bracket closes
/// before the end of the line, as in `[tool_error] ...` or reasoning that
/// quotes a header, or the line does not end with `]`, Oh My Pi rejects the
/// whole edit with a parse error and writes nothing. A bracketed `*** ...`
/// marker at the start is one Oh My Pi unwraps, so such a line is left
/// unproven, as is one with control characters.
fn unparseable_first_header(input: &str) -> Option<String> {
    if input.len() > crate::MAX_COMMAND_BYTES || input.contains('\0') {
        return None;
    }
    let mut lines = input
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t', '\r']))
        .filter(|line| !line.is_empty());
    let mut line = lines.next()?;
    if line == BEGIN_PATCH {
        line = lines.next()?;
    }
    closes_early(line).then(|| shown(line))
}

/// The reason code and message for an edit Oh My Pi cannot apply: one whose
/// first header it cannot read, or whose tagged header names a missing file.
pub(super) fn unappliable_edit(input: &str, cwd: Option<&str>) -> Option<(&'static str, String)> {
    if let Some(header) = missing_tagged_header(input, cwd) {
        return Some((MISSING_PATH, missing_header_reason(&header)));
    }
    let line = unparseable_first_header(input)?;
    Some((UNPARSEABLE_HEADER, unparseable_header_reason(&line)))
}

/// The block reason for an edit whose first header Oh My Pi cannot read.
fn unparseable_header_reason(line: &str) -> String {
    format!(
        "HOL Guard did not run this edit because Oh My Pi cannot read its first header `{line}` and would reject the whole edit. Write each header on its own line as just the path and the tag the read tool showed, for example `[src/app.py#1A2B]`, with nothing before or after it, and try again."
    )
}

/// Whether `line` opens a header Oh My Pi cannot parse: its opening `[`
/// closes before the end of the line, it holds nothing, or the line does
/// not end with `]`.
fn closes_early(line: &str) -> bool {
    let Some(body) = line.strip_prefix('[') else {
        return false;
    };
    if body.chars().any(|c| c.is_control() || c == '\u{feff}')
        || body.trim_start_matches([' ', '\t']).starts_with('*')
    {
        return false;
    }
    let mut depth = 1usize;
    for (index, c) in body.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    // An empty header such as `[]` or `[ ]` names nothing.
                    return index + 1 != body.len()
                        || body[..index].trim_matches([' ', '\t']).is_empty();
                }
            }
            _ => {}
        }
    }
    !body.ends_with(']')
}

/// The path and whether it carries a tag, the way Oh My Pi's
/// `parseHashlineHeaderLine` reads a line that opens with `[`; `None` where
/// it throws.
fn omp_header(line: &str) -> Option<(String, bool)> {
    let body = line.strip_prefix('[')?.strip_suffix(']')?;
    // JavaScript's `trim` also drops a byte order mark; leave such a line,
    // and one with control characters, unproven. Newer Oh My Pi releases
    // unwrap a bracketed `*** Begin Patch` or `*** End Patch` inside a header
    // row, so a row holding either is left unproven too.
    if body.chars().any(|c| c.is_control() || c == '\u{feff}')
        || SENTINELS.iter().any(|sentinel| body.contains(sentinel))
    {
        return None;
    }
    let (path, tagged) = strict_header(body).or_else(|| recovery_header(body))?;
    let path = normalize(path);
    (!path.is_empty()).then_some((path, tagged))
}

/// `tryParseHeader`: the raw body, with a trailing hex tag cut.
fn strict_header(body: &str) -> Option<(&str, bool)> {
    let (path, tagged) = split_tag(body);
    (!path.is_empty() && !path.contains('#')).then_some((path, tagged))
}

/// `tryParseRecoveryHeader`: the trimmed body without noise, with a trailing
/// hex tag (and blanks after it) cut.
fn recovery_header(body: &str) -> Option<(&str, bool)> {
    let body = strip_noise(body.trim());
    if body.is_empty() {
        return None;
    }
    let (path, tagged) = split_tag(body.trim_end());
    let path = if tagged { path } else { path.trim_end() };
    (!path.contains('#')).then_some((path, tagged))
}

fn split_tag(body: &str) -> (&str, bool) {
    match body.len().checked_sub(TAG_LENGTH + 1) {
        Some(start)
            if body.as_bytes()[start] == b'#'
                && body.as_bytes()[start + 1..]
                    .iter()
                    .all(u8::is_ascii_hexdigit) =>
        {
            (&body[..start], true)
        }
        _ => (body, false),
    }
}

/// `normalizeHashlinePath` for a relative path: trim, unquote, strip noise.
fn normalize(path: &str) -> String {
    let path = path.trim();
    let unquoted = match (path.chars().next(), path.chars().last()) {
        (Some(first @ ('"' | '\'')), Some(last)) if path.len() >= 2 && first == last => {
            &path[1..path.len() - 1]
        }
        _ => path,
    };
    strip_noise(unquoted).to_owned()
}

/// Deletes the `***` and `Update File:` noise Oh My Pi drops from a header
/// path before it opens the file.
pub(super) fn strip_noise(text: &str) -> &str {
    PATH_NOISE
        .find(text)
        .map_or(text, |noise| &text[noise.end()..])
}

/// Whether Oh My Pi would find nothing at `path`, an ordinary name that is
/// not sensitive or protected. A `~` or scheme spelling, a control character
/// or a path that cannot be checked leaves it unproven.
fn missing_target(path: &str, workspace: &Path) -> bool {
    let scheme = path
        .split_once(":/")
        .is_some_and(|(name, _)| !name.is_empty() && !name.contains(['/', '\\', ' ']));
    // Oh My Pi resolves `..` before it opens the path, so a missing folder
    // before `..` proves nothing.
    if path.starts_with('~')
        || scheme
        || Path::new(path)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || path.len() > 4096
        || path.chars().any(char::is_control)
        || super::sensitive_command(path)
        || super::apply_patch_writes::protected_name(Path::new(path))
    {
        return false;
    }
    // Walk down from the session folder so a junk name too long for the file
    // system still reads as missing at its first absent folder.
    let mut candidate = workspace.to_path_buf();
    for component in Path::new(path).components() {
        candidate.push(component);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
        }
    }
    false
}

fn shown(line: &str) -> String {
    let shown: String = line
        .chars()
        .filter(|c| !c.is_control() && *c != '`')
        .take(SHOWN_CHARS)
        .collect();
    if line.chars().count() > SHOWN_CHARS {
        format!("{shown}...")
    } else {
        shown
    }
}

#[cfg(test)]
#[path = "omp_hashline_recovery_tests.rs"]
mod tests;
