//! Which program may be fed literal bytes on standard input.
//!
//! A quoted heredoc and a here-string both put bytes on standard input and
//! nothing else: the projection strips the operator and the redirects and
//! hands the rest of the command back to be evaluated in full. The bytes are
//! not expanded, read no file and reach no network. The only way they can
//! matter is a program that runs, applies or installs what it reads.
//!
//! The list is positive because that risk has no shape to test for. A shell
//! and an interpreter are the obvious cases, but `xargs` builds a command line
//! from stdin, `psql`, `mysql` and `sqlite3` execute it, `patch` and
//! `git apply` apply it, `tar -x` and `dd` write it, `crontab -` installs it
//! and `kubectl apply -f -` deploys it. None of them looks like an
//! interpreter, so naming the programs that only read is the only test that
//! stays correct as programs are added.
//!
//! `git commit -F -` reads those bytes as the message it records. It runs
//! nothing from them and saves them nowhere else, so it belongs beside the
//! filters. No other `git` subcommand does: `apply` and `am` apply a patch,
//! `hash-object --stdin` writes an object and `fast-import` rewrites history,
//! so the subcommand is named rather than the program. The commit itself is
//! still the write it is, and keeps the proof every other spelling of it gets.
//!
//! Which segment of a chain the operator belongs to is not in the projected
//! text, so every segment answers for it. A chain whose segments all only
//! read leaves nothing that could run the bytes, whichever one the shell
//! hands them to.

use super::Quote;
use crate::{CanonicalCommandV1, CommandSegmentV1};

/// Programs that read standard input as data. Each prints, counts, filters or
/// reshapes what it reads; none runs, applies or installs it.
const FILTERS: &[&str] = &[
    "cat", "column", "cut", "diff", "fmt", "fold", "grep", "head", "jq", "nl", "rev", "sort",
    "tail", "tee", "tr", "uniq", "wc", "yq",
];

/// Whether the command the bytes reach only reads them, so what arrives on
/// standard input is data and nothing else. The caller still proves every
/// file that command writes on its own.
///
/// The operator belongs to the command the shell was reading when it met it.
/// With nothing separating that command from the end of the text, it is the
/// last segment, and that segment alone answers for the bytes. With a
/// separator after it, which segment the shell hands them to is no longer in
/// the projected text, so every segment answers for them.
pub(super) fn reads_data(model: &CanonicalCommandV1, separated_after: bool) -> bool {
    if !model.wrapper_chain.is_empty() || model.path_overridden || model.segments.is_empty() {
        return false;
    }
    if separated_after {
        model.segments.iter().all(segment_reads_data)
    } else {
        model.segments.last().is_some_and(segment_reads_data)
    }
}

/// Whether `segment` is one plain `git commit -F -`, which reads a quoted
/// heredoc only as the message it records, with nothing else reading standard
/// input. The decision's projection already lets such a commit take the
/// bytes; the workspace sandbox's projection asks the same question of the
/// segment a heredoc feeds, so a commit routed to the sandbox can be planned.
pub(in crate::pretool) fn heredoc_records_commit_message(segment: &str) -> bool {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: segment.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .is_ok_and(|model| {
        model.confidence == "exact"
            && model.uncertainty_reason.is_none()
            && model.wrapper_chain.is_empty()
            && !model.path_overridden
            && model.segments.len() == 1
            && segment_reads_data(&model.segments[0])
            && model.segments[0].executable.as_deref() == Some("git")
    })
}

/// The command a heredoc operator at the end of `out` belongs to: the text
/// after the last unquoted separator. `None` when a comment is open there,
/// because the shell then ignores the operator and runs the lines meant as
/// its body as commands.
pub(in crate::pretool) fn heredoc_segment(out: &str) -> Option<&str> {
    let (mut quote, mut escaped, mut commented) = (Quote::None, false, false);
    let (mut start, mut word_start) = (0, true);
    for (position, value) in out.char_indices() {
        let at_word_start = std::mem::replace(&mut word_start, false);
        if escaped {
            escaped = false;
            continue;
        }
        // A comment runs to the end of its line, quotes and all.
        if commented {
            if value == '\n' {
                (commented, start, word_start) = (false, position + 1, true);
            }
            continue;
        }
        match (quote, value) {
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::None,
            (Quote::Double | Quote::None, '\\') => escaped = true,
            (Quote::Single | Quote::Double, _) => {}
            (Quote::None, '\'') => quote = Quote::Single,
            (Quote::None, '"') => quote = Quote::Double,
            (Quote::None, '#') if at_word_start => commented = true,
            (Quote::None, ';' | '|' | '&' | '\n' | '(' | ')' | '{' | '}') => {
                (start, word_start) = (position + 1, true);
            }
            (Quote::None, value) => word_start = value.is_whitespace(),
        }
    }
    (!commented).then(|| &out[start..])
}

/// Whether one segment, spelled plainly by name with no wrapper, environment
/// assignment or path override, only reads what reaches it on standard input.
fn segment_reads_data(segment: &CommandSegmentV1) -> bool {
    segment.wrapper_chain.is_empty()
        && segment.environment_names.is_empty()
        && !segment.path_overridden
        && segment.executable.as_deref().is_some_and(|executable| {
            FILTERS.contains(&executable) || records_a_commit_message(executable, segment)
        })
}

/// Whether the segment is a `git commit` that takes its message from standard
/// input, which is the only commit form that reads the bytes at all. A message
/// on the command line, a message file and an amended message all leave them
/// untouched, so dropping the body in front of one of those would project a
/// command the shell never ran.
///
/// The subcommand is the first word, so a global option such as `-C` or `-c`
/// in front of it leaves the segment unrecognised and the projection closed.
/// That is deliberate: those options choose the repository and the
/// configuration the commit runs under, and this test answers only for what
/// the bytes on standard input become.
fn records_a_commit_message(executable: &str, segment: &CommandSegmentV1) -> bool {
    if executable != "git" {
        return false;
    }
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    matches!(
        words.split_first(),
        Some((&"commit", rest))
            if crate::pretool::git_local_writes::forms::message_from_standard_input(rest)
    )
}

/// The bare `cat` the caller may stand a no-op in for. Reading standard input
/// is the whole of what it does, so once the write is proven there is nothing
/// left for the command itself to do. Every other filter, and `cat` with
/// arguments, still has the files it names read.
pub(super) fn is_bare_cat(model: &CanonicalCommandV1) -> bool {
    model.segments.len() == 1
        && model.segments[0].executable.as_deref() == Some("cat")
        && model.segments[0].arguments.is_empty()
}

/// Read a `<<< WORD` here-string off the text, leaving the command behind.
///
/// A here-string is one word, so the whole of what reaches standard input is
/// in the text. That holds only while the word substitutes values: a command
/// substitution inside it runs a program the projected text no longer names,
/// so the word is checked before the operator is taken away.
pub(super) fn remove_here_string(chars: &[char], start: usize, out: &mut String) -> Option<usize> {
    if chars.get(start + 1) != Some(&'<') || chars.get(start + 2) != Some(&'<') {
        return None;
    }
    // `foo<<<bar` redirects a file descriptor the projection cannot read.
    if !super::trailing_word(out).is_empty() {
        return None;
    }
    let mut index = start + 3;
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let word_start = index;
    let mut quote = Quote::None;
    while let Some(&current) = chars.get(index) {
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match current {
                '\\' => index += 1,
                '"' => quote = Quote::None,
                _ => {}
            },
            Quote::None => match current {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => index += 1,
                _ if current.is_whitespace() || matches!(current, ';' | '|' | '&' | '<' | '>') => {
                    break
                }
                _ => {}
            },
        }
        index += 1;
    }
    if quote != Quote::None || index == word_start || index > chars.len() {
        return None;
    }
    if !word_is_data(&chars[word_start..index]) {
        return None;
    }
    out.push(' ');
    Some(index)
}

/// Whether the here-string word substitutes values and nothing else.
///
/// `$NAME` and `${NAME}` put a value on standard input, which is the common
/// shape and runs nothing. A command substitution, a backtick, a process
/// substitution, `$'...'` and an arithmetic expansion each evaluate inside the
/// word, so the projected text would no longer name everything the shell runs.
/// Arithmetic reaches furthest of those: it evaluates the values of the names
/// it mentions, and a subscript inside one of those values substitutes a
/// command, so `$[x]` runs whatever `x` holds.
fn word_is_data(chars: &[char]) -> bool {
    let mut index = 0;
    let mut quote = Quote::None;
    while index < chars.len() {
        let current = chars[index];
        if quote == Quote::Single {
            if current == '\'' {
                quote = Quote::None;
            }
            index += 1;
            continue;
        }
        match current {
            '\\' => index += 1,
            '\'' if quote == Quote::None => quote = Quote::Single,
            '"' => {
                quote = if quote == Quote::Double {
                    Quote::None
                } else {
                    Quote::Double
                }
            }
            '`' => return false,
            '<' | '>' if chars.get(index + 1) == Some(&'(') => return false,
            '$' => match chars.get(index + 1) {
                Some(&('(' | '[' | '\'' | '"')) => return false,
                Some(&'{') => match plain_expansion(chars, index + 2) {
                    Some(close) => index = close,
                    None => return false,
                },
                _ => {}
            },
            _ => {}
        }
        index += 1;
    }
    true
}

/// The `}` of a `${NAME}` that substitutes a value, or `${#NAME}` for its
/// length. Every other brace form expands a replacement, evaluates an
/// arithmetic offset or changes shell state, so none of them is a value.
fn plain_expansion(chars: &[char], start: usize) -> Option<usize> {
    let start = start + usize::from(chars.get(start) == Some(&'#'));
    let mut index = start;
    while chars
        .get(index)
        .is_some_and(|value| value.is_ascii_alphanumeric() || *value == '_')
    {
        index += 1;
    }
    if index == start || chars.get(index) != Some(&'}') {
        return None;
    }
    Some(index)
}

/// Skips the bodies of the pending heredocs in order, as
/// `skip_heredoc_bodies` does. A body that feeds Python must fit the sandbox
/// ([`python_program_fits`]); `wide` is set once one uses more than builtins.
pub(in crate::pretool) fn skip_bodies(
    chars: &[char],
    mut index: usize,
    heredocs: &mut Vec<(String, bool)>,
    programs: &mut Vec<bool>,
    wide: &mut bool,
) -> Option<usize> {
    if heredocs.len() != programs.len() {
        return None;
    }
    for (heredoc, program) in heredocs.drain(..).zip(programs.drain(..)) {
        let start = index;
        index = super::skip_heredoc_bodies(chars, index, &mut vec![heredoc])?;
        if program {
            let text: String = chars[start..index].iter().collect();
            let text = text.strip_suffix('\n').unwrap_or(&text);
            // The last line is the delimiter.
            let body: Vec<&str> = match text.rsplit_once('\n') {
                Some((body, _)) => body.split('\n').collect(),
                None => Vec::new(),
            };
            if !crate::native_command_controls::python_is_builtin_only(&body) {
                *wide = true;
                if !python_program_fits(&body) {
                    return None;
                }
            }
        }
    }
    Some(index)
}

/// Whether a program fed to Python on standard input may run in the
/// workspace sandbox. A program that uses only builtins can start nothing.
/// Any other program is held to the bar a script file in the workspace
/// meets: it may import modules, the project's own included, but needs
/// neither the network nor a credential store. The sandbox, not this scan,
/// bounds what it does; the scan keeps a program that would fail there on
/// review. The source has to be plain ASCII with no coding declaration, so
/// the text scanned is the text Python runs.
/// Such a program is only taken when it is the whole command
/// (`script_content::fed::python_alone`).
fn python_program_fits(body: &[&str]) -> bool {
    body.iter().all(|row| row.is_ascii())
        && !body.iter().take(2).any(|row| coding_comment(row))
        && crate::pretool::script_content::fed::source_clean(
            crate::pretool::script_content::Language::Python,
            &body.join("\n"),
        )
}

/// Whether a row may be a source-encoding declaration. Python reads one only
/// from a comment on the first or second line (PEP 263), so the caller asks
/// just those two; anywhere else `coding` is ordinary text, as in
/// `open(path, encoding="utf-8")`. Any comment naming `coding` there counts,
/// looser than Python's own pattern.
fn coding_comment(row: &str) -> bool {
    row.trim_start_matches([' ', '\t', '\x0c'])
        .strip_prefix('#')
        .is_some_and(|comment| comment.to_ascii_lowercase().contains("coding"))
}
