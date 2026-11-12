//! The `sed` reading: a line-range print, a substitution or a stream edit
//! over one file or a pipe.

/// Leading `-n`, `-E` and `-r` flags (alone or joined, as in `-nE`), then one
/// script or one or more `-e SCRIPT` pairs, then the targets.
fn sed_programs_and_targets(arguments: &[String]) -> Option<(bool, Vec<&str>, &[String])> {
    let mut quiet = false;
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first() {
        let Some(letters) = flag.strip_prefix('-').filter(|letters| {
            !letters.is_empty() && letters.bytes().all(|b| matches!(b, b'n' | b'E' | b'r'))
        }) else {
            break;
        };
        quiet |= letters.contains('n');
        rest = tail;
    }
    let mut programs = Vec::new();
    if rest.first().is_some_and(|arg| arg == "-e") {
        while let [flag, program, tail @ ..] = rest {
            if flag != "-e" {
                break;
            }
            programs.push(program.as_str());
            rest = tail;
        }
    } else {
        let (program, targets) = rest.split_first()?;
        programs.push(program.as_str());
        rest = targets;
    }
    if programs.is_empty() {
        return None;
    }
    Some((quiet, programs, rest))
}

pub(in crate::pretool) fn safe_sed_stdin_arguments(arguments: &[String]) -> bool {
    let Some((_, _, targets)) = sed_programs_and_targets(arguments) else {
        return false;
    };
    (targets.is_empty() || matches!(targets, [target] if target == "-"))
        && safe_sed_arguments(arguments, true, super::super::PathContext::default())
}

/// Upper bound on `;`-separated range prints in one `sed -n` program.
const MAX_PRINT_RANGES: usize = 16;

pub(in crate::pretool) fn safe_sed_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::super::PathContext<'_>,
) -> bool {
    let Some((quiet, programs, targets)) = sed_programs_and_targets(arguments) else {
        return false;
    };
    if programs
        .iter()
        .any(|program| program.len() > 256 || program.contains(['\n', '\r']))
    {
        return false;
    }
    // `1,12p;28,40p` prints several line ranges, as the Codex output proof
    // already allows, and `-e 5p -e 9p` is the same program. Every statement
    // must print a region named by line numbers, `$` or a `/regex/` address,
    // so no w/W/e/r command, label or other command can join it. A `;` inside
    // a pattern belongs to the address, and a program whose delimiter is left
    // open is one this reading never finished, so it stays unread.
    let statements: Option<Vec<&str>> = programs
        .iter()
        .map(|program| crate::codex_output_args::sed_statements_split(program))
        .try_fold(Vec::new(), |mut all, split| {
            all.extend(split?);
            Some(all)
        });
    let bounded_print = quiet
        && statements.is_some_and(|statements| {
            statements.len() <= MAX_PRINT_RANGES
                && statements
                    .iter()
                    .all(|statement| bounded_print_statement(statement))
        });
    // Substitutions with inert flags, and nothing else. A redaction spells
    // its own delimiter inside the pattern -- `s/\\/tmp\\/scratch-[a-z]*/DIR/`
    // names a path by escaping every slash in it -- so the reading walks the
    // program and honours that escape rather than counting the delimiters it
    // finds. No e/w commands, program files, in-place edits or any other
    // statement can enter this proof.
    let substitution = programs
        .iter()
        .all(|program| crate::sed_substitution::sed_script_is_pure_substitution(program));
    // Line deletes, early quits and addressed substitutions trim the same
    // stream (`sed '1d;$d'`, `sed 5q`, `sed '12s/a/b/'`); the reading admits
    // only commands that print, drop or rewrite the lines it reads.
    let stream_edit = programs
        .iter()
        .all(|program| crate::sed_substitution::sed_script_is_stream_edit(program));
    (bounded_print || substitution || stream_edit)
        && (matches!(targets, [target] if (target == "-" && piped_input) || (!target.starts_with('-') && super::command_read_target(target, context, false)))
            || (targets.is_empty() && piped_input))
}

/// One `sed -n` statement that only names lines: `5p`, `$p`, `36,39p`,
/// `36, 39p`. A range with no command, such as `36,37`, is a sed syntax error
/// that prints nothing, so it reads no more than the print does.
///
/// A region a reader names rather than counts -- `/export/p`,
/// `/export/,/^};/p`, `0,/export/p` -- prints from the same file and writes
/// nothing either, so the read-only filter's reading of a `/regex/` address
/// decides it here too. That reading takes only the plain slash pair: a
/// `\%...%` delimiter, a negated address, an empty pattern, a third address
/// and any command other than `p` stay unread and keep their review.
///
/// Only a statement that spells a pattern address is read that way. A
/// statement of digits alone keeps the stricter line rule above, which
/// refuses sed's invalid line `0` and a `p` that names no line at all.
fn bounded_print_statement(statement: &str) -> bool {
    let statement = statement.trim_matches([' ', '\t']);
    if statement.contains('/') && crate::codex_output_args::sed_print_command_is_bounded(statement)
    {
        return true;
    }
    let range = statement
        .strip_suffix('p')
        .unwrap_or(statement)
        .trim_end_matches([' ', '\t']);
    let counts: Vec<_> = range.split(',').collect();
    (1..=2).contains(&counts.len())
        && counts.iter().all(|count| {
            let count = count.trim_matches([' ', '\t']);
            count == "$"
                || (!count.is_empty()
                    && count.len() <= 6
                    && count.bytes().all(|byte| byte.is_ascii_digit())
                    && count.parse::<u32>().is_ok_and(|count| count > 0))
        })
}
