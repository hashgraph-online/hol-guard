//! Output filters after a contained core: `| head -N`, `| tail -N`, the same
//! two bounded by bytes (`-c N`) or spelled with `-n N`, a `grep` or `rg`
//! that only reads its standard input, and a `cut` that keeps part of each
//! line, chained up to three deep.
//!
//! The execution sink (`contained_output_filters.py`) peels the same chain,
//! runs the core contained and applies the filters to its captured output.
//! A filter that names a file, reads patterns from one, recurses or writes
//! anywhere is not a filter here, so the whole command keeps its review.
use crate::CommandSegmentV1;

/// The longest chain the sink applies.
pub(in crate::pretool) const MAX_FILTERS: usize = 3;

/// Single-letter `grep` switches that change only which lines of standard
/// input are printed and how. Recursion (`-r`), pattern files (`-f`), file
/// listings (`-l`), and every option the sink does not apply are absent.
const GREP_SWITCHES: &str = "EFGacinosvwx";

/// The same for `rg`, which spells its own set: `-S`/`-s` select case
/// folding, `-N` drops line numbers and `-U` matches across lines. `-E`
/// (encoding) and `-g` (glob) take a value in ripgrep, and `-P` opts into a
/// second regex engine, so none of them is a switch here.
const RG_SWITCHES: &str = "FNSUacinosvwx";

/// Options that take a line count, spelled alike by both programs.
const GREP_COUNTS: &[&str] = &["-A", "-B", "-C", "-m"];

/// `cut`'s own switches: `-s` drops a line with no delimiter and `-n` keeps a
/// character whole. Neither names anything to open.
const CUT_SWITCHES: &str = "sn";

/// The options that carry `cut`'s selection and its delimiter. Every one of
/// them takes a value, attached or as the word after.
const CUT_VALUED: &[&str] = &["-b", "-c", "-f", "-d"];

/// `cat`'s switches, which only decide how the bytes it copies are spelled:
/// `-v` prints a non-printing byte as an escape, `-E`/`-T` mark line ends and
/// tabs, `-A` is all three, `-e` and `-t` pair `-v` with one of them, `-n`
/// and `-b` number lines, `-s` squeezes blank runs and `-u` drops buffering.
/// None of them takes a value and none names anything to open, so a `cat`
/// with only these reads standard input and nothing else. Every operand,
/// including a lone `-`, is a file `cat` opens, which `text_filter` refuses.
const CAT_SWITCHES: &str = "AbeEnstTuv";

#[path = "contained_sed_script.rs"]
mod sed_script;

/// `sed`'s own switches, none of which names anything to open: `-n` prints
/// only what the script selects, `-E` and `-r` read the script's patterns as
/// extended regular expressions, `-s` treats each input separately, `-u`
/// drops buffering and `-z` separates lines by NUL. `-i` edits a file in
/// place and `-f` reads the script out of one, so neither is a switch here
/// and a word spelling either keeps the command's review.
const SED_SWITCHES: &str = "Enrsuz";

/// Whether `value` is a count small enough to be a filter's bound.
fn bounded_count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `segment` is one filter stage whose source text is `source`.
pub(super) fn filter_stage(segment: &CommandSegmentV1, source: &str) -> bool {
    if !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || !plain_source(source)
    {
        return false;
    }
    match segment.executable.as_deref() {
        Some("head" | "tail") => head_tail_arguments(&segment.arguments),
        Some("grep" | "egrep" | "fgrep") => stdin_arguments(&segment.arguments, GREP_SWITCHES),
        Some("rg") => stdin_arguments(&segment.arguments, RG_SWITCHES),
        Some("cut") => text_filter(&segment.arguments, CUT_SWITCHES, CUT_VALUED),
        _ => false,
    }
}

/// Whether `program <arguments>` is a matcher reading only standard input.
///
/// The sink's own peel reads a stage from the command text rather than from a
/// parsed segment, so it asks this directly.
pub(in crate::pretool) fn matcher_stage(program: &str, arguments: &[String]) -> bool {
    match program {
        "grep" | "egrep" | "fgrep" => stdin_arguments(arguments, GREP_SWITCHES),
        "rg" => stdin_arguments(arguments, RG_SWITCHES),
        // `cut` keeps part of each line and opens nothing without an operand,
        // which `text_filter` refuses, so the runtime can run it over the
        // captured text exactly as the pipeline would have.
        "cut" => text_filter(arguments, CUT_SWITCHES, CUT_VALUED),
        _ => false,
    }
}

/// The bound one `head`/`tail` stage keeps: the count, and whether it counts
/// bytes rather than lines.
///
/// `head -40`, `head -n 40` and `head -c 1500` all bound the text the stage
/// prints and read nothing but standard input, so the sink applies each of
/// them in process. A byte count truncates the captured bytes exactly where
/// the program would, which may be mid-character; the sink keeps those bytes
/// as they stand rather than rounding to a character boundary.
pub(in crate::pretool) fn head_tail_bound(arguments: &[String]) -> Option<(u32, bool)> {
    let (digits, bytes) = match arguments {
        [single] => match single.strip_prefix("-c").filter(|rest| !rest.is_empty()) {
            Some(digits) => (digits, true),
            None => (single.strip_prefix('-')?, false),
        },
        [flag, count] => match flag.as_str() {
            "-n" => (count.as_str(), false),
            "-c" => (count.as_str(), true),
            _ => return None,
        },
        _ => return None,
    };
    if !bounded_count(digits) {
        return None;
    }
    Some((digits.parse().ok()?, bytes))
}

pub(in crate::pretool) fn head_tail_arguments(arguments: &[String]) -> bool {
    head_tail_bound(arguments).is_some()
}

/// A matcher that reads only standard input: switches from `switches`,
/// counted options, `-e PATTERN`, and one pattern operand unless `-e` gave
/// the patterns. Any further operand is a file, so it is refused.
fn stdin_arguments(arguments: &[String], switches: &str) -> bool {
    let mut expressions = 0usize;
    let mut operands = 0usize;
    let mut options_done = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if argument == "-" {
            return false;
        }
        if options_done || !argument.starts_with('-') {
            operands += 1;
            continue;
        }
        if argument == "--" {
            options_done = true;
            continue;
        }
        if argument == "-e" {
            if index >= arguments.len() {
                return false;
            }
            index += 1;
            expressions += 1;
            continue;
        }
        if let Some(attached) = GREP_COUNTS
            .iter()
            .find_map(|option| argument.strip_prefix(*option))
        {
            let count = if attached.is_empty() {
                index += 1;
                match arguments.get(index - 1) {
                    Some(count) => count.as_str(),
                    None => return false,
                }
            } else {
                attached
            };
            if !bounded_count(count) {
                return false;
            }
            continue;
        }
        let flags = argument.strip_prefix('-').unwrap_or_default();
        if flags.is_empty() || !flags.chars().all(|flag| switches.contains(flag)) {
            return false;
        }
    }
    if expressions > 0 {
        operands == 0
    } else {
        operands == 1
    }
}

/// Whether `program <arguments>` only reshapes the text of the stage before
/// it, for a pipeline the sink rejoins and the sandbox's own shell runs stage
/// by stage.
///
/// A rejoined stage is never peeled off and applied in process, so the sink
/// cannot vouch for what it reads: it is the shell in the containment root
/// that runs it. Each program here therefore has to read standard input and
/// nothing else. `head`, `tail` and the matchers already have that reading,
/// and the rest earn it by taking no operand, because every one of them opens
/// an operand as a file. Anything else -- a shell, an interpreter, `xargs` --
/// would make the program that finally runs a different one from the program
/// the containment proof screened.
pub(in crate::pretool) fn rejoined_stage(program: &str, arguments: &[String]) -> bool {
    match program {
        "head" | "tail" => head_tail_arguments(arguments),
        "grep" | "egrep" | "fgrep" => stdin_arguments(arguments, GREP_SWITCHES),
        "rg" => stdin_arguments(arguments, RG_SWITCHES),
        "wc" => text_filter(arguments, "clmwL", &[]),
        // `cat` with no operand copies standard input through, and its
        // switches only change how the bytes are spelled. Agents reach for
        // `| cat -A` or `| cat -v` to make a runner's escape codes legible.
        "cat" => text_filter(arguments, CAT_SWITCHES, &[]),
        "cut" => text_filter(arguments, CUT_SWITCHES, CUT_VALUED),
        // `-o` and `-T` name a file and a directory to write, and `-S` sizes a
        // buffer, so none of the three is a switch here.
        "sort" => text_filter(arguments, "bcdfghiMnrsuVz", &["-k", "-t"]),
        "uniq" => text_filter(arguments, "cdiuz", &["-f", "-s", "-w"]),
        // `tr` has no file operand at all: it reads standard input whatever it
        // is given, so its operands are the character sets they look like.
        "tr" => true,
        // `sed` with no file operand reads standard input, and the stage runs
        // under the sandbox's own shell inside the containment root -- the
        // same place the same `sed` already runs when no directory change
        // precedes it. Agents reach for `| sed -n '/BEGIN/,/END/p'` to cut
        // one block out of a long runner log.
        "sed" => sed_arguments(arguments),
        _ => false,
    }
}

/// Whether a rejoined stage's own words survive being written back as text.
///
/// `plain_source` reads the segment the way a shell does, so it lets a quoted
/// `|`, `;`, `<`, `>` or `&` through as an ordinary character. The sink writes
/// the stage back from its lexed words, where those characters are operators
/// again, so it refuses the same word. Asking for both here keeps the
/// classifier from promising a containment the sink will not build.
pub(in crate::pretool) fn rejoined_words(program: &str, arguments: &[String]) -> bool {
    std::iter::once(program)
        .chain(arguments.iter().map(String::as_str))
        .all(|word| {
            !word
                .chars()
                .any(|character| crate::pretool::sink_peel::ARGUMENT_REJECT.contains(character))
        })
}

/// Whether `sed <arguments>` reads only standard input: switches from
/// [`SED_SWITCHES`], `-e SCRIPT` expressions, and one script operand unless
/// `-e` already gave the script. Any further operand is a file `sed` opens,
/// and a lone `-` is standard input spelled as one, which the peel cannot
/// write back.
///
/// Counting operands is not enough on its own, because a `sed` script opens
/// files and runs programs by itself: `r FILE` reads one, `w FILE` writes
/// one and GNU `e COMMAND` runs a shell. Every script the command carries
/// therefore goes through [`sed_script::text_filter_script`] as well.
fn sed_arguments(arguments: &[String]) -> bool {
    let mut expressions = 0usize;
    let mut operands = 0usize;
    let mut options_done = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if argument == "-" {
            return false;
        }
        if options_done || !argument.starts_with('-') {
            operands += 1;
            // The first operand is the script when no `-e` gave one; a
            // second operand is a file, which the count below refuses.
            if operands == 1 && expressions == 0 && !sed_script::text_filter_script(argument) {
                return false;
            }
            continue;
        }
        if argument == "--" {
            options_done = true;
            continue;
        }
        if argument == "-e" {
            let Some(script) = arguments.get(index) else {
                return false;
            };
            if !sed_script::text_filter_script(script) {
                return false;
            }
            index += 1;
            expressions += 1;
            continue;
        }
        let flags = argument.strip_prefix('-').unwrap_or_default();
        if flags.is_empty() || !flags.chars().all(|flag| SED_SWITCHES.contains(flag)) {
            return false;
        }
    }
    if expressions > 0 {
        operands == 0
    } else {
        operands == 1
    }
}

/// Whether `arguments` are switches and bounded option values only.
///
/// `switches` are the single letters that change the shape of the text, and
/// `valued` the options taking one value, attached or as the word after. An
/// operand is refused outright: every program this serves reads it as a file,
/// which is a read the containment proof never screened.
fn text_filter(arguments: &[String], switches: &str, valued: &[&str]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        let Some(flags) = argument.strip_prefix('-') else {
            return false;
        };
        if flags.is_empty() {
            return false;
        }
        if let Some(attached) = valued
            .iter()
            .find_map(|option| argument.strip_prefix(*option))
        {
            if attached.is_empty() {
                if index >= arguments.len() {
                    return false;
                }
                index += 1;
            }
            continue;
        }
        if !flags.chars().all(|flag| switches.contains(flag)) {
            return false;
        }
    }
    true
}

/// Plain words the sink lexes into the same arguments: no `$` or backquote
/// anywhere, no control character but a tab, and outside quotes only word
/// characters and blanks. Globs, braces, `~`, escapes, redirects and
/// operators all leave the filter to review.
pub(in crate::pretool) fn plain_source(source: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut chars = source.chars();
    while let Some(current) = chars.next() {
        if matches!(current, '$' | '`') || (current.is_control() && current != '\t') {
            return false;
        }
        match quote {
            Some('\'') => {
                if current == '\'' {
                    quote = None;
                }
            }
            Some(_) => match current {
                '"' => quote = None,
                '\\' => match chars.next() {
                    Some(next) if !matches!(next, '$' | '`') && !next.is_control() => {}
                    _ => return false,
                },
                _ => {}
            },
            None => match current {
                '\'' | '"' => quote = Some(current),
                ' ' | '\t' | '-' | '_' | '.' | ',' | ':' | '/' | '=' | '+' | '@' | '%' | '^' => {}
                _ if current.is_ascii_alphanumeric() => {}
                _ => return false,
            },
        }
    }
    quote.is_none()
}

#[cfg(test)]
#[path = "contained_output_filters_tests.rs"]
mod tests;
