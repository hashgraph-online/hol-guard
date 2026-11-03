//! Text filters that read their input rather than change anything.
//!
//! After a pipe these filters only reshape the proven producer's output, so
//! the options alone are screened. Given a file operand they open that file,
//! which is the ordinary read `cat` proves, so each operand takes the same
//! read proof. `tr` never opens a file: every operand is a character set.
//! `uniq` is the exception that writes — `uniq INPUT OUTPUT` truncates the
//! second operand — so only a single operand is proven for it.

/// Enough operands for an ordinary command line, not a fan-out.
const MAX_INPUTS: usize = 16;

pub(super) fn safe_arguments(tool: &str, arguments: &[String]) -> bool {
    match tool {
        "sort" => {
            let mut operands: Vec<&str> = Vec::new();
            safe_sort_arguments(arguments, &mut operands) && operands.is_empty()
        }
        "uniq" => arguments
            .iter()
            .all(|argument| short_flags(argument, "cdui")),
        "cut" => safe_cut_arguments(arguments),
        "tr" => safe_tr_arguments(arguments),
        "base64" => safe_base64_arguments(arguments),
        _ => false,
    }
}

fn short_flags(value: &str, allowed: &str) -> bool {
    value
        .strip_prefix('-')
        .is_some_and(|flags| !flags.is_empty() && flags.chars().all(|flag| allowed.contains(flag)))
}

/// `tr` never opens a file: every operand is a character set. Only the set
/// options are admitted and at most two sets follow them.
fn safe_tr_arguments(arguments: &[String]) -> bool {
    let mut sets = 0;
    let mut after_options = false;
    for argument in arguments {
        if !after_options && argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options && argument.starts_with('-') && argument.len() > 1 {
            if !(short_flags(argument, "cCdst")
                || matches!(
                    argument.as_str(),
                    "--complement" | "--delete" | "--squeeze-repeats" | "--truncate-set1"
                ))
            {
                return false;
            }
            continue;
        }
        sets += 1;
    }
    (1..=2).contains(&sets)
}

/// `base64` over standard input, writing only to stdout. Any operand or
/// `-i`/`-o` names a file (BSD spells input and output that way), so neither
/// is admitted; only decode, garbage and line-wrap options are.
fn safe_base64_arguments(arguments: &[String]) -> bool {
    let wrap = |value: &str| {
        !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
    };
    let mut pending_wrap = false;
    for argument in arguments {
        if pending_wrap {
            if !wrap(argument) {
                return false;
            }
            pending_wrap = false;
            continue;
        }
        match argument.as_str() {
            "-d" | "-D" | "--decode" | "--ignore-garbage" => {}
            "-w" | "-b" => pending_wrap = true,
            other => {
                let value = other
                    .strip_prefix("--wrap=")
                    .or_else(|| other.strip_prefix("--break="))
                    .or_else(|| other.strip_prefix("-w"))
                    .or_else(|| other.strip_prefix("-b"));
                if !value.is_some_and(wrap) {
                    return false;
                }
            }
        }
    }
    !pending_wrap
}

fn safe_cut_arguments(arguments: &[String]) -> bool {
    let mut operands = Vec::new();
    cut_arguments(arguments, &mut operands) && operands.is_empty()
}

/// `cut`'s option grammar, collecting the file operands it was given.
fn cut_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    let mut selection = None;
    let mut delimiter = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if matches!(argument.as_str(), "-s" | "-n") {
            index += 1;
            continue;
        }
        let Some(option) = argument.strip_prefix('-') else {
            operands.push(argument.as_str());
            index += 1;
            continue;
        };
        let mut chars = option.chars();
        let Some(flag) = chars.next() else {
            return false;
        };
        if !matches!(flag, 'b' | 'c' | 'f' | 'd') {
            return false;
        }
        let attached = chars.as_str();
        let value = if attached.is_empty() {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return false;
            };
            value.as_str()
        } else {
            attached
        };
        if flag == 'd' {
            if delimiter || !single_delimiter(value) {
                return false;
            }
            delimiter = true;
        } else {
            if selection.is_some() || !bounded_selection(value) {
                return false;
            }
            selection = Some(flag);
        }
        index += 1;
    }
    selection.is_some() && (!delimiter || selection == Some('f'))
}

fn bounded_selection(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let number = |text: &str| {
        (!text.is_empty() && text.len() <= 6 && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u32>().ok())
            .flatten()
            .filter(|number| *number > 0)
    };
    value.split(',').all(|part| {
        if let Some((start, end)) = part.split_once('-') {
            if start.is_empty() && end.is_empty() {
                return false;
            }
            let start = if start.is_empty() {
                Some(1)
            } else {
                number(start)
            };
            let end = if end.is_empty() {
                Some(u32::MAX)
            } else {
                number(end)
            };
            matches!((start, end), (Some(start), Some(end)) if start <= end)
        } else {
            number(part).is_some()
        }
    })
}

/// The same filters given a file operand instead of a pipe. Every operand is
/// opened for reading, so every operand takes the ordinary read proof.
pub(super) fn safe_file_arguments(
    tool: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let mut operands: Vec<&str> = Vec::new();
    let options_proven = match tool {
        "sort" => safe_sort_arguments(arguments, &mut operands),
        "uniq" => partition_short_flags(arguments, "cdui", &mut operands),
        "cut" => cut_arguments(arguments, &mut operands),
        _ => false,
    };
    let maximum = if tool == "uniq" { 1 } else { MAX_INPUTS };
    options_proven
        && !operands.is_empty()
        && operands.len() <= maximum
        && operands
            .iter()
            .all(|operand| super::safe_reads::command_read_target(operand, context, false))
}

/// One delimiter character. A tab is the separator tabular output really
/// carries, and the shell writes it out before Guard reads the word — `-d
/// $'\t'` and a quoted tab both arrive here as the character itself — so it
/// is admitted by name while the other control characters stay out.
fn single_delimiter(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(character) = characters.next() else {
        return false;
    };
    characters.next().is_none() && (character == '\t' || !character.is_control())
}

/// The `sort` options that carry no value. Its one writing option is
/// `-o`/`--output`; `-T`/`--temporary-directory` names a directory Guard has
/// not read and `--compress-program` hands the run to another program, so the
/// screen names the reading options instead of allowing every leading dash.
const SORT_READING_FLAGS: &str = "bCcdfghiMmnrsuVz";

/// The value a `sort` key, separator, buffer size or worker count carries.
/// It describes how to order the input rather than naming anything to open,
/// so a short literal is admitted and an expansion is not.
fn safe_sort_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && !value.contains(['$', '`', '\\', '\'', '"'])
        && value
            .chars()
            .all(|character| character == '\t' || !character.is_control())
}

/// `sort` reshapes what it reads and writes only to standard output. `-k`,
/// `-t`, `-S` and the long `--key`, `--field-separator`, `--buffer-size` and
/// `--parallel` take a value, attached or as the next word, so a key
/// definition or a field separator is not mistaken for a file to read.
fn safe_sort_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    let mut after_options = false;
    let mut expecting_value = false;
    for argument in arguments {
        let value = argument.as_str();
        if expecting_value {
            if !safe_sort_value(value) {
                return false;
            }
            expecting_value = false;
            continue;
        }
        if after_options || !value.starts_with('-') || value == "-" {
            operands.push(value);
            continue;
        }
        if value == "--" {
            after_options = true;
            continue;
        }
        if let Some(long) = value.strip_prefix("--") {
            if !safe_sort_long_option(long, &mut expecting_value) {
                return false;
            }
            continue;
        }
        if !safe_sort_short_flags(&value[1..], &mut expecting_value) {
            return false;
        }
    }
    !expecting_value
}

/// One long `sort` option, with its value attached by `=` or still to come.
fn safe_sort_long_option(long: &str, expecting_value: &mut bool) -> bool {
    let (name, attached) = match long.split_once('=') {
        Some((name, attached)) => (name, Some(attached)),
        None => (long, None),
    };
    match name {
        "key" | "field-separator" | "buffer-size" | "parallel" => match attached {
            Some(attached) => safe_sort_value(attached),
            None => {
                *expecting_value = true;
                true
            }
        },
        // `--check` reports on its own; `--sort` always carries its word.
        "check" => true,
        "sort" => attached.is_some_and(safe_sort_value),
        "ignore-leading-blanks"
        | "dictionary-order"
        | "ignore-case"
        | "general-numeric-sort"
        | "ignore-nonprinting"
        | "month-sort"
        | "human-numeric-sort"
        | "numeric-sort"
        | "reverse"
        | "stable"
        | "unique"
        | "version-sort"
        | "zero-terminated"
        | "merge"
        | "debug" => attached.is_none(),
        _ => false,
    }
}

/// One short `sort` cluster. A value-taking flag ends the cluster: the rest of
/// the word is its value, or the next word is when nothing follows it.
fn safe_sort_short_flags(cluster: &str, expecting_value: &mut bool) -> bool {
    if cluster.is_empty() {
        return false;
    }
    let mut characters = cluster.chars();
    while let Some(flag) = characters.next() {
        if SORT_READING_FLAGS.contains(flag) {
            continue;
        }
        if !matches!(flag, 'k' | 't' | 'S') {
            return false;
        }
        let attached = characters.as_str();
        if attached.is_empty() {
            *expecting_value = true;
            return true;
        }
        return safe_sort_value(attached);
    }
    true
}

/// Split a short-flag command line into its flags and its file operands.
fn partition_short_flags<'a>(
    arguments: &'a [String],
    allowed: &str,
    operands: &mut Vec<&'a str>,
) -> bool {
    let mut after_options = false;
    for argument in arguments {
        let value = argument.as_str();
        if after_options || !value.starts_with('-') {
            operands.push(value);
        } else if value == "--" {
            after_options = true;
        } else if !short_flags(value, allowed) {
            return false;
        }
    }
    true
}
