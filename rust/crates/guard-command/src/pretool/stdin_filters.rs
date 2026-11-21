//! Text filters that read their input rather than change anything.
//!
//! After a pipe these filters only reshape the proven producer's output, so
//! the options alone are screened. Given a file operand they open that file,
//! which is the ordinary read `cat` proves, so each operand takes the same
//! read proof. `tr` never opens a file: every operand is a character set.
//! `uniq` is the exception that writes — `uniq INPUT OUTPUT` truncates the
//! second operand — so only a single operand is proven for it.
//!
//! `paste`, `join` and `column` belong here for the same reason: each one
//! joins or lays out the columns of what it reads and has no option that
//! names a file to write.
//!
//! `ul` and `tsort` render what they read the same way, and the `zcat`
//! family does it through a decompressor. `numfmt` is not one of them: it
//! rewrites the numbers it is handed and opens no file, so it is screened by
//! `safe_number_arguments` rather than taking a read proof for an operand.
//!
//! `strings`, `hexdump`, `xxd`, `pr`, `shuf` and `iconv` belong here too:
//! each prints a rendering of what it reads. `xxd` is the second exception
//! that writes — `xxd INPUT OUTPUT` truncates its second operand — so only a
//! single operand is proven for it.
//!
//! `nl`, `tac`, `rev`, `fold`, `expand`, `unexpand`, `fmt` and `comm` number,
//! reverse, wrap, retab, reflow or compare the lines of what they read, and
//! none of them has an option that names a file to write either.

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
        "base64" | "base32" => safe_base64_arguments(arguments),
        "paste" => {
            let mut operands: Vec<&str> = Vec::new();
            super::stdin_filter_options::safe_paste_arguments(arguments, &mut operands)
                && stdin_operands(&operands)
        }
        "column" => {
            let mut operands: Vec<&str> = Vec::new();
            super::stdin_filter_options::safe_column_arguments(arguments, &mut operands)
                && operands.is_empty()
        }
        "nl" | "tac" | "rev" | "fold" | "expand" | "unexpand" | "fmt" => {
            let mut operands: Vec<&str> = Vec::new();
            layout_arguments(tool, arguments, &mut operands) && operands.is_empty()
        }
        "strings" | "hexdump" | "xxd" | "pr" | "shuf" | "iconv" | "ul" | "tsort" => {
            let mut operands: Vec<&str> = Vec::new();
            dump_arguments(tool, arguments, &mut operands) && operands.is_empty()
        }
        name if super::decompress_reads::decompress_viewer(name) => {
            let mut operands: Vec<&str> = Vec::new();
            super::decompress_reads::decompress_arguments(name, arguments, &mut operands)
                && operands.is_empty()
        }
        _ => false,
    }
}

/// The dump and paging filters, each with its own option line. A tool this
/// dispatcher does not name proves nothing and keeps the command under
/// review.
fn dump_arguments<'a>(tool: &str, arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    match tool {
        "strings" => super::dump_filter_options::safe_strings_arguments(arguments, operands),
        "hexdump" => super::dump_filter_options::safe_hexdump_arguments(arguments, operands),
        "xxd" => super::dump_filter_options::safe_xxd_arguments(arguments, operands),
        "pr" => super::dump_filter_options::safe_pr_arguments(arguments, operands),
        "shuf" => super::dump_filter_options::safe_shuf_arguments(arguments, operands),
        "ul" => super::dump_filter_options::safe_ul_arguments(arguments, operands),
        "tsort" => super::dump_filter_options::safe_tsort_arguments(arguments, operands),
        "numfmt" => super::dump_filter_options::safe_numfmt_arguments(arguments, operands),
        "iconv" => super::dump_filter_options::safe_iconv_arguments(arguments, operands),
        _ => false,
    }
}

/// One layout filter's option line. Each of these reshapes the lines of what
/// it reads; none of them has an option that names a file to write.
fn layout_arguments<'a>(tool: &str, arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    match tool {
        "nl" => super::stdin_filter_options::safe_nl_arguments(arguments, operands),
        "tac" => super::stdin_filter_options::safe_tac_arguments(arguments, operands),
        "rev" => super::stdin_filter_options::safe_rev_arguments(arguments, operands),
        "fold" => super::stdin_filter_options::safe_fold_arguments(arguments, operands),
        "expand" | "unexpand" => {
            super::stdin_filter_options::safe_expand_arguments(arguments, operands)
        }
        "fmt" => super::stdin_filter_options::safe_fmt_arguments(arguments, operands),
        "comm" => super::stdin_filter_options::safe_comm_arguments(arguments, operands),
        _ => false,
    }
}

/// `paste - -` reads standard input twice to pair its lines, so a dash is the
/// one operand a piped `paste` may carry.
fn stdin_operands(operands: &[&str]) -> bool {
    operands.iter().all(|operand| *operand == "-")
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

/// `base64` and `base32` over standard input, writing only to stdout. The two
/// carry the same option line. Any operand or `-i`/`-o` names a file (BSD
/// spells input and output that way), so neither is admitted; only decode,
/// garbage and line-wrap options are.
fn safe_base64_arguments(arguments: &[String]) -> bool {
    let wrap = super::base64_reads::safe_wrap_count;
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
/// `numfmt` rewrites the numbers it is handed and reads standard input when
/// it is handed none, so every operand is a number and none of them opens a
/// file. A word that is not one of the numbers `numfmt` scales keeps the
/// command under review rather than taking a read proof it never earns.
pub(super) fn safe_number_arguments(arguments: &[String]) -> bool {
    let mut operands: Vec<&str> = Vec::new();
    super::dump_filter_options::safe_numfmt_arguments(arguments, &mut operands)
        && operands.len() <= MAX_INPUTS
        && operands.iter().all(|operand| numeric_operand(operand))
}

/// One number as `numfmt` reads it: digits with at most one fraction, and one
/// of the unit letters it scales by, `i` marking the binary spellings. A sign
/// is left out because the screen reads a leading dash as an option.
fn numeric_operand(operand: &str) -> bool {
    let (number, suffix) =
        match operand.find(|character: char| !character.is_ascii_digit() && character != '.') {
            Some(index) => operand.split_at(index),
            None => (operand, ""),
        };
    let mut parts = number.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    parts.next().is_none()
        && !whole.is_empty()
        && fraction.is_none_or(|fraction| !fraction.is_empty())
        && matches!(
            suffix,
            "" | "K"
                | "M"
                | "G"
                | "T"
                | "P"
                | "E"
                | "Z"
                | "Y"
                | "R"
                | "Q"
                | "Ki"
                | "Mi"
                | "Gi"
                | "Ti"
                | "Pi"
                | "Ei"
                | "Zi"
                | "Yi"
                | "Ri"
                | "Qi"
        )
}

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
        "paste" => super::stdin_filter_options::safe_paste_arguments(arguments, &mut operands),
        "join" => super::stdin_filter_options::safe_join_arguments(arguments, &mut operands),
        "column" => super::stdin_filter_options::safe_column_arguments(arguments, &mut operands),
        "nl" | "tac" | "rev" | "fold" | "expand" | "unexpand" | "fmt" | "comm" => {
            layout_arguments(tool, arguments, &mut operands)
        }
        name if super::decompress_reads::decompress_viewer(name) => {
            super::decompress_reads::decompress_arguments(name, arguments, &mut operands)
        }
        other => dump_arguments(other, arguments, &mut operands),
    };
    let maximum = match tool {
        "uniq" => 1,
        // `join` pairs exactly two sorted inputs, and `comm` compares two.
        "join" | "comm" => 2,
        // `xxd INPUT OUTPUT` truncates the second operand.
        "xxd" => 1,
        _ => MAX_INPUTS,
    };
    // A file operand is opened, so it takes the read proof `cat` takes, and
    // that proof only holds against a verified home and working directory.
    // Without them the screen reads the spelling alone, which cannot tell a
    // plain name from a link to a secret. The stdin forms above are unaffected.
    super::safe_reads::verified_path_context(context.home_dir, context.cwd)
        && options_proven
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
            if !super::stdin_filter_options::safe_filter_value(value) {
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
            Some(attached) => super::stdin_filter_options::safe_filter_value(attached),
            None => {
                *expecting_value = true;
                true
            }
        },
        // `--check` reports on its own; `--sort` always carries its word.
        "check" => true,
        "sort" => attached.is_some_and(super::stdin_filter_options::safe_filter_value),
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

/// One short `sort` cluster, with `-k`, `-t` and `-S` as its value-taking
/// flags.
fn safe_sort_short_flags(cluster: &str, expecting_value: &mut bool) -> bool {
    super::stdin_filter_options::screen_short_flags(
        cluster,
        SORT_READING_FLAGS,
        "ktS",
        expecting_value,
    )
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
