//! The `sort` option screen.
//!
//! `sort` reshapes what it reads and prints the result, but it is the one
//! filter in this family with a rich option grammar: a key definition, a
//! field separator, a buffer size and a parallelism count each carry a value
//! that must not be mistaken for a file to read, and its writing options
//! (`-o`, `-T`, `--compress-program`) must stay out. That grammar is long
//! enough to read on its own, so it sits beside `stdin_filters` rather than
//! inside it.

/// The `sort` options that carry no value. Its one writing option is
/// `-o`/`--output`; `-T`/`--temporary-directory` names a directory Guard has
/// not read and `--compress-program` hands the run to another program, so the
/// screen names the reading options instead of allowing every leading dash.
const SORT_READING_FLAGS: &str = "bCcdfghiMmnrsuVz";

/// `sort` reshapes what it reads and writes only to standard output. `-k`,
/// `-t`, `-S` and the long `--key`, `--field-separator`, `--buffer-size` and
/// `--parallel` take a value, attached or as the next word, so a key
/// definition or a field separator is not mistaken for a file to read.
pub(super) fn safe_sort_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
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
