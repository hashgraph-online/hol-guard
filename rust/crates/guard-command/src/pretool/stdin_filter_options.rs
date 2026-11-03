//! The option lines of the filters that lay out what they read.
//!
//! Each screen names the options it has read: the flags that carry no value,
//! the flags that do, and the long options spelled either way. An option the
//! screen has not read is refused, so a new spelling keeps the command under
//! review rather than slipping past as an operand.

/// The value a key, separator, field number or width carries. It describes
/// how to order or lay out the input rather than naming anything to open, so
/// a short literal is admitted and an expansion is not.
pub(super) fn safe_filter_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && !value.contains(['$', '`', '\\', '\'', '"'])
        && value
            .chars()
            .all(|character| character == '\t' || !character.is_control())
}

/// The `paste` options that carry no value. Every operand is a file it reads;
/// the output only ever goes to standard output.
const PASTE_READING_FLAGS: &str = "sz";

/// `paste` lays the lines of its inputs side by side. `-d` carries the
/// delimiter list, attached or as the next word.
pub(super) fn safe_paste_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    screen_options(
        arguments,
        operands,
        PASTE_READING_FLAGS,
        "d",
        &["serial", "zero-terminated"],
        &["delimiters"],
    )
}

/// The `join` options that carry no value.
const JOIN_READING_FLAGS: &str = "iz";

/// Every `join` option that takes a value names a field, a separator, a side
/// or an output format — never a file to write.
pub(super) fn safe_join_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    screen_options(
        arguments,
        operands,
        JOIN_READING_FLAGS,
        "12jtaveo",
        &[
            "ignore-case",
            "zero-terminated",
            "check-order",
            "nocheck-order",
            "header",
        ],
        &["field", "field-separator", "output-delimiter"],
    )
}

/// The `column` options that carry no value.
const COLUMN_READING_FLAGS: &str = "tx";

/// `column` lays its input out in columns. `-s` carries the input separator
/// and `-o` the output one — both are text it prints between fields, not a
/// file it opens.
pub(super) fn safe_column_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    screen_options(
        arguments,
        operands,
        COLUMN_READING_FLAGS,
        "scoN",
        &["table"],
        &[
            "separator",
            "output-separator",
            "output-width",
            "table-columns",
        ],
    )
}

/// One filter's option line: the flags that carry no value, the flags that
/// do, and the long options spelled either way. Anything else is refused, so
/// an option this screen has not read keeps the command under review.
fn screen_options<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
    reading_flags: &str,
    value_flags: &str,
    reading_long: &[&str],
    value_long: &[&str],
) -> bool {
    let mut after_options = false;
    let mut expecting_value = false;
    for argument in arguments {
        let value = argument.as_str();
        if expecting_value {
            if !safe_filter_value(value) {
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
            let (name, attached) = match long.split_once('=') {
                Some((name, attached)) => (name, Some(attached)),
                None => (long, None),
            };
            if value_long.contains(&name) {
                match attached {
                    Some(attached) => {
                        if !safe_filter_value(attached) {
                            return false;
                        }
                    }
                    None => expecting_value = true,
                }
                continue;
            }
            if reading_long.contains(&name) && attached.is_none() {
                continue;
            }
            return false;
        }
        if !screen_short_flags(
            &value[1..],
            reading_flags,
            value_flags,
            &mut expecting_value,
        ) {
            return false;
        }
    }
    !expecting_value
}

/// One short cluster. A value-taking flag ends the cluster: the rest of the
/// word is its value, or the next word is when nothing follows it.
pub(super) fn screen_short_flags(
    cluster: &str,
    reading_flags: &str,
    value_flags: &str,
    expecting_value: &mut bool,
) -> bool {
    if cluster.is_empty() {
        return false;
    }
    let mut characters = cluster.chars();
    while let Some(flag) = characters.next() {
        if reading_flags.contains(flag) {
            continue;
        }
        if !value_flags.contains(flag) {
            return false;
        }
        let attached = characters.as_str();
        if attached.is_empty() {
            *expecting_value = true;
            return true;
        }
        return safe_filter_value(attached);
    }
    true
}
