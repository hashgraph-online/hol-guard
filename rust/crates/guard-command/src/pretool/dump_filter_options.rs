//! The option lines of the filters that dump or page what they read.
//!
//! These tools print a rendering of their input and have no option that
//! names a file to write — except the ones named here, which are refused by
//! omission: `shuf -o`, `iconv -o`, and the second operand `xxd` truncates.

/// The `strings` options that carry no value.
const STRINGS_READING_FLAGS: &str = "af";

/// `strings` prints the printable runs of what it reads. `-n`, `-t` and `-e`
/// name a length, a radix and an encoding. GNU `strings` also reads a leading
/// `@` operand as a file of further arguments rather than as input, so the
/// names it would then open are not in this command line; such an operand
/// keeps the command under review.
pub(super) fn safe_strings_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        STRINGS_READING_FLAGS,
        "nte",
        &["all", "print-file-name"],
        &["bytes", "radix", "encoding"],
    ) && operands.iter().all(|operand| !operand.starts_with('@'))
}

/// The `hexdump` options that carry no value: the output formats and the
/// repeat-line switch.
const HEXDUMP_READING_FLAGS: &str = "bcCdovx";

/// `hexdump` renders bytes. `-s` and `-n` bound the range and `-e` carries a
/// format string. `-f` names a format file Guard has not read, so the screen
/// leaves it out and the command stays under review.
pub(super) fn safe_hexdump_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        HEXDUMP_READING_FLAGS,
        "sne",
        &[
            "one-byte-octal",
            "one-byte-char",
            "canonical",
            "two-bytes-decimal",
            "two-bytes-octal",
            "two-bytes-hex",
            "no-squeezing",
        ],
        &["skip", "length", "format"],
    )
}

/// The `xxd` options that carry no value, spelled whole. `-ps`, `-plain` and
/// `-postscript` are `xxd`'s own spellings of `-p`: it reads a short option
/// as a whole word, never as a cluster, so reading `-ps` as `-p -s` would
/// hand the seek the word after it and skip the file that word names.
const XXD_READING_OPTIONS: &[&str] = &[
    "-a",
    "-b",
    "-E",
    "-e",
    "-i",
    "-p",
    "-ps",
    "-plain",
    "-postscript",
    "-r",
    "-u",
];

/// The `xxd` options that carry a column count, a group size, a length, a
/// display offset and a seek — all numbers, attached or as the next word.
const XXD_VALUE_OPTIONS: &[&str] = &["-c", "-g", "-l", "-o", "-s"];

/// `xxd` writes its dump to a second operand, so only one operand is proven
/// here; the caller caps it. Every option is matched whole: a spelling this
/// screen has not read keeps the command under review rather than being read
/// as a cluster `xxd` would never split that way.
pub(super) fn safe_xxd_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
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
        if !value.starts_with('-') || value == "-" {
            operands.push(value);
            continue;
        }
        if XXD_READING_OPTIONS.contains(&value) {
            continue;
        }
        let Some(option) = XXD_VALUE_OPTIONS
            .iter()
            .find(|option| value.starts_with(*option))
        else {
            return false;
        };
        let attached = &value[option.len()..];
        if attached.is_empty() {
            expecting_value = true;
            continue;
        }
        if !super::stdin_filter_options::safe_filter_value(attached) {
            return false;
        }
    }
    !expecting_value
}

/// The `pr` options that carry no value, plus the digits of the column count
/// `pr` spells as `-COLUMN`. `-s` is here rather than among the value flags
/// because its separator is attached (`-s,`) and optional: reading it as a
/// flag that takes the next word would eat the file that word names.
const PR_READING_FLAGS: &str = "adFfJmrstT0123456789";

/// `pr` pages what it reads for printing. `-h` carries the header text, `-l`
/// and `-w` the page geometry, and `-o` the left margin — a count, not a file
/// to write.
pub(super) fn safe_pr_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        PR_READING_FLAGS,
        "hlow",
        &["show-control-chars", "omit-header", "merge", "join-lines"],
        &["header", "length", "width", "indent"],
    )
}

/// The `shuf` options that carry no value.
const SHUF_READING_FLAGS: &str = "rz";

/// `shuf` reorders the lines of what it reads. `-n` bounds the output.
/// `-o`/`--output` writes a file and `--random-source` reads one Guard has
/// not proven, so neither is named here.
pub(super) fn safe_shuf_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        SHUF_READING_FLAGS,
        "n",
        &["repeat", "zero-terminated"],
        &["head-count"],
    )
}

/// The `iconv` options that carry no value.
const ICONV_READING_FLAGS: &str = "cs";

/// `iconv` re-encodes what it reads. `-f` and `-t` name character sets.
/// `-o`/`--output` writes a file, so it is left out and keeps the command
/// under review.
pub(super) fn safe_iconv_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        ICONV_READING_FLAGS,
        "ft",
        &["verbose"],
        &["from-code", "to-code"],
    )
}
