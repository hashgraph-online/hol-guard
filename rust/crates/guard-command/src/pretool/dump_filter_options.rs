//! The option lines of the filters that dump or page what they read.
//!
//! These tools print a rendering of their input and have no option that
//! names a file to write — except the ones named here, which are refused by
//! omission: `shuf -o`, `iconv -o`, and the second operand `xxd` truncates.

/// The `strings` options that carry no value.
const STRINGS_READING_FLAGS: &str = "af";

/// `strings` prints the printable runs of what it reads. `-n`, `-t` and `-e`
/// name a length, a radix and an encoding.
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
    )
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

/// The `xxd` options that carry no value.
const XXD_READING_FLAGS: &str = "abEeipru";

/// `xxd` writes its dump to a second operand, so only one operand is proven
/// here; the caller caps it. `-c`, `-g`, `-l`, `-o` and `-s` carry a column
/// count, a group size, a length, a display offset and a seek — all numbers.
pub(super) fn safe_xxd_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        XXD_READING_FLAGS,
        "cglos",
        &[],
        &[],
    )
}

/// The `pr` options that carry no value.
const PR_READING_FLAGS: &str = "adFfJmrtT";

/// `pr` pages what it reads for printing. `-h` carries the header text, `-l`
/// and `-w` the page geometry, and `-o` the left margin — a count, not a file
/// to write. A bare digit cluster is the column count.
pub(super) fn safe_pr_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        PR_READING_FLAGS,
        "hlows",
        &["show-control-chars", "omit-header", "merge", "join-lines"],
        &["header", "length", "width", "indent", "separator-char"],
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
