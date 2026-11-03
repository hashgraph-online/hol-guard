//! The option lines of the filters that dump or page what they read.
//!
//! These tools print a rendering of their input and have no option that
//! names a file to write — except the ones named here, which are refused by
//! omission: `shuf -o`, `iconv -o`, and the second operand `xxd` truncates.

/// The `strings` options that carry no value.
const STRINGS_READING_FLAGS: &str = "af";

/// `strings` prints the printable runs of what it reads. `-n`, `-t` and `-e`
/// name a length, a radix and an encoding. GNU `strings` expands every
/// `@`-prefixed word of its command line — an option's value as readily as an
/// operand — into the arguments that file holds, so the names it would then
/// open are not in this command line. Any such word keeps the command under
/// review, and it is screened before the option line so a refusal leaves no
/// operand behind.
pub(super) fn safe_strings_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    if arguments.iter().any(|argument| argument.starts_with('@')) {
        return false;
    }
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
/// as a cluster `xxd` would never split that way. `xxd` also stops reading
/// options at its first operand, so a later `-p` is the output file it
/// truncates rather than a flag; once an operand is in hand every word after
/// it is an operand here too, and the caller's cap refuses the pair.
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
        if !operands.is_empty() || !value.starts_with('-') || value == "-" {
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
/// `pr` spells as `-COLUMN`.
const PR_READING_FLAGS: &str = "adFfJmrtT0123456789";

/// `pr -s` carries its separator attached (`-s,`) or takes the default when
/// nothing follows it, so it ends the cluster without reaching for the next
/// word. Reading it as a plain flag would let the rest of the cluster be read
/// as flags — `-sh` is the separator `h`, not `-s -h` — and a `-h` read there
/// would swallow the file the following word names.
const PR_OPTIONAL_VALUE_FLAGS: &str = "s";

/// `pr` pages what it reads for printing. `-h` carries the header text, `-l`
/// and `-w` the page geometry, and `-o` the left margin — a count, not a file
/// to write.
pub(super) fn safe_pr_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    super::stdin_filter_options::screen_options_with_optional(
        arguments,
        operands,
        PR_READING_FLAGS,
        "hlow",
        PR_OPTIONAL_VALUE_FLAGS,
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

/// The `ul` options that carry no value.
const UL_READING_FLAGS: &str = "i";

/// `ul` renders underlines for a terminal. `-t` names the terminal type.
pub(super) fn safe_ul_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        UL_READING_FLAGS,
        "t",
        &["indicated"],
        &["terminal"],
    )
}

/// `tsort` topologically sorts the pairs it reads and carries no option at
/// all, so every word is an operand.
pub(super) fn safe_tsort_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    super::stdin_filter_options::screen_options(arguments, operands, "", "", &[], &[])
}

/// The `numfmt` options that carry no value.
const NUMFMT_READING_FLAGS: &str = "z";

/// `numfmt` rewrites the numbers it prints. Every option that takes a value
/// names a unit, a field, a format or a delimiter. `--header` is admitted
/// only in its bare spelling: the screen cannot tell an attached count from
/// a value taken off the next word, and reading the operand as a count would
/// lose the file.
pub(super) fn safe_numfmt_arguments<'a>(
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    super::stdin_filter_options::screen_options(
        arguments,
        operands,
        NUMFMT_READING_FLAGS,
        "d",
        &["debug", "zero-terminated", "header"],
        &[
            "delimiter",
            "field",
            "format",
            "from",
            "from-unit",
            "to",
            "to-unit",
            "grouping",
            "invalid",
            "padding",
            "round",
            "suffix",
        ],
    )
}
