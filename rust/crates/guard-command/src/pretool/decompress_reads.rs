//! The viewers that decompress straight to standard output.
//!
//! `zcat` and its siblings are the decompressor's `--stdout` mode under a
//! fixed name: each prints what it reads and none of them has an option that
//! names a file to write. What one does to a file is what `cat` does to it,
//! so the operand goes through the same bounded, sensitive-path-aware read
//! proof.
//!
//! The decompressors' own names are deliberately absent. `gunzip`, `bunzip2`,
//! `unxz` and `zstd` replace the file they read unless `--stdout` is spelled,
//! and `zstd -o` and `xz --files` name further files, so those spellings keep
//! the command under review.

/// The `zcat`/`gzcat` options that carry no value. `-l` lists a member table
/// and `-t` tests integrity; both only print.
///
/// `-S`/`--suffix` is deliberately absent. When the operand names nothing,
/// gzip retries the name with a suffix appended, and the suffix `-S` carries
/// is the first one it tries, so `zcat -f --suffix=nv .e` opens `.env` while
/// the read proof only ever saw `.e`. Refusing the option keeps the file gzip
/// opens within one of the fixed compression suffixes of the proven operand.
const GZIP_READING_FLAGS: &str = "fqvrtlnN";

/// The `bzcat` options that carry no value.
const BZIP2_READING_FLAGS: &str = "sqvfk";

/// The `xzcat`/`lzcat` options that carry no value.
const XZ_READING_FLAGS: &str = "qvQ";

/// The `zstdcat` options that carry no value. `-D` names a dictionary file,
/// and `-o` names one to write, so neither is here.
const ZSTD_READING_FLAGS: &str = "qvfk";

/// `zstd` reads the number for `-T` and `-M` out of the same word (`-T4`,
/// `-M32MB`) rather than off the next one, unlike the `xz` options spelled
/// the same way. Screening them as flags that take the next word would hand
/// `zstdcat -T report.gz` its own operand and leave nothing proven read.
const ZSTD_ATTACHED_VALUE_FLAGS: &str = "TM";

/// The `zstdcat` long options that carry no value.
const ZSTD_READING_LONG: &[&str] = &[
    "quiet",
    "verbose",
    "force",
    "keep",
    "decompress",
    "stdout",
    "to-stdout",
    "no-check",
];

/// The `zstdcat` long options that carry a thread count or a memory bound.
const ZSTD_NUMBER_LONG: &[&str] = &["threads", "memory", "memlimit", "memlimit-decompress"];

/// The compressed formats `zstd` reads. `--format` names one of them; it
/// never names a file.
const ZSTD_FORMATS: &[&str] = &["zstd", "gzip", "xz", "lzma", "lz4"];

/// The value `zstd` takes out of the same word for `-T` and `-M`. `zstd`
/// stops at the digits and parses whatever is left in the word as further
/// flags, so `-To decoded.txt` is `-T` followed by the `-o` that names a file
/// to write — a value the generic screen would have read as harmless text.
/// Only a plain count with one of `zstd`'s size suffixes is read here.
fn zstd_number(value: &str) -> bool {
    let suffix = value.trim_start_matches(|character: char| character.is_ascii_digit());
    value.len() > suffix.len() && matches!(suffix, "" | "K" | "M" | "KB" | "MB" | "KiB" | "MiB")
}

/// One `zstdcat` short cluster. A flag the screen has not read, and an
/// attached value that is not a plain count, keep the command under review.
fn zstd_short_cluster(cluster: &str) -> bool {
    let mut characters = cluster.chars();
    while let Some(flag) = characters.next() {
        if ZSTD_READING_FLAGS.contains(flag) {
            continue;
        }
        if !ZSTD_ATTACHED_VALUE_FLAGS.contains(flag) {
            return false;
        }
        return zstd_number(characters.as_str());
    }
    !cluster.is_empty()
}

/// `zstdcat`'s option line. It is screened here rather than by the shared
/// filter screen because `zstd` parses its short options itself: the rest of
/// a word after `-T` or `-M` is more flags once the digits run out, not the
/// flag's value.
fn zstd_arguments<'a>(arguments: &'a [String], operands: &mut Vec<&'a str>) -> bool {
    let mut after_options = false;
    for argument in arguments {
        let value = argument.as_str();
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
            match (name, attached) {
                (name, None) if ZSTD_READING_LONG.contains(&name) => continue,
                (name, Some(attached))
                    if ZSTD_NUMBER_LONG.contains(&name) && zstd_number(attached) =>
                {
                    continue
                }
                ("format", Some(attached)) if ZSTD_FORMATS.contains(&attached) => continue,
                _ => return false,
            }
        }
        if !zstd_short_cluster(&value[1..]) {
            return false;
        }
    }
    true
}

/// Whether this name is one of the fixed decompress-to-stdout viewers.
pub(super) fn decompress_viewer(tool: &str) -> bool {
    matches!(
        tool,
        "zcat" | "gzcat" | "bzcat" | "xzcat" | "lzcat" | "zstdcat"
    )
}

/// One viewer's option line. A name this screen does not know proves nothing
/// and keeps the command under review.
pub(super) fn decompress_arguments<'a>(
    tool: &str,
    arguments: &'a [String],
    operands: &mut Vec<&'a str>,
) -> bool {
    match tool {
        "zcat" | "gzcat" => super::stdin_filter_options::screen_options(
            arguments,
            operands,
            GZIP_READING_FLAGS,
            "",
            &[
                "force",
                "quiet",
                "verbose",
                "recursive",
                "list",
                "test",
                "no-name",
                "name",
                "keep",
                "decompress",
                "stdout",
                "to-stdout",
            ],
            &[],
        ),
        "bzcat" => super::stdin_filter_options::screen_options(
            arguments,
            operands,
            BZIP2_READING_FLAGS,
            "",
            &[
                "small",
                "quiet",
                "verbose",
                "force",
                "keep",
                "decompress",
                "stdout",
            ],
            &[],
        ),
        "xzcat" | "lzcat" => super::stdin_filter_options::screen_options(
            arguments,
            operands,
            XZ_READING_FLAGS,
            "TM",
            &[
                "quiet",
                "verbose",
                "no-warn",
                "robot",
                "keep",
                "force",
                "decompress",
                "stdout",
                "single-stream",
                "ignore-check",
            ],
            &[
                "threads",
                "memlimit",
                "memlimit-decompress",
                "format",
                "check",
            ],
        ),
        "zstdcat" => zstd_arguments(arguments, operands),
        _ => false,
    }
}
