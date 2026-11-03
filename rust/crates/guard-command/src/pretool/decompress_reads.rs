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
const GZIP_READING_FLAGS: &str = "fqvrtlnN";

/// The `bzcat` options that carry no value.
const BZIP2_READING_FLAGS: &str = "sqvfk";

/// The `xzcat`/`lzcat` options that carry no value.
const XZ_READING_FLAGS: &str = "qvQ";

/// The `zstdcat` options that carry no value. `-D` names a dictionary file,
/// and `-o` names one to write, so neither is here.
const ZSTD_READING_FLAGS: &str = "qvfk";

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
            "S",
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
            &["suffix"],
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
        "zstdcat" => super::stdin_filter_options::screen_options(
            arguments,
            operands,
            ZSTD_READING_FLAGS,
            "TM",
            &[
                "quiet",
                "verbose",
                "force",
                "keep",
                "decompress",
                "stdout",
                "no-check",
            ],
            &["threads", "memory", "memlimit", "format"],
        ),
        _ => false,
    }
}
