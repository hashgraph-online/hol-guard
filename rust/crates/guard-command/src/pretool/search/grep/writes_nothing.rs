//! Whether a segment of a command can put a file where a missing search root
//! is. The screen above asks it before it admits a root nothing is at, so the
//! answer has to hold for every program the segment can start.

use crate::CommandSegmentV1;

/// A peer that cannot create a filesystem entry: no output redirect beyond
/// `/dev/null`, and a program that only changes directory, prints, or opens
/// paths to read them. `ln -s <dir> <repo>/cfg && grep -rn . <repo>/cfg/` is
/// the shape this refuses, because `ln` puts a tree where the proof measured
/// nothing. `grep -rln needle app; cat notes.md` is the shape it admits: an
/// agent sweeps for a name it guessed at and prints a file it knows is there,
/// and without the redirect already refused above, `cat` can no more create
/// the missing root than `cd` or `echo` can.
pub(in crate::pretool) fn creates_nothing(segment: &CommandSegmentV1) -> bool {
    let text = ["2>&1", "2>/dev/null", ">/dev/null"]
        .iter()
        .fold(segment.text.clone(), |text, quiet| text.replace(quiet, ""));
    if text.contains('>') || !segment.wrapper_chain.is_empty() || segment.path_overridden {
        return false;
    }
    match segment.executable.as_deref() {
        Some("cd") => true,
        Some(executable) => {
            reads_only(executable)
                || pathless_builtin(executable)
                || (segment.pipeline_index > 0
                    && crate::pretool::segment_proof::stdin_filter_segment(segment))
        }
        None => false,
    }
}

/// A program that opens the paths it is given only to read them, and writes
/// what it finds to standard output. None of them takes an option that names
/// a file to write, so the redirect screen above is the whole write surface.
///
/// That last condition is what keeps the list short rather than the reading
/// itself. `sed` and `awk` read a named file and print it, but `sed -i` and
/// `print > "name"` both put bytes on disk; `sort -o`, `uniq OUT`, macOS
/// `base64 -o` and `file -C` each name an output file as an ordinary operand
/// or option. A command whose write surface is wider than the redirect screen
/// does not belong here even when the spelling in hand only reads.
fn reads_only(executable: &str) -> bool {
    matches!(
        executable,
        "basename"
            | "cat"
            | "cut"
            | "diff"
            | "dirname"
            | "du"
            | "echo"
            | "egrep"
            | "fgrep"
            | "grep"
            | "head"
            | "jq"
            | "ls"
            | "nl"
            | "printf"
            | "pwd"
            | "readlink"
            | "realpath"
            | "rg"
            | "stat"
            | "tail"
            | "test"
            | "tr"
            | "true"
            | "wc"
    )
}

/// A program that writes nothing and opens no path: its operands are words it
/// prints or compares, never names it creates. Without a redirect, which the
/// caller has already refused, it cannot put an entry where a missing root is.
fn pathless_builtin(executable: &str) -> bool {
    matches!(
        crate::pretool::executable_basename(executable),
        "echo" | "printf" | "pwd" | "true" | "false" | ":"
    )
}
