//! The marker a running process leaves inside a repository's own hidden
//! tree: a lock directory's pid, a dev server's port, a deploy sentinel's
//! generation. The read rule for one is narrow on purpose, so it lives apart
//! from the listing rules that admit the directory around it.

use std::path::Path;

/// The largest marker file this reading opens. A process identifier, a port
/// number and a lock's generation all fit in a line; a file larger than that
/// is holding something other than a marker.
const LONGEST_MARKER_FILE: usize = 64;

/// The longest number a marker holds. A pid, a port and a generation are all
/// well inside ten digits. Twenty bytes of digits is no process marker: it is
/// a card or account number, a recovery code, or a key written in decimal.
const LONGEST_MARKER_NUMBER: usize = 20;

/// The leaf names a process writes a marker to.
const MARKER_NAMES: [&str; 5] = ["pid", "pidfile", "port", "generation", "lock"];

/// The suffixes a marker carries when the name says what it belongs to,
/// as in `server.pid` or `vite.port`.
const MARKER_SUFFIXES: [&str; 4] = [".pid", ".pidfile", ".port", ".lock"];

/// Whether `canonical` is named the way a process names the marker it leaves.
///
/// Content alone cannot carry this rule. A PIN, a TOTP, a recovery code and a
/// 128-bit key written in decimal are all small runs of digits, so a file is
/// a marker because of where it sits and what it is called, not because the
/// number inside it looks plain.
fn marker_file_name(canonical: &Path) -> bool {
    let Some(name) = canonical.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    MARKER_NAMES.contains(&name.as_str())
        || MARKER_SUFFIXES
            .iter()
            .any(|suffix| name.len() > suffix.len() && name.ends_with(suffix))
}

/// Whether `canonical` is a marker file a running process left behind: a
/// small regular file, named for a marker, holding one number.
///
/// A lock directory holds the pid of whoever took it, a dev server writes its
/// port beside its state, and a deploy sentinel records the generation it is
/// on. None of them carries a document extension, so that screen refuses them
/// all, and an agent that asks who holds a lock is doing ordinary work.
///
/// The name and the number are both the proof, and neither stands alone. The
/// read is bounded at the source, so a file that grows or is replaced between
/// the size check and the read is refused rather than opened: the bound is on
/// what is read here, not a promise about what the command will see. The
/// output review repeats this rule and scans the file again.
pub(super) fn numeric_marker_file(canonical: &Path) -> bool {
    if !marker_file_name(canonical) {
        return false;
    }
    let Ok(read) = guard_secure_fs::read_bounded(canonical, LONGEST_MARKER_FILE) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&read.bytes) else {
        return false;
    };
    let value = text.trim();
    !value.is_empty()
        && value.len() <= LONGEST_MARKER_NUMBER
        && value.bytes().all(|byte| byte.is_ascii_digit())
}
