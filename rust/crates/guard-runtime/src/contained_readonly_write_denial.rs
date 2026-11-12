//! Whether a read-only run's output names a write its profile denied, so
//! the sink can add its note.

/// Words a denied write leaves in a program's output.
const WRITE_DENIAL_MARKERS: [&[u8]; 4] = [
    b"eperm",
    b"erofs",
    b"operation not permitted",
    b"read-only file system",
];

/// Whether a run's output names a write the read-only profile denied, as a
/// word of its own.
pub(in super::super) fn names_denied_write(outputs: &[&[u8]]) -> bool {
    outputs.iter().any(|output| {
        let lowered = output.to_ascii_lowercase();
        WRITE_DENIAL_MARKERS.iter().any(|marker| {
            lowered
                .windows(marker.len())
                .enumerate()
                .any(|(start, window)| {
                    window == *marker
                        && !word_byte(start.checked_sub(1).map(|at| lowered[at]))
                        && !word_byte(lowered.get(start + marker.len()).copied())
                })
        })
    })
}

/// Whether `byte` would continue a word, so a marker beside it is only part
/// of a longer name such as `filePermissions`.
fn word_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
