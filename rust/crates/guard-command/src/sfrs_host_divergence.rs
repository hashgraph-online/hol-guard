//! Host-sensitive tolerance for recorded `secret_file_request_services` vectors.
//!
//! The vectors are recorded on macOS, so a handful observe host filesystem
//! facts: APFS case-insensitive lookups (`PR-BODY.MD`, `BUILD`), the
//! `/tmp -> /private/tmp` symlink, and the absence of `/bin/gh` and
//! `/bin/python3`. On macOS every vector must match exactly. Elsewhere a
//! mismatch is tolerated only when it names one of the listed host-sensitive
//! markers, and only up to the listed count; any other mismatch, or more
//! sensitive mismatches than recorded, still fails.

/// Removes tolerated host-sensitive mismatches from `failures`.
///
/// `sensitive` pairs a substring that identifies a host-sensitive vector with
/// the maximum number of mismatches it may produce off macOS.
pub(crate) fn portable_failures(failures: Vec<String>, sensitive: &[(&str, usize)]) -> Vec<String> {
    if cfg!(target_os = "macos") {
        return failures;
    }
    let mut seen = vec![0usize; sensitive.len()];
    let mut remaining = Vec::new();
    for failure in failures {
        match sensitive
            .iter()
            .position(|(marker, _)| failure.contains(marker))
        {
            Some(index) => {
                seen[index] += 1;
                if seen[index] > sensitive[index].1 {
                    remaining.push(failure);
                }
            }
            None => remaining.push(failure),
        }
    }
    remaining
}
