//! `dd` reading one bounded file to standard output.
//!
//! `dd if=FILE bs=N count=N skip=N` prints a slice of the file exactly like
//! `head -c` or `tail -c`, so the input goes through the same bounded,
//! sensitive-path-aware read proof. Any operand that names an output file,
//! converts, or seeks keeps review, which is what makes `dd` dangerous.

use super::safe_reads::command_read_target;
use super::search::SECRET_EXTENSIONS;

fn readable(value: &str, context: super::PathContext<'_>) -> bool {
    let extension = std::path::Path::new(value)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !value.starts_with('-')
        && !SECRET_EXTENSIONS.contains(&extension.as_str())
        && command_read_target(value, context, false)
}

/// The most one block may hold. `dd` allocates a buffer of the block size, so
/// the bound keeps a read from asking for gigabytes of memory.
const MAX_BLOCK_BYTES: u64 = 16 * 1024 * 1024;

/// A count: digits with at most one size suffix.
fn size(value: &str) -> Option<u64> {
    let (digits, unit) = match value.char_indices().last() {
        Some((index, 'c')) => (&value[..index], 1),
        Some((index, 'w')) => (&value[..index], 2),
        Some((index, 'b')) => (&value[..index], 512),
        Some((index, 'k' | 'K')) => (&value[..index], 1024),
        Some((index, 'M')) => (&value[..index], 1024 * 1024),
        Some((index, 'G')) => (&value[..index], 1024 * 1024 * 1024),
        _ => (value, 1),
    };
    if digits.is_empty() || digits.len() > 12 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

fn block_size(value: &str) -> bool {
    size(value).is_some_and(|bytes| bytes <= MAX_BLOCK_BYTES)
}

pub(super) fn safe_dd_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut input = false;
    for argument in arguments {
        let Some((name, value)) = argument.split_once('=') else {
            return false;
        };
        let accepted = match name {
            "if" if !input && readable(value, context) => {
                input = true;
                true
            }
            "bs" | "ibs" => block_size(value),
            "count" | "skip" => size(value).is_some(),
            "status" => matches!(value, "none" | "noxfer"),
            _ => false,
        };
        if !accepted {
            return false;
        }
    }
    input
}

/// A whole `dd` segment that the native proof accepts as a read. It writes
/// nothing, so the compatibility layer does not count it as a destructive
/// command or a write to the paths it names.
pub(crate) fn proven_read_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    // The same whole-command conditions `benign_command_segments` requires.
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && segment.executable.as_deref() == Some("dd")
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}
