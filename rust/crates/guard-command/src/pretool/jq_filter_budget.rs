//! Limits on how much work one jq filter check may do.
//!
//! The grammar reads a filter by trying several splits of each part, and the
//! programs it admits may call `range`. Both are bounded per call, so these
//! limits stop a short filter from multiplying them: nested calls that each
//! retry their argument, or stacked `range` calls whose outputs multiply.

use std::cell::Cell;

use super::program;

/// How many stages and pipelines one filter may ask the grammar to read.
/// The splitters try several readings of a part, so a short filter of
/// nested calls could otherwise multiply the work at every level.
const MAX_STEPS: usize = 20_000;

thread_local! {
    static STEPS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn reset() {
    STEPS.with(|steps| steps.set(0));
}

/// Counts one step, and `false` once the filter has used its budget.
pub(super) fn spend() -> bool {
    STEPS.with(|steps| {
        let used = steps.get().saturating_add(1);
        steps.set(used);
        used <= MAX_STEPS
    })
}

/// Each admitted `range` call has its own emission bound. Refuse a filter with
/// multiple calls after definitions are inlined, so composition cannot multiply
/// those per-call bounds.
pub(super) fn range_budget(program: &str) -> bool {
    let mut calls = 0usize;
    range_calls_within_budget(program, &mut calls)
}

fn range_calls_within_budget(program: &str, calls: &mut usize) -> bool {
    let bytes = program.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let Some(end) = super::string_end(bytes, index) else {
                return false;
            };
            let mut inner = index + 1;
            while inner < end {
                if bytes[inner] == b'\\' && bytes.get(inner + 1) == Some(&b'(') {
                    let Some(close) = super::interpolation_end(bytes, inner + 1) else {
                        return false;
                    };
                    if !range_calls_within_budget(&program[inner + 2..close], calls) {
                        return false;
                    }
                    inner = close + 1;
                } else if bytes[inner] == b'\\' {
                    inner += 2;
                } else {
                    inner += 1;
                }
            }
            index = end + 1;
            continue;
        }
        if program::keyword(bytes, index, "range") {
            let end = index + "range".len();
            let mut next = end;
            while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                next += 1;
            }
            if bytes.get(next) == Some(&b'(') {
                *calls += 1;
                if *calls > 1 {
                    return false;
                }
            }
            index = end;
        } else {
            index += 1;
        }
    }
    true
}
