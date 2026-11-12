//! Pattern compilation for cloud action packs.
//!
//! Every pack pattern uses the linear-time `regex` engine with a size bound, so
//! a pack cannot ship a pattern that backtracks or compiles to a huge program.

const MAX_PATTERN_CHARS: usize = 512;
const MAX_REGEX_BYTES: usize = 1 << 20;

/// Compile an argument pattern so it must match the whole value. A pattern
/// such as `^a$|.*` reads as anchored but its second branch is not; wrapping
/// it in `^(?:...)$` closes that gap.
pub fn compile_whole(pattern: &str) -> Option<regex::Regex> {
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return None;
    }
    build(&format!("^(?:{pattern})$"))
}

/// Compile a pack pattern with the linear-time engine and a size bound.
pub fn compile(pattern: &str) -> Option<regex::Regex> {
    if pattern.is_empty() || pattern.chars().count() > MAX_PATTERN_CHARS {
        return None;
    }
    build(pattern)
}

fn build(pattern: &str) -> Option<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_BYTES)
        .dfa_size_limit(MAX_REGEX_BYTES)
        .build()
        .ok()
}
