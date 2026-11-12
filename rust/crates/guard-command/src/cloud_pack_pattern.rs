//! Pattern compilation for cloud action packs.
//!
//! Every pack pattern uses the linear-time `regex` engine with a size bound, so
//! a pack cannot ship a pattern that backtracks or compiles to a huge program.

const MAX_PATTERN_CHARS: usize = 512;
const MAX_REGEX_BYTES: usize = 1 << 20;

/// Compile an argument pattern so it must match the whole value. A pattern
/// such as `^a$|.*` reads as anchored but its second branch is not; wrapping
/// it in `^(?:...)$` closes that gap. The pattern must compile on its own
/// first: `^C)|(?:x$` is invalid alone, but wrapped its stray `)` would close
/// the wrapper and leave a branch that matches only a prefix.
pub fn compile_whole(pattern: &str) -> Option<regex::Regex> {
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return None;
    }
    build(pattern)?;
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

#[cfg(test)]
mod tests {
    use super::compile_whole;

    #[test]
    fn a_pattern_cannot_close_the_whole_value_wrapper() {
        assert!(compile_whole("^C)|(?:x$").is_none());
        let whole = compile_whole("^a$|.*b").expect("valid pattern");
        assert!(whole.is_match("ab"));
        assert!(!whole.is_match("bc"));
    }
}
