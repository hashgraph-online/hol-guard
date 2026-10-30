//! A handful of build and test settings whose name says "options" or "flags"
//! while the value in front of a command says nothing more than how loudly
//! the run reports, how many times it repeats, or which lint it refuses.
//!
//! `code_loading_environment_name` matches those names by fragment, because
//! most of what they can carry does load code: `GOFLAGS=-toolexec=./x` runs
//! a program of its own, `PYTEST_ADDOPTS=-pevil` loads a plugin, and
//! `RUSTFLAGS=-Clinker=./ld` picks the linker. Reading the name alone also
//! refuses `GOFLAGS=-count=1 go test ./...` and `PYTEST_ADDOPTS=-q pytest`,
//! which are how a developer turns off the test cache and quiets a run.
//!
//! So each family here reads its own value against a closed list of options
//! that name no file, no program and no search path. Anything else — an
//! unknown option, a separator, an empty value, a bare word — leaves the
//! setting unprojected, and the command keeps failing closed.

use crate::sfrs_constants::{PYTEST_SAFE_FLAGS, PYTEST_SAFE_FLAGS_WITH_VALUES};

/// `go` options that change how a build or test run reports and repeats.
/// None of them names a program (`-toolexec`, `-exec`), a compiler or
/// linker argument (`-gcflags`, `-ldflags`, `-asmflags`), a file
/// (`-overlay`, `-pkgdir`) or a build tag, and `-mod` is spelled with the
/// two values that forbid the module graph being rewritten, leaving
/// `-mod=mod` out.
const INERT_GO_FLAGS: &[&str] = &["-trimpath", "-v"];
const INERT_GO_FLAG_VALUES: &[(&str, &[&str])] = &[
    ("-buildvcs", &["auto", "false", "true"]),
    ("-mod", &["readonly", "vendor"]),
];

/// `rustc` lint levels. A lint name is the whole argument, so these cannot
/// reach the code-selecting options (`-C`, `-Z`, `-L`, `--extern`) that make
/// `RUSTFLAGS` worth refusing by name.
const RUST_LINT_LEVELS: &[&str] = &["-A", "-D", "-F", "-W"];

/// A setting whose value the runtime can read, carrying only options that
/// change how a run reports or repeats. The caller has already decided the
/// word is a literal assignment in front of a command.
pub(crate) fn inert_tool_setting(name: &str, value: &str) -> bool {
    match name.to_ascii_uppercase().as_str() {
        "GOFLAGS" => every_word(value, go_flag_inert),
        "PYTEST_ADDOPTS" => pytest_addopts_inert(value),
        "RUSTFLAGS" | "RUSTDOCFLAGS" => rust_lint_levels_only(value),
        _ => false,
    }
}

/// The shell hands a quoted setting over as one value holding several
/// options, exactly as a program reading it splits them again.
fn every_word(value: &str, inert: impl Fn(&str) -> bool) -> bool {
    let mut words = words(value).peekable();
    words.peek().is_some() && words.all(inert)
}

fn words(value: &str) -> impl Iterator<Item = &str> {
    value.split_whitespace()
}

fn go_flag_inert(word: &str) -> bool {
    if INERT_GO_FLAGS.contains(&word) {
        return true;
    }
    if let Some(count) = word.strip_prefix("-count=") {
        return !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit());
    }
    INERT_GO_FLAG_VALUES.iter().any(|(flag, allowed)| {
        word.strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
            .is_some_and(|chosen| allowed.contains(&chosen))
    })
}

/// `rustc` accepts a lint level joined to its lint (`-Dwarnings`) or spelled
/// apart from it (`-D warnings`), and both are how a project refuses one.
fn rust_lint_levels_only(value: &str) -> bool {
    let words: Vec<&str> = words(value).collect();
    let mut index = 0;
    while index < words.len() {
        let Some(lint) = RUST_LINT_LEVELS
            .iter()
            .find_map(|level| words[index].strip_prefix(level))
        else {
            return false;
        };
        if lint.is_empty() {
            index += 1;
            match words.get(index) {
                Some(apart) if lint_name(apart) => index += 1,
                _ => return false,
            }
            continue;
        }
        if !lint_name(lint) {
            return false;
        }
        index += 1;
    }
    !words.is_empty()
}

fn lint_name(lint: &str) -> bool {
    !lint.is_empty()
        && lint
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// The options `pytest` itself is already trusted with on a command line,
/// read the same way here. A value this walk does not reach the end of —
/// a plugin (`-p`), a configuration file (`-c`), a bare test path, or the
/// `--` that ends option parsing — is not inert, and an option that takes a
/// value is inert only when it is given one.
fn pytest_addopts_inert(value: &str) -> bool {
    let words: Vec<&str> = words(value).collect();
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        if PYTEST_SAFE_FLAGS.contains(&word) {
            index += 1;
            continue;
        }
        if PYTEST_SAFE_FLAGS_WITH_VALUES.contains(&word) {
            // The option's own value follows as the next word. A missing one
            // leaves the walk short of the end, and a word spelled as an
            // option or as the `--` that ends option parsing is not a value
            // this walk may step over unread.
            match words.get(index + 1) {
                Some(following) if !following.starts_with('-') => index += 2,
                _ => return false,
            }
            continue;
        }
        if PYTEST_SAFE_FLAGS_WITH_VALUES.iter().any(|flag| {
            word.strip_prefix(flag)
                .and_then(|rest| rest.strip_prefix('='))
                .is_some_and(|chosen| !chosen.is_empty())
        }) {
            index += 1;
            continue;
        }
        return false;
    }
    // Every word was read; the walk only steps over a value it has seen.
    !words.is_empty()
}

#[cfg(test)]
#[path = "inert_tool_settings_tests.rs"]
mod tests;
