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
//! A second family is spelled for the thing it switches off rather than for
//! what it carries: `PUPPETEER_SKIP_DOWNLOAD`, `CYPRESS_INSTALL_BINARY` and
//! `ESLINT_USE_FLAT_CONFIG` hold `DOWNLOAD`, `BINARY` and `CONFIG`, so the
//! `LOAD`, `BIN` and `CONF` fragments match inside a longer word that means
//! something else. Each of those settings takes one of two or three words and
//! decides whether a tool fetches its own binary, keeps a cache, prints a
//! staleness notice, or reads the newer configuration format.
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

/// The two words a switch of this kind is written with. `npm` and every tool
/// below read `0`/`1` and `false`/`true` the same way, and none of these
/// settings has a third meaning.
const OFF_OR_ON: &[&str] = &["0", "1", "false", "true"];

/// Switches whose whole job is to turn one step of a tool's own setup off.
/// None of them names a program, a file or a search path: the value is one
/// of the words above, and the step it refuses is a download, a cache, a
/// warning, a git hook, or the older of two configuration formats.
///
/// `CYPRESS_INSTALL_BINARY` is the one exception to the shared value list.
/// It is listed with `0` alone, because its other accepted values are a URL
/// or a path to a zip file, which is exactly the redirection the name test
/// refuses it for.
const TOOL_SWITCHES: &[(&str, &[&str])] = &[
    ("BROWSERSLIST_DISABLE_CACHE", OFF_OR_ON),
    ("BROWSERSLIST_IGNORE_OLD_DATA", OFF_OR_ON),
    ("CYPRESS_INSTALL_BINARY", &["0"]),
    ("ELECTRON_SKIP_BINARY_DOWNLOAD", OFF_OR_ON),
    ("ESLINT_USE_FLAT_CONFIG", &["false", "true"]),
    ("HUSKY_SKIP_HOOKS", OFF_OR_ON),
    ("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", OFF_OR_ON),
    ("PUPPETEER_SKIP_DOWNLOAD", OFF_OR_ON),
    ("SHARP_IGNORE_GLOBAL_LIBVIPS", OFF_OR_ON),
];

/// A setting whose value the runtime can read, carrying only options that
/// change how a run reports or repeats. The caller has already decided the
/// word is a literal assignment in front of a command.
pub(crate) fn inert_tool_setting(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if tool_switch_inert(&upper, value) {
        return true;
    }
    match upper.as_str() {
        "GOFLAGS" => every_word(value, go_flag_inert),
        "PYTEST_ADDOPTS" => pytest_addopts_inert(value),
        "RUSTFLAGS" | "RUSTDOCFLAGS" => rust_lint_levels_only(value),
        _ => false,
    }
}

/// One of the switches above, written with one of the words that switch
/// accepts. The name is matched whole, so a longer setting that merely
/// starts with one of them is not read as the switch.
fn tool_switch_inert(upper: &str, value: &str) -> bool {
    TOOL_SWITCHES
        .iter()
        .any(|(known, allowed)| upper == *known && allowed.contains(&value))
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
