//! Reading the macOS preference store.
//!
//! `defaults read com.apple.dock orientation` is how a session on macOS
//! answers a question about the machine it is working on: which appearance is
//! set, whether a tool has been configured, what a domain already holds. The
//! answer comes out of the user's own preference store, nothing is opened that
//! the caller did not name, and nothing is written.
//!
//! The same program writes that store, so the verb decides. `write`, `delete`,
//! `rename` and `import` change a domain, and `export` writes a plist to a path
//! the caller names; none of them is admitted here. Only `read`, `read-type`
//! and `domains` are, and a verb this screen does not know refuses the line
//! rather than being treated as a read.
//!
//! A domain is screened as a plain name. `defaults` also accepts a path to a
//! plist in place of one, and that spelling reads a file rather than the
//! preference store, so it keeps its review: the path never reaches the read
//! target check this module would have to repeat, and a reader that opens an
//! arbitrary file is a different question from one that reads the user's own
//! settings.
//!
//! `defaults read` with no domain at all dumps every domain the user has,
//! which is the whole preference store rather than an answer about one thing.
//! It is left reviewed for that reason.

/// The host selectors that may stand before the verb. They choose which host's
/// preferences are read and carry no path.
fn host_selector(words: &[String], index: &mut usize) -> bool {
    match words.get(*index).map(String::as_str) {
        Some("-currentHost") => {
            *index += 1;
            true
        }
        Some("-host") => match words.get(*index + 1) {
            Some(name) if plain_word(name) => {
                *index += 2;
                true
            }
            _ => false,
        },
        _ => false,
    }
}

/// A word with no path separator, no leading dash and nothing a shell would
/// have had to quote: a domain, a key or a host name.
fn plain_word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// The global domain, which is spelled three ways.
fn global_domain(value: &str) -> bool {
    matches!(value, "-g" | "-globalDomain" | "NSGlobalDomain")
}

/// A domain: the global one, or a plain name such as `com.apple.dock`.
fn domain(value: &str) -> bool {
    global_domain(value) || plain_word(value)
}

/// `defaults [-currentHost | -host NAME] read|read-type DOMAIN [KEY]` reads
/// what one domain holds, and `defaults [...] domains` lists the names of the
/// domains without reading any of them.
pub(super) fn safe_preference_read(basename: &str, arguments: &[String]) -> bool {
    if basename != "defaults" {
        return false;
    }
    let mut index = 0;
    host_selector(arguments, &mut index);
    let Some(verb) = arguments.get(index).map(String::as_str) else {
        return false;
    };
    let rest = &arguments[index + 1..];
    match verb {
        "domains" => rest.is_empty(),
        "read" | "read-type" => match rest {
            [name] => domain(name),
            [name, key] => domain(name) && plain_word(key),
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
#[path = "preference_reads_tests.rs"]
mod tests;
