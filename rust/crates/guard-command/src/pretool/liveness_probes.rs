//! Asking a database client whether its server is answering.
//!
//! `redis-cli ping` sends one `PING` and prints `PONG`. It reads no key,
//! writes none, and the reply is the same whatever the server holds, so the
//! command carries no data in either direction. It is the step before the
//! work -- a test suite waiting for its fixture server, a developer checking
//! that the container came up -- and `pg_isready` and `mysqladmin ping` ask
//! the same question without reaching review.
//!
//! The containment reading holds every database
//! client outside the workspace, because `psql -c` and `mysql -e` carry
//! arbitrary statements to a server the sandbox cannot contain. That reading
//! is right for a statement and wrong for a liveness check, and
//! [`super::version_probes`] and [`super::help_probes`] already read
//! `redis-cli --version` and `redis-cli --help` past it for the same reason:
//! the banner and the usage page name no host and no key either.
//!
//! Three limits keep this narrow.
//!
//! The verb has to be `ping` alone. `redis-cli ping hello` echoes the word
//! back, which is still harmless, but every other verb -- `get`, `set`,
//! `info`, `dbsize`, `flushall` -- names or moves what the server holds.
//!
//! The server has to be loopback. A `-h` naming anything but `127.0.0.1`,
//! `::1` or `localhost` reaches a machine this host does not own, and the
//! reply tells the caller it is there.
//!
//! Only the options that pick the loopback endpoint are admitted, and each
//! must carry its value on the line. A credential (`-a`, `--pass`, `--user`),
//! a connection URI (`-u`), a socket path (`-s`), a certificate (`--cacert`
//! and its neighbours) and the repeating or scripting modes (`-r`, `-i`,
//! `-x`, `--eval`, `--cluster`, `--pipe`, `--rdb`, `--scan`) are each a reason
//! this is no longer a liveness check, so an unrecognised word refuses the
//! whole line rather than being skipped.

/// `redis-cli [loopback options] ping`.
pub(super) fn safe_liveness_probe(basename: &str, arguments: &[String]) -> bool {
    if basename != "redis-cli" {
        return false;
    }
    let Some((verb, options)) = arguments.split_last() else {
        return false;
    };
    verb == "ping" && loopback_options(options)
}

/// The option words before the verb, read in pairs.
fn loopback_options(words: &[String]) -> bool {
    let mut remaining = words;
    while let Some((option, rest)) = remaining.split_first() {
        let (name, inline) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (option.as_str(), None),
        };
        if !matches!(name, "-h" | "-p" | "-n" | "-t") {
            return false;
        }
        let (value, tail) = match inline {
            Some(value) => (value, rest),
            None => match rest.split_first() {
                Some((value, tail)) => (value.as_str(), tail),
                None => return false,
            },
        };
        if !option_value_inert(name, value) {
            return false;
        }
        remaining = tail;
    }
    true
}

/// Whether this option's value keeps the probe on this host.
fn option_value_inert(name: &str, value: &str) -> bool {
    match name {
        "-h" => matches!(value, "127.0.0.1" | "::1" | "localhost"),
        // A port, a database index and a timeout are all plain numbers;
        // redis-cli reads the timeout as seconds and accepts a fraction.
        "-p" | "-n" => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "-t" => {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
                && value.bytes().filter(|byte| *byte == b'.').count() <= 1
                && value.bytes().any(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "liveness_probes_tests.rs"]
mod tests;
