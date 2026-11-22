//! Asking a database client whether its server is answering.
//!
//! `redis-cli ping` sends one `PING` and prints `PONG`. It reads no key,
//! writes none, and the reply is the same whatever the server holds, so the
//! command carries no data in either direction. It is the step before the
//! work -- a test suite waiting for its fixture server, a developer checking
//! that the container came up. `mysqladmin ping` asks the same question of the
//! other server a session usually waits for, so it is screened here beside it.
//! `pg_isready` already has its own screen in [`super::process_probes`].
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
//! must carry its value in the word after it, which is the only spelling
//! redis-cli reads. It compares every option word whole, so `-p6379` and
//! `-p=6379` name no port to it: both reach the unrecognised-option path and
//! exit before a connection is opened. A credential (`-a`, `--pass`, `--user`),
//! a connection URI (`-u`), a socket path (`-s`), a certificate (`--cacert`
//! and its neighbours) and the repeating or scripting modes (`-r`, `-i`,
//! `-x`, `--eval`, `--cluster`, `--pipe`, `--rdb`, `--scan`) are each a reason
//! this is no longer a liveness check, so an unrecognised word refuses the
//! whole line rather than being skipped.

/// A loopback liveness check: `redis-cli [options] ping` or
/// `mysqladmin [options] ping`.
pub(super) fn safe_liveness_probe(basename: &str, arguments: &[String]) -> bool {
    match basename {
        "redis-cli" => {
            let Some((verb, options)) = arguments.split_last() else {
                return false;
            };
            verb == "ping" && loopback_options(options)
        }
        "mysqladmin" => {
            let Some((verb, options)) = arguments.split_last() else {
                return false;
            };
            verb == "ping" && mysql_options(options)
        }
        _ => false,
    }
}

/// Whether `value` names this host.
fn loopback_host(value: &str) -> bool {
    matches!(value, "127.0.0.1" | "::1" | "localhost")
}

/// A port, a timeout or a connection count: a plain number.
fn plain_number(value: &str) -> bool {
    (1..=5).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// `mysqladmin ping` asks the server whether it is alive. Its other verbs --
/// `shutdown`, `drop`, `flush-logs`, `password` -- stop the server or change
/// what it holds, so only `ping` reaches here. `--defaults-file` reads a file
/// the caller names and `-p` carries a password, so neither is on this list.
///
/// The host has to be named in the command text. An omitted `-h` takes the
/// server from `MYSQL_HOST` or from a `~/.my.cnf` the caller did not write
/// here, so a line that names no host does not say which machine it reaches.
fn mysql_options(words: &[String]) -> bool {
    let mut loopback = false;
    let mut remaining = words;
    while let Some((option, rest)) = remaining.split_first() {
        if matches!(option.as_str(), "-s" | "--silent" | "--protocol=TCP") {
            remaining = rest;
            continue;
        }
        if !matches!(
            option.as_str(),
            "-h" | "--host" | "-P" | "--port" | "-u" | "--user" | "--connect-timeout"
        ) {
            return false;
        }
        let Some((value, tail)) = rest.split_first() else {
            return false;
        };
        let accepted = match option.as_str() {
            "-h" | "--host" => {
                loopback = loopback_host(value);
                loopback
            }
            "-P" | "--port" | "--connect-timeout" => plain_number(value),
            _ => crate::pretool::safe_scalar::postgres_name(value),
        };
        if !accepted {
            return false;
        }
        remaining = tail;
    }
    loopback
}

/// The option words before the verb, each read with the word after it.
fn loopback_options(words: &[String]) -> bool {
    let mut remaining = words;
    while let Some((option, rest)) = remaining.split_first() {
        if !matches!(option.as_str(), "-h" | "-p" | "-n" | "-t") {
            return false;
        }
        let Some((value, tail)) = rest.split_first() else {
            return false;
        };
        if !option_value_inert(option, value) {
            return false;
        }
        remaining = tail;
    }
    true
}

/// Whether this option's value keeps the probe on this host.
fn option_value_inert(name: &str, value: &str) -> bool {
    match name {
        "-h" => loopback_host(value),
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
