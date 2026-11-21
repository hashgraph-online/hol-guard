//! `http` and `xh` reading a URL.
//!
//! HTTPie, and the `xh` that reimplements its command line, are what an agent
//! reaches for when it wants a readable answer from a service it just started:
//! `http :3000/health`, `xh GET http://127.0.0.1:8080/health`. The request is
//! the one `curl http://localhost:3000/health` issues, so the destination is
//! read against the rules [`super::curl_reads`] already applies and nothing
//! here widens them.
//!
//! Five limits keep this reading narrower than curl's.
//!
//! The method is `GET` or `HEAD`, named or left to the default. HTTPie takes
//! the method as the first word and assumes `GET` when the first word is a
//! URL. Any other verb sends something whose answer is not a read, and a verb
//! written in another case is left to review rather than guessed at.
//!
//! Request items set headers and nothing else. HTTPie builds a body from
//! `name=value` and `name:=json`, a query string from `name==value`, and an
//! upload from `name@file`, which reads a local file to do it. Only the
//! header separator is read, under the name screen curl's `--header` gets.
//!
//! Every option is named below. `--download` and `--output` write a file,
//! `--session` reads and rewrites stored headers, `--auth` sends credentials,
//! and `--follow` sends the request to a host the destination check never saw.
//! An option this reading does not know could be any of them, so an unknown
//! one keeps the review.
//!
//! A public host is read only when the line says the request carries nothing
//! else. Both programs take a redirected stdin as the request body, and with
//! no method written they send it as a `POST`, so a command run with the
//! harness's own stdin attached can carry away something the text never
//! names. `--ignore-stdin` is how both programs say they will not, and it is
//! asked for wherever the answer could leave this machine. A loopback
//! destination is read without it: the body stays on the host, and the ports
//! this reading reaches are already held to dev servers.
//!
//! The program's own configuration carries no default option. Both read a
//! `config.json` before they look at the line, and whatever
//! `default_options` holds is prepended to every request: a `--follow`
//! written there sends a proven `http :3000/health` wherever a redirect
//! points, a `--download` writes a file the line never names, and a
//! `--session` reads and rewrites stored headers. None of that is visible in
//! the arguments, so the file is read as well, under the home the shell
//! itself expands and with the variables that move it screened out.
//!
//! The `https` and `xhs` aliases are absent. They differ from the names here
//! only in the scheme they assume for a URL written without one, which is a
//! guess this module would have to make for itself rather than take from
//! curl's reading of the same spelling.

use super::curl_reads::{expands, loopback_read_url, readable_url, safe_header};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The longest `config.json` this proof reads. A larger file is not one of
/// these programs' configurations, and is left to review rather than scanned.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Flags that change only what is printed or how a failing status is reported.
const PLAIN_FLAGS: [&str; 7] = [
    "--body",
    "--check-status",
    "--headers",
    "--ignore-stdin",
    "--json",
    "--quiet",
    "--verbose",
];

/// Single-letter forms of [`PLAIN_FLAGS`] that both programs spell alike. They
/// may be clustered (`-vb`).
///
/// `-h` is absent: HTTPie reads it as `--headers` and `xh` as its own help,
/// and neither meaning is worth guessing for a flag that only changes output.
const SHORT_FLAGS: &str = "jbvq";

/// Single-letter options that take a value. They end a cluster.
const SHORT_VALUES: &str = "p";

/// Options whose value selects a rendering or bounds the wait.
const VALUE_OPTIONS: [&str; 4] = ["--pretty", "--print", "--style", "--timeout"];

pub(super) fn safe_http_segment(
    executable: &str,
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && configuration_inert(executable, context)
        && read_request(&segment.arguments, context)
}

/// Whether the configuration these programs read adds nothing to the line.
///
/// The file is read from the home the shell expands, so the proof holds only
/// where that home is the one the stamp names, and only where no inherited
/// variable has moved the directory it is read from. A file that is missing
/// adds nothing; one that cannot be read, is not a regular file, is larger
/// than a configuration or is not the object these programs write is left to
/// review rather than guessed at.
pub(super) fn configuration_inert(executable: &str, context: super::PathContext<'_>) -> bool {
    let Some(home) = context.home_dir.map(Path::new) else {
        return false;
    };
    if !home.is_absolute() || !context.shell_home_matches || !context.http_config_absent {
        return false;
    }
    configuration_files(executable, home)
        .is_some_and(|files| files.iter().all(|file| carries_no_default_options(file)))
}

/// Where each program keeps its `config.json`.
///
/// HTTPie reads `~/.config/httpie` and still honours the `~/.httpie` its
/// older releases wrote, and `xh` reads the platform's own configuration
/// directory, which is `~/Library/Application Support` on macOS. Every
/// spelling a release may use is read, because the proof has to hold
/// whichever one the installed program picks.
fn configuration_files(executable: &str, home: &Path) -> Option<Vec<PathBuf>> {
    let configuration = home.join(".config");
    match executable {
        "http" => Some(vec![
            configuration.join("httpie").join("config.json"),
            home.join(".httpie").join("config.json"),
        ]),
        "xh" => Some(vec![
            configuration.join("xh").join("config.json"),
            home.join("Library")
                .join("Application Support")
                .join("xh")
                .join("config.json"),
        ]),
        _ => None,
    }
}

/// A configuration that prepends no option to the command.
fn carries_no_default_options(path: &Path) -> bool {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() == ErrorKind::NotFound,
    };
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    match value.get("default_options") {
        None => value.is_object(),
        Some(serde_json::Value::Array(options)) => options.is_empty(),
        Some(_) => false,
    }
}

fn read_request(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if arguments.iter().any(|argument| expands(argument)) {
        return false;
    }
    let mut words = Vec::new();
    let mut options = true;
    let mut ignores_stdin = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if !options || !argument.starts_with('-') || argument == "-" {
            words.push(argument);
            index += 1;
            continue;
        }
        let Some(consumed) = option_consumed(arguments, index) else {
            return false;
        };
        ignores_stdin |= argument == "--ignore-stdin";
        index += consumed;
    }
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    // The method is the first word only when a URL follows it; a lone word is
    // the URL, which is how `http example.test` reaches its default `GET`.
    let (url, items) = if rest.is_empty() {
        (*first, rest)
    } else if matches!(*first, "GET" | "HEAD") {
        rest.split_first()
            .map(|(url, items)| (*url, items))
            .expect("rest is not empty")
    } else if first.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        // A verb this proof does not read, or one written in another case.
        return false;
    } else {
        (*first, rest)
    };
    readable(url, context, ignores_stdin) && items.iter().all(|item| header_item(item))
}

/// The URL as these programs read it.
///
/// A URL beginning with `:` is HTTPie's shorthand for the local host, so
/// `:3000/health` is `localhost:3000/health` and `:/health` is
/// `localhost/health`. Writing the host back in is all this does; the result
/// is then read by [`readable_url`], which decides what the request may reach.
///
/// Off this host the reading also asks for `--ignore-stdin`, because without
/// it the body is whatever the harness left on stdin rather than what the
/// line names.
fn readable(url: &str, context: super::PathContext<'_>, ignores_stdin: bool) -> bool {
    let spelled = match url.strip_prefix(':') {
        None => std::borrow::Cow::Borrowed(url),
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            std::borrow::Cow::Owned(format!("localhost{rest}"))
        }
        Some(rest) => std::borrow::Cow::Owned(format!("localhost:{rest}")),
    };
    loopback_read_url(&spelled, context) || (ignores_stdin && readable_url(&spelled, context))
}

/// A request item that only sets a header.
///
/// HTTPie splits an item at the first separator it finds, and which one that
/// is decides what the item builds: `=` a body field, `:=` a raw JSON value,
/// `==` a query parameter, `@` a file upload, `:` a header. The search is
/// therefore for the earliest separator of any kind rather than for a colon,
/// so `fields=a:b` is read as the body field it is.
fn header_item(item: &str) -> bool {
    let Some(position) = item.find([':', '=', '@']) else {
        return false;
    };
    item.as_bytes()[position] == b':'
        && !matches!(item.as_bytes().get(position + 1), Some(b'=' | b'@'))
        && safe_header(item)
}

/// How many arguments a proven option takes, or `None` when it is not proven.
fn option_consumed(arguments: &[String], index: usize) -> Option<usize> {
    let argument = arguments[index].as_str();
    if let Some(long) = argument.strip_prefix("--") {
        let (name, inline) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (long, None),
        };
        let option = format!("--{name}");
        if inline.is_none() && PLAIN_FLAGS.contains(&option.as_str()) {
            return Some(1);
        }
        if !VALUE_OPTIONS.contains(&option.as_str()) {
            return None;
        }
        let value = match inline {
            Some(value) => value,
            None => arguments.get(index + 1)?.as_str(),
        };
        let consumed = if inline.is_some() { 1 } else { 2 };
        plain_value(value).then_some(consumed)
    } else {
        let cluster = &argument[1..];
        for (offset, short) in cluster.char_indices() {
            if SHORT_FLAGS.contains(short) {
                continue;
            }
            if !SHORT_VALUES.contains(short) {
                return None;
            }
            let attached = &cluster[offset + short.len_utf8()..];
            let (value, consumed) = if attached.is_empty() {
                (arguments.get(index + 1)?.as_str(), 2)
            } else {
                (attached, 1)
            };
            return plain_value(value).then_some(consumed);
        }
        // A lone `-` never reaches here, and an empty cluster cannot be written.
        Some(1)
    }
}

/// A value naming a rendering, a print selection or a number of seconds.
///
/// Every option that takes one here chooses among the program's own words, so
/// a value is held to the characters those words are spelled with. That keeps
/// a path, a URL or a shell operator out of an option this reading admits.
fn plain_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b','))
}

#[cfg(test)]
#[path = "http_reads_tests.rs"]
mod tests;
