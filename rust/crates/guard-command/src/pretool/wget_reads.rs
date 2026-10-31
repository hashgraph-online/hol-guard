//! A `wget` request that prints what it fetched and leaves no file behind.
//!
//! `wget -qO- http://127.0.0.1:8080/health` is the readiness check a developer
//! writes when `curl` is not installed, and the same request written with
//! `curl` is already proven. The two differ in one habit that decides this
//! reading: `curl` prints the response and `wget` saves it, so a bare
//! `wget URL` names no file yet writes one into the working directory, under
//! a name the server's own headers can choose. Only a run that says where the
//! response goes is read here -- `-O-` to standard output, `-O /dev/null` or
//! a scratch file, or `--spider`, which asks for the headers alone.
//!
//! Every option is allowlisted, so anything that sends a body, reads a local
//! file or URL list, carries credentials, writes a log beside the download,
//! recurses into the site or runs a `.wgetrc` command keeps the normal review
//! path. The URLs themselves pass the screens [`super::curl_reads`] applies:
//! public `http(s)` content, or a dev server on this machine at a port no
//! local admin service claims.
//!
//! Redirects are the one place the two fetchers part. `curl` follows none
//! unless asked, and this proof never asks; `wget` follows up to twenty by
//! default, which would reach a private range or a metadata endpoint that the
//! destination screen refuses. A public URL is therefore read only when
//! `--max-redirect=0` holds the request to the host that was named. A loopback
//! URL is read as written: a service already running on this machine could put
//! anything it can reach into its own response body, so the redirect it might
//! answer with grants it nothing new.

use super::curl_reads::{web_target, WebTarget};

/// Long options that change only presentation, address family or caching.
const PLAIN_FLAGS: [&str; 16] = [
    "--content-on-error",
    "--debug",
    "--https-only",
    "--inet4-only",
    "--inet6-only",
    "--no-cache",
    "--no-config",
    "--no-cookies",
    "--no-dns-cache",
    "--no-hsts",
    "--no-show-progress",
    "--no-verbose",
    "--quiet",
    "--server-response",
    "--show-progress",
    "--verbose",
];

/// Single-letter forms of [`PLAIN_FLAGS`] that may be clustered (`-qS`).
const SHORT_FLAGS: &str = "qvS46";
/// Single-letter options that take a value. They end a cluster.
const SHORT_VALUES: &str = "OtTUw";

/// Options whose value counts something: a duration, a count or a bound.
const NUMERIC_OPTIONS: [&str; 8] = [
    "--connect-timeout",
    "--dns-timeout",
    "--max-redirect",
    "--read-timeout",
    "--timeout",
    "--tries",
    "--wait",
    "--waitretry",
];

pub(super) fn safe_wget_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && reads_a_named_url(&segment.arguments, context)
}

/// A whole `wget` segment the native proof accepts as a read.
///
/// None of its allowed options reads standard input, a local file or a list of
/// URLs, so the compatibility layer does not treat it as a possible upload
/// when it sits in a pipeline -- where `-T` counts seconds rather than naming
/// a file to send, as the same letter does for `curl`.
pub(crate) fn proven_read_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("wget")
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

fn reads_a_named_url(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if arguments.iter().any(|argument| expands(argument)) {
        return false;
    }
    // Where the response lands. Until an option says, `wget` names the file
    // itself, from the URL or from the headers the server answers with.
    let mut output_named = false;
    let mut redirects_bounded = false;
    let mut public = false;
    let mut urls = 0usize;
    let mut options = true;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if !options || !argument.starts_with('-') || argument == "-" {
            match web_target(argument, context) {
                Some(WebTarget::Public) => public = true,
                Some(WebTarget::Loopback) => {}
                None => return false,
            }
            urls += 1;
            index += 1;
            continue;
        }
        let Some(read) = option_read(arguments, index, context) else {
            return false;
        };
        if read.names_the_output {
            output_named = true;
        }
        // wget applies its options in order, so a repeated `--max-redirect`
        // is decided by the last one written.
        if let Some(bound) = read.redirect_bound {
            redirects_bounded = bound;
        }
        index += read.consumed;
    }
    urls > 0 && output_named && (!public || redirects_bounded)
}

/// What one option told this reading, and how many arguments it took.
struct OptionRead {
    consumed: usize,
    names_the_output: bool,
    /// `Some` only for `--max-redirect`, carrying whether that spelling of it
    /// holds the request to the host that was named.
    redirect_bound: Option<bool>,
}

impl OptionRead {
    fn plain(consumed: usize) -> Self {
        Self {
            consumed,
            names_the_output: false,
            redirect_bound: None,
        }
    }
}

fn expands(argument: &str) -> bool {
    argument.contains(['$', '`', '\n', '\r'])
}

/// How one proven option reads, or `None` when it is not proven.
fn option_read(
    arguments: &[String],
    index: usize,
    context: super::PathContext<'_>,
) -> Option<OptionRead> {
    let argument = arguments[index].as_str();
    // `wget` spells several options with two letters after one dash. Only the
    // quiet one is read here, and it is matched whole so no cluster reading
    // mistakes its `n` for a flag.
    if argument == "-nv" {
        return Some(OptionRead::plain(1));
    }
    // `--spider` asks for the headers and stops, so nothing is written at all.
    if argument == "--spider" {
        return Some(OptionRead {
            consumed: 1,
            names_the_output: true,
            redirect_bound: None,
        });
    }
    if let Some(long) = argument.strip_prefix("--") {
        let (name, inline) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (long, None),
        };
        let option = format!("--{name}");
        if inline.is_none() && PLAIN_FLAGS.contains(&option.as_str()) {
            return Some(OptionRead::plain(1));
        }
        let value = match inline {
            Some(value) => value,
            None => arguments.get(index + 1)?.as_str(),
        };
        let consumed = if inline.is_some() { 1 } else { 2 };
        return value_read(&option, value, consumed, context);
    }
    let cluster = &argument[1..];
    for (offset, short) in cluster.char_indices() {
        if SHORT_FLAGS.contains(short) {
            continue;
        }
        if !SHORT_VALUES.contains(short) {
            return None;
        }
        let long = match short {
            'O' => "--output-document",
            't' => "--tries",
            'T' => "--timeout",
            'U' => "--user-agent",
            'w' => "--wait",
            _ => return None,
        };
        let attached = &cluster[offset + short.len_utf8()..];
        let (value, consumed) = if attached.is_empty() {
            (arguments.get(index + 1)?.as_str(), 2)
        } else {
            (attached, 1)
        };
        return value_read(long, value, consumed, context);
    }
    Some(OptionRead::plain(1))
}

fn value_read(
    option: &str,
    value: &str,
    consumed: usize,
    context: super::PathContext<'_>,
) -> Option<OptionRead> {
    if expands(value) {
        return None;
    }
    match option {
        "--output-document" => named_output(value, context).then_some(OptionRead {
            consumed,
            names_the_output: true,
            redirect_bound: None,
        }),
        "--user-agent" => (!value.is_empty()).then(|| OptionRead::plain(consumed)),
        "--compression" => {
            matches!(value, "auto" | "gzip" | "none").then(|| OptionRead::plain(consumed))
        }
        _ if NUMERIC_OPTIONS.contains(&option) => counted(value).then_some(OptionRead {
            consumed,
            names_the_output: false,
            redirect_bound: (option == "--max-redirect")
                .then(|| value.trim_start_matches('0').is_empty()),
        }),
        _ => None,
    }
}

/// Where the response may land: standard output, nowhere, or a scratch file
/// the command named itself.
fn named_output(value: &str, context: super::PathContext<'_>) -> bool {
    value == "-"
        || value == "/dev/null"
        || super::curl_reads::output_targets::scratch_output_target(value, context)
}

fn counted(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

#[cfg(test)]
#[path = "wget_reads_tests.rs"]
mod tests;
