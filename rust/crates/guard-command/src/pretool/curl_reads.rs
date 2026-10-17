//! Plain `curl` GET and HEAD requests for public web content and local dev
//! servers.
//!
//! The request may only fetch named public `http(s)` URLs and print the
//! response to stdout, where the pipeline's own proofs judge every consumer
//! (`curl ... | sh` keeps its review because `sh` has no proof). Every option
//! is allowlisted, so anything that sends a body, reads a local file, loads a
//! config, carries credentials, routes through a proxy or socket, or writes a
//! file other than a scratch file keeps the normal review path.
//!
//! A read of a dev server on `127.0.0.1` or `localhost` is proven too, on a
//! conventional dev-server port ([`super::loopback_ports`]) that neither
//! Guard's daemon nor a local service answering a plain GET with
//! credentials, cluster state or a debugger ([`LOCAL_ADMIN_PORTS`]) may
//! listen on. Private, link-local
//! and metadata addresses, other loopback spellings, rebinding names and
//! names under reserved test suffixes stay reviewed: those resolve to local
//! services rather than public content. The response body and headers reach
//! a file only through `-o` or `-D` naming a scratch file ([`output_targets`]); the redirect
//! projection holds `curl ... > file` to the same targets through
//! [`NETWORK_READ_REASON`]. A URL whose path, query or fragment holds a
//! credential shape, a JWT or a long opaque token stays reviewed, since the
//! request line itself can carry data to the host.

#[path = "curl_output_targets.rs"]
pub(in crate::pretool) mod output_targets;
#[path = "url_secrets.rs"]
pub(super) mod url_secrets;

pub(crate) const NETWORK_READ_REASON: &str = "native_exact_safe_network_read";

/// Names reserved by RFC 6761 or routinely mapped to local development
/// servers. They never name public content.
const RESERVED_SUFFIXES: [&str; 4] = [".test", ".invalid", ".example", ".localhost"];

/// Loopback ports of container engines (`2375`, `2376`, `4243`), cluster
/// stores, APIs and proxies (`2379`, `2380`, `6443`, `8001`, kubelet and
/// kube-proxy `10248`-`10256`), Nomad (`4646`), secret stores and service
/// catalogs (`8200`, `8500`), proxy admin APIs (`2019`, `15000`), and the
/// Chrome and Node inspectors (`9222`, `9229`). A GET to any of them can read
/// secrets or drive another process.
///
/// This list subtracts from the dev-server ports, which is what a loopback
/// read is allowed on in the first place: a port no framework conventionally
/// binds is already unreachable here without being named. It is written out
/// whole, the kubelet block included, so the list keeps saying what it means
/// if the dev-server ranges ever widen onto one of these.
const LOCAL_ADMIN_PORTS: [u16; 23] = [
    2019, 2375, 2376, 2379, 2380, 4243, 4646, 6443, 8001, 8200, 8500, 9222, 9229, 10248, 10249,
    10250, 10251, 10252, 10253, 10254, 10255, 10256, 15000,
];

/// Flags that change only presentation, failure handling or transport version.
const PLAIN_FLAGS: [&str; 17] = [
    "--compressed",
    "--fail",
    "--fail-with-body",
    "--get",
    "--globoff",
    "--head",
    "--http1.1",
    "--http2",
    "--include",
    "--ipv4",
    "--ipv6",
    "--no-buffer",
    "--no-progress-meter",
    "--show-error",
    "--silent",
    "--ssl-reqd",
    "--verbose",
];

/// Single-letter forms of [`PLAIN_FLAGS`] that may be clustered (`-fsS`).
///
/// `-L`/`--location` is absent on purpose: a public URL could answer with a
/// redirect to loopback, a private range or a metadata endpoint, and curl
/// would follow it (resending custom headers) without the destination check.
const SHORT_FLAGS: &str = "fsSiIvN46gG";
/// Single-letter options that take a value. They end a cluster.
const SHORT_VALUES: &str = "mHXwoDA";

const NUMERIC_OPTIONS: [&str; 6] = [
    "--connect-timeout",
    "--max-time",
    "--max-redirs",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
];

/// Credential-bearing header names and query terms.
const CREDENTIAL_TERMS: [&str; 9] = [
    "auth",
    "token",
    "key",
    "secret",
    "password",
    "session",
    "cookie",
    "credential",
    "sig",
];

pub(super) fn safe_curl_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    if model.dialect != "posix" || segment.pipeline_index != 0 {
        return false;
    }
    let arguments = &segment.arguments;
    if arguments.iter().any(|argument| expands(argument)) {
        return false;
    }
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
            if !readable_url(argument, context) {
                return false;
            }
            urls += 1;
            index += 1;
            continue;
        }
        let Some(consumed) = option_consumed(arguments, index, context) else {
            return false;
        };
        if let Some(url) = url_option(arguments, index) {
            if !readable_url(url, context) {
                return false;
            }
            urls += 1;
        }
        index += consumed;
    }
    urls > 0
}

/// A whole `curl` segment, generic checks included, that the native proof
/// accepts as a GET or HEAD of a public URL. None of its allowed options reads
/// standard input or a local file, so the compatibility layer does not treat
/// it as a possible upload when it sits in a pipeline.
pub(crate) fn proven_read_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("curl")
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

/// Reason code for a proven command: a network read keeps a distinct code so
/// a projected file redirect of its body stays reviewed.
pub(crate) fn proven_reason_code(model: &crate::CanonicalCommandV1) -> &'static str {
    let fetches = model.segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|executable| super::executable_basename(executable) == "curl")
    });
    if fetches {
        NETWORK_READ_REASON
    } else {
        "native_exact_safe_command"
    }
}

fn expands(argument: &str) -> bool {
    argument.contains(['$', '`', '\n', '\r']) || argument.starts_with('@')
}

fn url_option(arguments: &[String], index: usize) -> Option<&str> {
    let argument = arguments[index].as_str();
    if argument == "--url" {
        return arguments.get(index + 1).map(String::as_str);
    }
    argument.strip_prefix("--url=")
}

/// How many arguments a proven option takes, or `None` when it is not proven.
fn option_consumed(
    arguments: &[String],
    index: usize,
    context: super::PathContext<'_>,
) -> Option<usize> {
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
        let value = match inline {
            Some(value) => value,
            None => arguments.get(index + 1)?.as_str(),
        };
        let consumed = if inline.is_some() { 1 } else { 2 };
        return long_value_safe(&option, value, context).then_some(consumed);
    }
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
        return short_value_safe(short, value, context).then_some(consumed);
    }
    Some(1)
}

fn short_value_safe(short: char, value: &str, context: super::PathContext<'_>) -> bool {
    let long = match short {
        'm' => "--max-time",
        'H' => "--header",
        'X' => "--request",
        'w' => "--write-out",
        'o' => "--output",
        'D' => "--dump-header",
        'A' => "--user-agent",
        _ => return false,
    };
    long_value_safe(long, value, context)
}

fn long_value_safe(option: &str, value: &str, context: super::PathContext<'_>) -> bool {
    if expands(value) {
        return false;
    }
    match option {
        "--url" => true,
        "--request" => matches!(value.to_ascii_uppercase().as_str(), "GET" | "HEAD"),
        "--header" => safe_header(value),
        // `%output{...}` makes curl write a file.
        "--write-out" => !value.to_ascii_lowercase().contains("%output"),
        "--output" => value == "/dev/null" || output_targets::scratch_output_target(value, context),
        // Response headers go to stdout (`-`) like the body, or to a file
        // held to the same targets as `--output`.
        "--dump-header" => {
            value == "-"
                || value == "/dev/null"
                || output_targets::scratch_output_target(value, context)
        }
        "--user-agent" => !value.is_empty(),
        _ if NUMERIC_OPTIONS.contains(&option) => {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        }
        _ => false,
    }
}

fn safe_header(value: &str) -> bool {
    let Some((name, _)) = value.split_once(':') else {
        return false;
    };
    let name = name.trim().to_ascii_lowercase();
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !CREDENTIAL_TERMS.iter().any(|term| name.contains(term))
}

fn readable_url(raw: &str, context: super::PathContext<'_>) -> bool {
    public_url(raw) || loopback_url(raw, context.home_dir)
}

/// An `http(s)` URL naming `127.0.0.1` or `localhost` itself, on a dev-server
/// port that no local admin service or Guard daemon listens on.
pub(in crate::pretool) fn loopback_url(raw: &str, home_dir: Option<&str>) -> bool {
    if raw.contains(['{', '}', '[', ']', '\\', ' ']) {
        return false;
    }
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Domain(name)) => name == "localhost",
        _ => false,
    };
    loopback
        && matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default().is_some_and(|port| {
            super::loopback_ports::dev_server_port(port, &LOCAL_ADMIN_PORTS, home_dir)
        })
        && !url_secrets::carries_secret(&url)
}

fn public_url(raw: &str) -> bool {
    // curl expands `{a,b}` and `[1-9]` itself; an IPv6 literal also needs brackets.
    if raw.contains(['{', '}', '[', ']', '\\', ' ']) {
        return false;
    }
    if !super::generic::plain_public_url(raw) {
        return false;
    }
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    !RESERVED_SUFFIXES
        .iter()
        .any(|suffix| host.ends_with(suffix) || host == suffix[1..])
        && !url_secrets::carries_secret(&url)
}

#[cfg(test)]
#[path = "curl_reads_tests.rs"]
mod tests;
