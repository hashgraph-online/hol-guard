//! `nc -z` reachability checks against a loopback port.
//!
//! Zero-I/O mode opens a TCP connection, reports whether it succeeded and
//! closes it without reading or sending data. Against loopback that only
//! answers whether a local dev server is listening, the same thing `lsof -i`
//! or a failed `curl localhost` tells the agent.
//!
//! Still reviewed:
//! - any host other than `127.0.0.1`, `localhost` or `::1`.
//! - `nc` reading from a pipe, and every mode that moves data or runs code:
//!   listening (`-l`), `-e`/`-c` execution, UDP (`-u`, whose scan sends
//!   bytes), proxies (`-x`/`-X`), Unix sockets (`-U`), source binding and any
//!   option not listed below.
//! - `ncat` and `socat`, whose option sets differ.

/// Single-letter flags that may be clustered with `-z` (`-zv`, `-vz`).
const SHORT_FLAGS: &str = "zvn46";
/// Single-letter options that take a timeout in seconds. They end a cluster.
const SHORT_VALUES: &str = "wG";

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

pub(super) fn safe_nc_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix" && segment.pipeline_index == 0 && safe_nc_arguments(&segment.arguments)
}

/// A whole `nc`/`netcat` segment, generic checks included, that the native
/// proof accepts as a zero-I/O loopback probe. It reads no standard input and
/// sends nothing, so the compatibility layer does not treat it as an upload.
pub(crate) fn proven_probe_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    matches!(segment.executable.as_deref(), Some("nc" | "netcat"))
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

pub(super) fn safe_nc_arguments(arguments: &[String]) -> bool {
    let mut zero_io = false;
    let mut positionals: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        let Some(flags) = argument.strip_prefix('-') else {
            positionals.push(argument);
            continue;
        };
        if flags.is_empty() || flags.starts_with('-') {
            return false;
        }
        for (offset, flag) in flags.char_indices() {
            if SHORT_FLAGS.contains(flag) {
                zero_io |= flag == 'z';
                continue;
            }
            if !SHORT_VALUES.contains(flag) {
                return false;
            }
            let attached = &flags[offset + flag.len_utf8()..];
            let value = if attached.is_empty() {
                let Some(value) = arguments.get(index) else {
                    return false;
                };
                index += 1;
                value.as_str()
            } else {
                attached
            };
            if !timeout_seconds(value) {
                return false;
            }
            break;
        }
    }
    zero_io
        && matches!(positionals.as_slice(), [host, ports]
            if LOOPBACK_HOSTS.contains(host) && port_spec(ports))
}

fn timeout_seconds(value: &str) -> bool {
    (1..=3).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// One port or an ascending `low-high` range.
fn port_spec(value: &str) -> bool {
    match value.split_once('-') {
        Some((low, high)) => match (port(low), port(high)) {
            (Some(low), Some(high)) => low <= high,
            _ => false,
        },
        None => port(value).is_some(),
    }
}

fn port(value: &str) -> Option<u16> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port > 0)
}

#[cfg(test)]
mod tests {
    use super::safe_nc_arguments;

    fn arguments(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn loopback_zero_io_probes_are_admitted() {
        for command in [
            "-z 127.0.0.1 55433",
            "-zv localhost 5432",
            "-vz ::1 8080",
            "-z -w 2 127.0.0.1 3000",
            "-zw2 127.0.0.1 3000",
            "-z -G 3 localhost 6379",
            "-zn 127.0.0.1 8000-8010",
        ] {
            assert!(safe_nc_arguments(&arguments(command)), "{command}");
        }
    }

    #[test]
    fn data_moving_or_non_loopback_forms_are_refused() {
        for command in [
            "127.0.0.1 55433",
            "-v 127.0.0.1 55433",
            "-z example.com 443",
            "-z 10.0.0.5 22",
            "-z 169.254.169.254 80",
            "-z 127.0.0.2 80",
            "-z 127.0.0.1",
            "-z 127.0.0.1 80 81",
            "-z 127.0.0.1 0",
            "-z 127.0.0.1 70000",
            "-z 127.0.0.1 90-80",
            "-z 127.0.0.1 http",
            "-zu 127.0.0.1 53",
            "-z -u 127.0.0.1 53",
            "-l 55433",
            "-zl 127.0.0.1 55433",
            "-z -e /bin/sh 127.0.0.1 55433",
            "-z -c sh 127.0.0.1 55433",
            "-z -x proxy.example.com:1080 127.0.0.1 22",
            "-z -X 5 127.0.0.1 22",
            "-z -U /tmp/socket",
            "-z -s 127.0.0.1 127.0.0.1 80",
            "-z -p 4444 127.0.0.1 80",
            "-z -w 127.0.0.1 80",
            "-z -w 1000 127.0.0.1 80",
            "-z --wait 1 127.0.0.1 80",
            "-z - 127.0.0.1 80",
        ] {
            assert!(!safe_nc_arguments(&arguments(command)), "{command}");
        }
    }
}
