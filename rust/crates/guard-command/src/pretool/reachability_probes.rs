//! Asking whether a host answers, and what the resolver knows about it.
//!
//! A session whose request timed out asks the next question before it changes
//! anything: is the host up, where does the path stop, who owns the name. `nc
//! -z` and the `dig`/`host`/`nslookup` lookups beside this module already read
//! past review, but `ping`, `traceroute`, `whois` and `getent hosts` did not,
//! so the same question reached review or not depending on which tool the
//! agent picked.
//!
//! None of these opens a file the caller names, writes one, reads standard
//! input or starts another program. What they do carry is the name itself:
//! the query leaves the machine, which is how data leaves through DNS or a
//! whois registry. That is the same channel the lookups beside this module
//! already accept, so the operand is screened the same way -- a fixed host
//! name or address, with no expansion, no long opaque label and no credential
//! shape.
//!
//! Each option list is written per name, because several of these programs
//! carry a half that is no longer a probe:
//!
//! * `ping -p PATTERN` puts caller-chosen bytes in the payload, `-f` floods
//!   the target, `-l PRELOAD` sends its first packets as fast as it can,
//!   `-A` paces itself by the answers rather than by a clock, and `-S`/`-I`
//!   choose the source. Only the counting, pacing and formatting options are
//!   admitted, and `-i 0` is refused with them: for a privileged caller each
//!   of those three sends at the rate `-f` does, so the admitted pacing is a
//!   whole second or more.
//! * `traceroute -g GATEWAY` source-routes the probe, `-s` sets the source
//!   address and `-p` the destination port. Only the hop, query and wait
//!   limits are admitted.
//! * `whois -h HOST` sends the query text to any server the caller names, so
//!   the proof admits only the configured registry.
//! * `getent` reads the name-service databases, and `passwd`, `shadow` and
//!   `group` are account records rather than network facts. Only the host,
//!   service, protocol and network databases are admitted.
//!
//! An option a screen does not know refuses the whole line rather than being
//! skipped, so a value can never be read as a file name.

use super::dns_lookups::host_name;

/// Whether `program` is a reachability probe this module screens.
pub(super) fn proves(program: &str) -> bool {
    matches!(
        program,
        "ping" | "ping6" | "traceroute" | "traceroute6" | "whois" | "getent"
    )
}

/// Whether `program`'s `arguments` form a plain probe of a fixed name.
pub(super) fn safe_probe_arguments(program: &str, arguments: &[String]) -> bool {
    match program {
        "ping" | "ping6" => one_target(arguments, &PING_FLAGS, &PING_COUNTS),
        "traceroute" | "traceroute6" => trace_arguments(arguments),
        "whois" => matches!(arguments, [name] if host_name(name)),
        "getent" => getent_arguments(arguments),
        _ => false,
    }
}

/// `ping` options that stand alone: numeric output, quiet and verbose
/// reporting, a timestamp, and the address-family choices. `-A` is
/// deliberately absent: adaptive pacing sends the next packet as the last is
/// answered, which for a privileged caller drops the floor between packets
/// altogether, the same traffic `-f` is refused for.
const PING_FLAGS: [&str; 6] = ["-n", "-q", "-v", "-D", "-4", "-6"];

/// `ping` options whose value is a count, an interval or a deadline. Each is
/// a small number of packets or seconds, never a file or an address.
/// `-l PRELOAD` is deliberately absent: it sends that many packets at once
/// before the pacing starts, which is the flood `-f` is refused for.
const PING_COUNTS: [&str; 5] = ["-c", "-i", "-W", "-w", "-t"];

/// `traceroute` options that stand alone.
const TRACE_FLAGS: [&str; 5] = ["-n", "-I", "-4", "-6", "-d"];

/// `traceroute` options whose value is a hop, query or wait limit.
const TRACE_COUNTS: [&str; 5] = ["-m", "-q", "-w", "-f", "-z"];

/// One host operand preceded by options from the two lists.
fn one_target(arguments: &[String], flags: &[&str], counts: &[&str]) -> bool {
    let mut targets = 0;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if flags.contains(&argument) {
            continue;
        }
        if counts.contains(&argument) {
            let Some(value) = arguments.get(index) else {
                return false;
            };
            index += 1;
            if !small_number(value) || (argument == "-i" && !paced(value)) {
                return false;
            }
            continue;
        }
        if argument.starts_with('-') || !host_name(argument) {
            return false;
        }
        targets += 1;
    }
    targets == 1
}

/// `traceroute` takes the same shape with its own option lists, and may carry
/// a trailing probe size after the host.
fn trace_arguments(arguments: &[String]) -> bool {
    let mut targets = 0;
    let mut size = 0;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if TRACE_FLAGS.contains(&argument) {
            continue;
        }
        if TRACE_COUNTS.contains(&argument) {
            let Some(value) = arguments.get(index) else {
                return false;
            };
            index += 1;
            if !small_number(value) {
                return false;
            }
            continue;
        }
        if argument.starts_with('-') {
            return false;
        }
        if targets == 1 && small_number(argument) {
            size += 1;
            continue;
        }
        if !host_name(argument) {
            return false;
        }
        targets += 1;
    }
    targets == 1 && size <= 1
}

/// The name-service databases that hold network facts, with plain keys.
fn getent_arguments(arguments: &[String]) -> bool {
    const DATABASES: [&str; 8] = [
        "hosts",
        "ahosts",
        "ahostsv4",
        "ahostsv6",
        "services",
        "protocols",
        "networks",
        "rpc",
    ];
    let Some((database, keys)) = arguments.split_first() else {
        return false;
    };
    DATABASES.contains(&database.as_str())
        && !keys.is_empty()
        && keys.iter().all(|key| host_name(key))
}

/// A probe count, interval, hop limit or size: a plain number, at most five
/// digits, that no program reads as a file name.
/// `ping -i 0` sends the next packet as soon as the last one is answered,
/// which is the flood `-f` is refused for written another way. A probe paces
/// itself by a whole second or more.
fn paced(value: &str) -> bool {
    value.bytes().any(|byte| byte != b'0')
}

fn small_number(value: &str) -> bool {
    (1..=5).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
#[path = "reachability_probes_tests.rs"]
mod tests;
