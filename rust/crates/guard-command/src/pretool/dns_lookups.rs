//! `dig`, `nslookup` and `host` lookups of a named host.
//!
//! A lookup asks the configured resolver, or a DNS server the command names,
//! for the records of one name and prints the answer. It reads no local file,
//! writes nothing, reads no standard input and never connects to the host it
//! asks about. A lookup of a fixed name therefore does less than the `curl`
//! GET of the same host that [`super::super::curl_reads`] already proves.
//! Before this proof a lookup ran in the network-less sandbox, where it could
//! only fail, and a chain holding one went to review.
//!
//! Still reviewed:
//! - a name or server built from an expansion or a glob, or one holding a
//!   long opaque label or a credential shape. The query carries the name to
//!   the DNS server, which is how data leaves through DNS.
//! - options that read a file (`dig -f` batch files, `-k` key files), carry
//!   a key (`-y`), pick a port or a source address (`-p`, `-b`,
//!   `nslookup -port=`), list a whole zone (`host -l`), and every option not
//!   listed below.
//! - a `dig` that may read a `~/.digrc` (one exists, or the home is unknown)
//!   without `-r`, and zone transfers (`AXFR`, `IXFR`).
//! - `nslookup` or `host` without a name: `nslookup` then reads commands from
//!   standard input.

use std::net::IpAddr;

/// What an argument is to the program reading it.
enum Word {
    /// An option that stands alone.
    Flag,
    /// An option whose value is the next argument.
    Value,
    /// An option with its value attached, already screened.
    Attached,
    /// A name, a record type or class, or a `@server`.
    Operand,
}

/// Whether `program`'s `arguments` form a plain lookup of fixed names.
/// `dig` also reads options from `~/.digrc`, which can name a batch or key
/// file, so it passes only with `-r` or when `rc_absent` says there is none.
pub(super) fn safe_lookup_arguments(program: &str, arguments: &[String], rc_absent: bool) -> bool {
    let mut operands = 0;
    let mut dig_no_rc = rc_absent;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        let word = match program {
            "dig" => dig_word(argument),
            "host" => host_word(argument),
            "nslookup" => nslookup_word(argument),
            _ => None,
        };
        match word {
            Some(Word::Flag | Word::Attached) => {
                if program == "dig" && argument == "-r" {
                    dig_no_rc = true;
                }
            }
            Some(Word::Value) => {
                let Some(value) = arguments.get(index) else {
                    return false;
                };
                index += 1;
                if is_zone_transfer(value) || !value_screen(argument)(value) {
                    return false;
                }
            }
            Some(Word::Operand) => {
                if is_zone_transfer(argument) {
                    return false;
                }
                operands += 1;
            }
            None => return false,
        }
    }
    if program == "dig" {
        dig_no_rc
    } else {
        (1..=2).contains(&operands)
    }
}

fn dig_word(argument: &str) -> Option<Word> {
    if let Some(option) = argument.strip_prefix('+') {
        return query_option(option).then_some(Word::Flag);
    }
    if let Some(server) = argument.strip_prefix('@') {
        return host_name(server).then_some(Word::Operand);
    }
    short_option(argument, "46hruv", "tcxq")
}

fn host_word(argument: &str) -> Option<Word> {
    short_option(argument, "aACdrsTUvVw46", "tcWNR")
}

fn nslookup_word(argument: &str) -> Option<Word> {
    const FLAGS: [&str; 16] = [
        "debug",
        "nodebug",
        "d2",
        "nod2",
        "vc",
        "novc",
        "recurse",
        "norecurse",
        "search",
        "nosearch",
        "defname",
        "nodefname",
        "fail",
        "nofail",
        "ignoretc",
        "noignoretc",
    ];
    const VALUES: [&str; 10] = [
        "type",
        "ty",
        "querytype",
        "query",
        "q",
        "class",
        "cl",
        "timeout",
        "retry",
        "ndots",
    ];
    let Some(option) = argument.strip_prefix('-') else {
        return host_name(argument).then_some(Word::Operand);
    };
    if FLAGS.contains(&option) {
        return Some(Word::Flag);
    }
    let (name, value) = option.split_once('=')?;
    (VALUES.contains(&name) && plain_word(value) && !is_zone_transfer(value))
        .then_some(Word::Attached)
}

/// A single-letter option from `flags` or `values`, or a name operand.
fn short_option(argument: &str, flags: &str, values: &str) -> Option<Word> {
    let Some(option) = argument.strip_prefix('-') else {
        return host_name(argument).then_some(Word::Operand);
    };
    let mut letters = option.chars();
    let letter = letters.next()?;
    let rest = letters.as_str();
    if flags.contains(letter) && rest.is_empty() {
        return Some(Word::Flag);
    }
    if !values.contains(letter) {
        return None;
    }
    if rest.is_empty() {
        return Some(Word::Value);
    }
    (!is_zone_transfer(rest) && value_screen(argument)(rest)).then_some(Word::Attached)
}

/// How the value of a short option is screened: a reverse lookup (`-x`) or
/// a query name (`-q`) is a host name, everything else a plain word.
fn value_screen(option: &str) -> fn(&str) -> bool {
    if option.starts_with("-x") || option.starts_with("-q") {
        host_name
    } else {
        plain_word
    }
}

/// A `dig` query option: `+short`, `+noall`, `+time=2`. None of them reads
/// or writes a file.
fn query_option(option: &str) -> bool {
    let (name, value) = option.split_once('=').unwrap_or((option, "x"));
    !name.is_empty()
        && name.len() <= 24
        && name.bytes().all(|byte| byte.is_ascii_lowercase())
        && plain_word(value)
}

/// Zone transfers are deliberately outside the fixed-record lookup proof.
fn is_zone_transfer(value: &str) -> bool {
    value.eq_ignore_ascii_case("AXFR") || value.eq_ignore_ascii_case("IXFR")
}

/// A record type, a class, a count or a number of seconds.
fn plain_word(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// A literal address, or a host name of letters, digits, `-` and `_` in
/// labels short enough not to carry encoded data.
fn host_name(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    (1..=253).contains(&name.len())
        && name.split('.').all(|label| {
            (1..48).contains(&label.len())
                && !label.starts_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && !super::super::curl_reads::url_secrets::text_carries_secret(name)
}

#[cfg(test)]
#[path = "dns_lookups_tests.rs"]
mod tests;
