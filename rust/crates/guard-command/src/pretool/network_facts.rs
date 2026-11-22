//! Asking the machine how it is attached to the network.
//!
//! A session that cannot reach its dev server looks at the interfaces, the
//! routing table, the listening sockets and the resolver before it changes
//! anything. `lsof -i`, `nc -z` and `nslookup` already read past review, and
//! `netstat`, `ss`, `ifconfig`, `ip`, `route get`, `arp`, `scutil` and
//! `ipconfig get...` ask the same question of the same tables, so the answer
//! should not depend on which of them the agent reached for.
//!
//! Every name here prints a table the kernel already holds. Four of them also
//! carry a writing half, and this screen admits neither it nor anything that
//! could be read as it:
//!
//! * `ifconfig IFACE inet ADDRESS` configures an interface, so a second
//!   operand refuses the proof: one interface name, and nothing after it.
//!   Its flag list holds only the report flags, because `ifconfig IFACE
//!   -alias` and its neighbours are spelled like one.
//! * `ip` is almost entirely a configuration tool. Only its reporting objects
//!   are admitted, and only with `show`, `list` or `get` -- which is also what
//!   it does with no verb at all. `add`, `del`, `set`, `change`, `replace`,
//!   `flush` and `append` keep their review.
//! * `route add` and `route delete` edit the routing table; only `route get`
//!   is a read.
//! * `arp -d`, `-s` and `-f` delete, publish and load entries, so the flag
//!   list holds only the report flags, and `-f` would open a file besides.
//! * `ss --kill` closes the sockets it matched, and `-K` is its short
//!   spelling, so both refuse the proof.
//!
//! `scutil` reads the resolver and proxy state with `--dns`, `--proxy` and
//! `--nwi`, and sets the host's names with `--set`; only the reading options
//! are listed. macOS `ipconfig` reads with the `get...` verbs and reconfigures
//! with `set`, so the verb has to begin with `get`.
//!
//! None of these opens a file the caller names, and an option this screen does
//! not know refuses the whole line rather than being skipped, so no value is
//! ever read as a file name.

/// A reader of the interface, routing, neighbour or resolver tables.
pub(super) fn safe_network_fact(basename: &str, arguments: &[String]) -> bool {
    match basename {
        "netstat" => flag_words(arguments),
        "ss" => socket_statistics_arguments(arguments),
        "ifconfig" => interface_arguments(arguments),
        "ip" => ip_arguments(arguments),
        "route" => route_arguments(arguments),
        "arp" => address_table_arguments(arguments),
        "scutil" => configuration_arguments(arguments),
        "ipconfig" => address_client_arguments(arguments),
        _ => false,
    }
}

/// Every word is a report flag: no operand, so no file and no address.
fn flag_words(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| report_flag(argument))
}

/// A short or long report flag, with no value attached to it.
fn report_flag(word: &str) -> bool {
    let body = match word.strip_prefix("--") {
        Some(long) => long,
        None => match word.strip_prefix('-') {
            Some(short) => short,
            None => return false,
        },
    };
    !body.is_empty()
        && body.len() <= 32
        && body
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// `ss` reporting on sockets, never closing one.
fn socket_statistics_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        !matches!(argument.as_str(), "-K" | "--kill")
            && !argument.starts_with("-K")
            && report_flag(argument)
    })
}

/// `ifconfig` printing one interface or all of them.
///
/// A configuration line is the interface name followed by what to set on it,
/// so a second operand refuses the proof.
fn interface_arguments(arguments: &[String]) -> bool {
    let mut operands = 0;
    for argument in arguments {
        if argument.starts_with('-') {
            if !matches!(
                argument.as_str(),
                "-a" | "-L" | "-m" | "-r" | "-v" | "-u" | "-d" | "-l" | "-C" | "-s"
            ) {
                return false;
            }
            continue;
        }
        operands += 1;
        if operands > 1 || !interface_name(argument) {
            return false;
        }
    }
    true
}

/// `ip OBJECT [show|list|get]`, the reporting half of the tool.
fn ip_arguments(arguments: &[String]) -> bool {
    let mut remaining = arguments;
    while let Some((word, rest)) = remaining.split_first() {
        if !word.starts_with('-') {
            break;
        }
        if !matches!(
            word.as_str(),
            "-4" | "-6"
                | "-br"
                | "-brief"
                | "-d"
                | "-details"
                | "-s"
                | "-stats"
                | "-o"
                | "-oneline"
                | "-c"
                | "-color"
                | "-j"
                | "-json"
                | "-n"
                | "-numeric"
        ) {
            return false;
        }
        remaining = rest;
    }
    let Some((object, rest)) = remaining.split_first() else {
        return false;
    };
    if !matches!(
        object.as_str(),
        "addr"
            | "address"
            | "a"
            | "link"
            | "l"
            | "route"
            | "r"
            | "ro"
            | "neigh"
            | "neighbour"
            | "neighbor"
            | "n"
            | "rule"
            | "maddr"
            | "tunnel"
    ) {
        return false;
    }
    let Some((verb, operands)) = rest.split_first() else {
        return true;
    };
    matches!(verb.as_str(), "show" | "list" | "ls" | "get" | "sh")
        && operands.iter().all(|operand| address_word(operand))
}

/// `route get DESTINATION`, the one `route` spelling that reads.
fn route_arguments(arguments: &[String]) -> bool {
    let mut remaining = arguments;
    while let Some((word, rest)) = remaining.split_first() {
        if !word.starts_with('-') {
            break;
        }
        if !matches!(word.as_str(), "-n" | "-v" | "-inet" | "-inet6") {
            return false;
        }
        remaining = rest;
    }
    let Some((verb, operands)) = remaining.split_first() else {
        return false;
    };
    verb == "get" && !operands.is_empty() && operands.iter().all(|operand| address_word(operand))
}

/// `arp` printing the neighbour table.
fn address_table_arguments(arguments: &[String]) -> bool {
    let mut operands = 0;
    for argument in arguments {
        if argument.starts_with('-') {
            if !matches!(argument.as_str(), "-a" | "-n" | "-l" | "-e" | "-v") {
                return false;
            }
            continue;
        }
        operands += 1;
        if operands > 1 || !address_word(argument) {
            return false;
        }
    }
    true
}

/// `scutil` reading the resolver, proxy and network-interest state.
fn configuration_arguments(arguments: &[String]) -> bool {
    match arguments {
        [option] => matches!(option.as_str(), "--dns" | "--proxy" | "--nwi" | "--nc"),
        [option, key] => option == "--get" && interface_name(key),
        _ => false,
    }
}

/// macOS `ipconfig` with a reading verb.
fn address_client_arguments(arguments: &[String]) -> bool {
    let Some((verb, operands)) = arguments.split_first() else {
        return false;
    };
    verb.starts_with("get")
        && verb.len() <= 32
        && verb
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        && operands.len() <= 2
        && operands.iter().all(|operand| interface_name(operand))
}

/// An interface or configuration key: a plain word, never a path.
fn interface_name(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 64
        && !word.starts_with('-')
        && word
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
}

/// An address, prefix or host name operand: no path separator, no option.
fn address_word(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 128
        && !word.starts_with('-')
        && word.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '-' | '_' | '/')
        })
        && !word.contains("//")
        && word.matches('/').count() <= 1
}

#[cfg(test)]
#[path = "network_facts_tests.rs"]
mod network_facts_tests;
