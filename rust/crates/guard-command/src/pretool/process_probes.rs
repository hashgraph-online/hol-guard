//! Process and service probes that only report local state.
//!
//! * `lsof -i`: lists open network sockets and the processes that hold them,
//!   the view `ps aux` already gives for command lines. Only socket listings
//!   are admitted: an `-i` selector, `-s` state filters, `-p` process ids and
//!   the display flags `-n`, `-P`, `-t`, `-a`, `-l` and `-V`. lsof joins
//!   selectors with OR, so `-p` needs `-a` to stay a socket listing.
//! * `pg_isready`: asks a local PostgreSQL server whether it accepts
//!   connections and prints the answer. It sends no query and no password.
//!
//! Still reviewed:
//! - `lsof` with file or directory operands, `+` options, repeat mode (`-r`),
//!   output fields (`-F`), a host selector (`@host`) or any other option.
//! - `pg_isready` against any host other than `127.0.0.1`, `localhost` or
//!   `::1`, a connection string in `--dbname`, and any other option.

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

pub(in crate::pretool) fn safe_lsof_arguments(arguments: &[String]) -> bool {
    let mut network = false;
    let mut pid = false;
    let mut and = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        let Some(cluster) = argument.strip_prefix('-') else {
            return false;
        };
        if cluster.is_empty() || cluster.starts_with('-') || !cluster.is_ascii() {
            return false;
        }
        for (offset, flag) in cluster.char_indices() {
            let rest = &cluster[offset + flag.len_utf8()..];
            match flag {
                'a' => {
                    and = true;
                    continue;
                }
                'n' | 'P' | 't' | 'l' | 'V' => continue,
                'i' => {
                    network = true;
                    if !rest.is_empty() {
                        if !socket_selector(rest) {
                            return false;
                        }
                    } else if let Some(next) = arguments.get(index) {
                        if socket_selector_start(next) {
                            if !socket_selector(next) {
                                return false;
                            }
                            index += 1;
                        }
                    }
                }
                's' => {
                    if !rest.is_empty() {
                        if !state_filter(rest) {
                            return false;
                        }
                    } else if arguments.get(index).is_some_and(|next| state_filter(next)) {
                        index += 1;
                    }
                }
                'p' => {
                    pid = true;
                    let value = if rest.is_empty() {
                        let Some(value) = arguments.get(index) else {
                            return false;
                        };
                        index += 1;
                        value.as_str()
                    } else {
                        rest
                    };
                    if !process_ids(value) {
                        return false;
                    }
                }
                _ => return false,
            }
            break;
        }
    }
    // Without `-a`, `-p` also lists every open file of that process.
    network && (!pid || and)
}

/// `[46][protocol][:port]`, for example `:5432`, `TCP:3000`, `4tcp` or
/// `:3000-3010`. A host part (`@host`) is not admitted.
fn socket_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b',' | b'-'))
}

fn socket_selector_start(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    ["4", "6", ":", "tcp", "udp"]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

/// `TCP:LISTEN` or `UDP:Idle,^Unbound`.
fn state_filter(value: &str) -> bool {
    let Some((protocol, states)) = value.split_once(':') else {
        return false;
    };
    matches!(protocol.to_ascii_uppercase().as_str(), "TCP" | "UDP")
        && !states.is_empty()
        && states.len() <= 64
        && states
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b',' | b'^'))
}

fn process_ids(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'^'))
}

pub(in crate::pretool) fn safe_pg_isready_arguments(arguments: &[String]) -> bool {
    // The command text must name a loopback host: an omitted -h would take
    // the target from PGHOST or a service file. This bounds what the agent
    // wrote, not the inherited libpq environment (PGHOSTADDR or a service
    // `hostaddr` still overrides -h); that environment is the user's own
    // configuration, and the probe sends only a startup packet.
    let mut explicit_loopback = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if !argument.is_ascii() {
            return false;
        }
        if matches!(argument, "-q" | "--quiet") {
            continue;
        }
        let (option, attached) = match argument.split_once('=') {
            Some((option, value)) if option.starts_with("--") => (option, Some(value)),
            _ if argument.len() > 2 && argument.starts_with('-') && !argument.starts_with("--") => {
                (&argument[..2], Some(&argument[2..]))
            }
            _ => (argument, None),
        };
        let value = match attached {
            Some(value) => value,
            None => {
                let Some(value) = arguments.get(index) else {
                    return false;
                };
                index += 1;
                value.as_str()
            }
        };
        let valid = match option {
            "-h" | "--host" => {
                explicit_loopback = LOOPBACK_HOSTS.contains(&value);
                explicit_loopback
            }
            "-p" | "--port" => port(value),
            "-t" | "--timeout" => {
                (1..=3).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
            }
            "-d" | "--dbname" | "-U" | "--username" => plain_name(value),
            _ => false,
        };
        if !valid {
            return false;
        }
    }
    explicit_loopback
}

fn port(value: &str) -> bool {
    (1..=5).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port > 0)
}

/// A database or role name, never a connection string (`host=…`, a URI).
fn plain_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{safe_lsof_arguments, safe_pg_isready_arguments};

    fn arguments(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn socket_listings_and_local_readiness_checks_are_admitted() {
        for command in [
            "-i",
            "-i :5432",
            "-i:3000",
            "-ti:3000",
            "-ti :3000",
            "-nP -iTCP:5432 -sTCP:LISTEN",
            "-nP -iTCP -sTCP:LISTEN",
            "-i4 -a -p 123,456",
            "-ai -p 123",
            "-i tcp:8000-8010",
        ] {
            assert!(safe_lsof_arguments(&arguments(command)), "lsof {command}");
        }
        for command in [
            "-h localhost -q",
            "-h localhost -p 5432",
            "--host=127.0.0.1 --port=5432 -t 3",
            "-h ::1 -d app_dev -U app_user",
        ] {
            assert!(
                safe_pg_isready_arguments(&arguments(command)),
                "pg_isready {command}"
            );
        }
    }

    #[test]
    fn file_operands_hosts_and_connection_strings_are_refused() {
        for command in [
            "",
            "-n",
            "/usr/local",
            "-i :5432 /usr/local",
            "+D /usr/local",
            "-i @example.com",
            "-i TCP@example.com:443",
            "-r 1 -i",
            "-F n -i",
            "-p",
            "-p self -i",
            "-i -p 123",
            "-ip 123",
            "--help",
        ] {
            assert!(!safe_lsof_arguments(&arguments(command)), "lsof {command}");
        }
        for command in [
            "",
            "-q",
            "-d app_dev -U app_user",
            "-h db.example.com",
            "--host=10.0.0.5",
            "-d host=db.example.com",
            "-d postgresql://db.example.com/app",
            "-p 0",
            "-p",
            "-x",
            "app",
        ] {
            assert!(
                !safe_pg_isready_arguments(&arguments(command)),
                "pg_isready {command}"
            );
        }
    }
}
