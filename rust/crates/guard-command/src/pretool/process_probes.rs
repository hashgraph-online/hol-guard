//! Process and service probes that only report local state.
//!
//! * `lsof -i`: lists open network sockets and the processes that hold them,
//!   the view `ps aux` already gives for command lines. Only socket listings
//!   are admitted: an `-i` selector, `-s` state filters, `-p` process ids and
//!   the display flags `-n`, `-P`, `-t`, `-a`, `-l` and `-V`. lsof joins
//!   selectors with OR, so `-p` needs `-a` to stay a socket listing.
//! * `pg_isready`: asks a local PostgreSQL server whether it accepts
//!   connections and prints the answer. It sends no query and no password.
//!   The server is named by a loopback host or by an absolute Unix-socket
//!   directory such as `/tmp` or a Homebrew `var/postgresql@16`.
//!
//! Still reviewed:
//! - `lsof` with file or directory operands, `+` options, repeat mode (`-r`),
//!   output fields (`-F`), a host selector (`@host`) or any other option.
//! - `pg_isready` against any host other than `127.0.0.1`, `localhost`, `::1`
//!   or a socket directory, a connection string in `--dbname`, and any other
//!   option.

#[cfg(unix)]
use crate::pretool::directory_targets::path_trust::{steady_directory, unswappable};

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

/// A PostgreSQL host that never leaves the machine: a loopback name or address,
/// or an absolute Unix-socket directory (libpq reads a leading `/` that way).
/// A `,` would add a second host, `=` or `:` would start a connection string.
pub(in crate::pretool) fn local_postgres_host(value: &str) -> bool {
    LOOPBACK_HOSTS.contains(&value)
        || (value.starts_with('/')
            && value.len() <= 255
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-@+".contains(&byte)))
}

/// A Unix-socket directory where no other local user can stand in for the
/// server: libpq connects to `<dir>/.s.PGSQL.<port>`, and whoever owns that
/// socket answers the probe or query and can ask for a password. The
/// directory must belong to this user or root; a missing one passes only
/// below a directory nobody else can write, where no one can create it. In a private
/// directory a missing socket is fine, since nobody else can create one. A
/// directory others can write must be sticky, as `/tmp` is, and then every
/// socket psql may reach must already exist and belong to this user or root,
/// because a missing name could be planted before the client connects. Without
/// a port that means every socket present plus the default `5432` one.
pub(in crate::pretool) fn trusted_postgres_socket(host: &str, port: Option<&str>) -> bool {
    if !host.starts_with('/') {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = nix::unistd::getuid().as_raw();
        let Ok(directory) = std::fs::metadata(host) else {
            return missing_directory_protected(std::path::Path::new(host), uid);
        };
        let shared = directory.mode() & 0o022 != 0;
        if !directory.is_dir()
            || (directory.uid() != uid && directory.uid() != 0)
            || (shared && directory.mode() & 0o1000 == 0)
            || !unswappable(std::path::Path::new(host), uid, 0)
        {
            return false;
        }
        let owned = |path: &std::path::Path| match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.uid() == uid || metadata.uid() == 0,
            Err(error) => !shared && error.kind() == std::io::ErrorKind::NotFound,
        };
        let directory = std::path::Path::new(host);
        match port {
            Some(port) => owned(&directory.join(format!(".s.PGSQL.{port}"))),
            None => {
                (!shared || owned(&directory.join(".s.PGSQL.5432")))
                    && std::fs::read_dir(directory).is_ok_and(|entries| {
                        entries.into_iter().all(|entry| {
                            entry.is_ok_and(|entry| {
                                !entry.file_name().to_string_lossy().starts_with(".s.PGSQL.")
                                    || owned(&entry.path())
                            })
                        })
                    })
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = port;
        true
    }
}

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
    // The command text must name a local host: an omitted -h would take
    // the target from PGHOST or a service file. This bounds what the agent
    // wrote, not the inherited libpq environment (PGHOSTADDR or a service
    // `hostaddr` still overrides -h); that environment is the user's own
    // configuration, and the probe sends only a startup packet.
    let mut explicit_local = false;
    let (mut host, mut port_value) = (None, None);
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
                host = Some(value);
                explicit_local = local_postgres_host(value);
                explicit_local
            }
            "-p" | "--port" => {
                port_value = Some(value);
                port(value)
            }
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
    explicit_local && host.is_some_and(|host| trusted_postgres_socket(host, port_value))
}

pub(in crate::pretool) fn port(value: &str) -> bool {
    (1..=5).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port > 0)
}

/// A database or role name, never a connection string (`host=…`, a URI).
pub(in crate::pretool) fn plain_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// A missing socket directory nobody else can create or redirect: its
/// nearest existing ancestor is a real directory closed to other writers, and
/// every directory above it, both as spelled and as resolved, belongs to this
/// user or root and is closed or sticky, so no link along the way can be
/// swapped before psql connects.
#[cfg(unix)]
fn missing_directory_protected(path: &std::path::Path, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    if std::fs::symlink_metadata(path).is_ok() {
        return false;
    }
    let Some(existing) = path
        .ancestors()
        .skip(1)
        .find(|parent| std::fs::symlink_metadata(parent).is_ok())
    else {
        return false;
    };
    let Ok(resolved) = existing.canonicalize() else {
        return false;
    };
    std::fs::symlink_metadata(existing).is_ok_and(|metadata| {
        metadata.is_dir()
            && (metadata.uid() == uid || metadata.uid() == 0)
            && metadata.mode() & 0o022 == 0
    }) && existing
        .ancestors()
        .skip(1)
        .all(|path| steady_directory(path, uid))
        && resolved
            .ancestors()
            .skip(1)
            .all(|path| steady_directory(path, uid))
}

/// What a `psql` read inherits from the session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PsqlEnvironment {
    /// No startup variable is set and the shell's HOME is `home_dir`.
    pub startup_files_absent: bool,
    /// No routing variable is set.
    pub routing_unset: bool,
}

/// Variables that change which startup files psql reads; `-X` skips them.
pub(in crate::pretool) const PSQL_STARTUP_VARIABLES: [&str; 2] = ["PSQLRC", "PGSYSCONFDIR"];

/// Variables that change which server libpq reaches without `-h`, `-p` or
/// `service=` on the command line, with or without `-X`.
pub(in crate::pretool) const PSQL_ROUTING_VARIABLES: [&str; 5] = [
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGSERVICE",
    "PGSERVICEFILE",
];

/// Whether every ancestor of `path` is a [`steady_directory`] for this user.
#[cfg(all(test, unix))]
pub(in crate::pretool) fn steady_ancestry(path: &std::path::Path) -> bool {
    let uid = nix::unistd::getuid().as_raw();
    path.ancestors().all(|path| steady_directory(path, uid))
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
            "-h tmp",
            "-h /tmp,db.example.com",
            "-h @abstract",
            "-h /tmp/$(id)",
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

    #[cfg(unix)]
    #[test]
    fn a_socket_directory_any_user_can_write_is_not_a_trusted_server() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pg-isready-sockets")
            .join(std::process::id().to_string());
        let (open, group, shared, own) = (
            root.join("open"),
            root.join("group"),
            root.join("shared"),
            root.join("own"),
        );
        for (directory, mode) in [
            (&open, 0o777),
            (&group, 0o770),
            (&shared, 0o1777),
            (&own, 0o700),
        ] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::fs::write(own.join(".s.PGSQL.5432"), "").unwrap();
        let probe = |directory: &std::path::Path, port: &str| {
            safe_pg_isready_arguments(&arguments(&format!("-h {} {port}", directory.display())))
        };
        assert!(!probe(&open, "-q"));
        assert!(!probe(&open, "-p 5432"));
        assert!(!probe(&group, "-p 5432"));
        // A missing socket in a shared directory could be planted later.
        assert!(!probe(&shared, "-q"));
        assert!(!probe(&shared, "-p 55434"));
        std::fs::write(shared.join(".s.PGSQL.55434"), "").unwrap();
        assert!(probe(&shared, "-p 55434"));
        assert!(!probe(&shared, "-q"));
        std::fs::write(shared.join(".s.PGSQL.5432"), "").unwrap();
        assert!(probe(&shared, "-q"));
        // Only a missing directory nobody else could create passes.
        assert!(!probe(&open.join("missing"), "-p 5432"));
        assert!(!probe(&shared.join("missing"), "-p 5432"));
        // A link to a closed directory that another user could swap away.
        std::os::unix::fs::symlink(&own, open.join("link")).unwrap();
        assert!(!probe(&open.join("link/missing"), "-p 5432"));
        // The checkout's own ancestry decides the positive case on CI hosts.
        let steady = super::steady_ancestry(&root);
        assert_eq!(probe(&own.join("missing"), "-p 5432"), steady);
        assert!(probe(&own, "-q"));
        assert!(probe(&own, "-p 5432"));
        assert!(probe(&own, "-p 55434"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
