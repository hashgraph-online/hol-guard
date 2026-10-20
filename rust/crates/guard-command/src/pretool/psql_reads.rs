//! Read-only `psql` against a local server: `-l`/`--list`, or one `-c`
//! statement that `psql_statement` proves is a plain `SELECT` or `SHOW`.
//!
//! The host must be loopback or an absolute Unix-socket directory, the port a
//! number, and the database and role plain names, never a connection string
//! or URI. Without `-h`, psql uses its default local socket unless the user's
//! own `PGHOST`, `PGSERVICE` or service file names another server; that
//! inherited configuration is the user's, as it is for `pg_isready`. Inline
//! environment assignments never reach this proof.
//!
//! Without `-X`, psql runs the system `psqlrc` (part of the install, trusted
//! as Git's template directory is, unless `PGSYSCONFDIR` moves it), then
//! `PSQLRC` or `~/.psqlrc`, any of which can run `\!` shell commands. Such a
//! read is admitted only when none can exist. A Unix-socket directory, named
//! or the shared `/tmp` default when `-h` is absent, must also be one no
//! other user can plant a server socket in.
//!
//! Still reviewed: script files (`-f`), output and log files (`-o`, `-L`),
//! variables other than `ON_ERROR_STOP`, print settings other than the pager
//! and footer, a second `-c`, an interactive session (neither `-c` nor `-l`,
//! so psql would read standard input), a remote host, and any other option.

#[path = "psql_statement.rs"]
mod psql_statement;

use crate::pretool::safe_scalar::{
    local_postgres_host, postgres_name, postgres_port, trusted_postgres_socket,
};
use psql_statement::read_only_statement;
use std::path::Path;

/// Output-shaping flags: list databases, unaligned, tuples only, quiet,
/// skip `~/.psqlrc`, never prompt for a password, expanded rows.
const FLAGS: &str = "lAtqXwx";
/// Short options that take a value, attached or as the next argument.
const VALUED: &str = "cdFhPpUv";

#[derive(Default)]
struct Invocation {
    list: bool,
    command: bool,
    no_psqlrc: bool,
    host: Option<String>,
    port: Option<String>,
    positionals: usize,
}

impl Invocation {
    fn flag(&mut self, flag: char) {
        self.list |= flag == 'l';
        self.no_psqlrc |= flag == 'X';
    }

    fn valued(&mut self, option: char, value: &str) -> bool {
        match option {
            'c' if !self.command => {
                self.command = true;
                read_only_statement(value)
            }
            'h' => {
                self.host = Some(value.to_owned());
                local_postgres_host(value)
            }
            'p' => {
                self.port = Some(value.to_owned());
                postgres_port(value)
            }
            'd' | 'U' => postgres_name(value),
            'P' => matches!(value, "pager=off" | "pager=0" | "footer=off"),
            'v' => value.split_once('=').is_some_and(|(name, setting)| {
                name == "ON_ERROR_STOP"
                    && matches!(
                        setting.to_ascii_lowercase().as_str(),
                        "0" | "1" | "on" | "off" | "true" | "false"
                    )
            }),
            'F' => (1..=4).contains(&value.len()) && !value.contains(['\\', '\0']),
            _ => false,
        }
    }
}

fn long_option(name: &str) -> Option<char> {
    Some(match name {
        "list" => 'l',
        "no-align" => 'A',
        "tuples-only" => 't',
        "quiet" => 'q',
        "no-psqlrc" => 'X',
        "no-password" => 'w',
        "expanded" => 'x',
        "command" => 'c',
        "dbname" => 'd',
        "field-separator" => 'F',
        "host" => 'h',
        "pset" => 'P',
        "port" => 'p',
        "username" => 'U',
        "set" | "variable" => 'v',
        _ => return None,
    })
}

pub(in crate::pretool) fn safe_psql_arguments(
    arguments: &[String],
    context: crate::pretool::PathContext<'_>,
) -> bool {
    context.psql_environment.routing_unset
        && admitted(arguments, trusted_default_socket, || {
            context.psql_environment.startup_files_absent
                && startup_files_absent(
                    context.home_dir,
                    std::env::var_os("PSQLRC").as_deref(),
                    std::env::var_os("HOME").as_deref(),
                    std::env::var_os("APPDATA").as_deref(),
                )
        })
}

/// Whether psql would read `PSQLRC` or a home startup file: no `-X`.
pub(in crate::pretool) fn psql_reads_startup_files(arguments: &[String]) -> bool {
    parse(arguments).is_none_or(|invocation| !invocation.no_psqlrc)
}

/// The default socket directory other users can write: upstream builds
/// (Homebrew, Postgres.app) use `/tmp`. Debian's and Red Hat's run directory
/// is writable only by the server account, so nobody else can plant there.
const SHARED_DEFAULT_SOCKET_DIRECTORY: &str = "/tmp";
const SYSTEM_SOCKET_DIRECTORIES: &[&str] = &["/run/postgresql", "/var/run/postgresql"];

/// Where psql connects without `-h`: a trusted `/tmp` socket, or, when `/tmp`
/// holds no socket for the port, a distribution's server-only run directory,
/// but only for a Debian-packaged psql whose libpq defaults to it. Other
/// builds default to `/tmp`, where a missing name could be planted.
fn trusted_default_socket(port: Option<&str>) -> bool {
    let name = format!(".s.PGSQL.{}", port.unwrap_or("5432"));
    trusted_postgres_socket(SHARED_DEFAULT_SOCKET_DIRECTORY, port)
        || (std::fs::symlink_metadata(Path::new(SHARED_DEFAULT_SOCKET_DIRECTORY).join(name))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            && first_psql(std::env::var_os("PATH").as_deref())
                .is_some_and(|psql| distribution_client(&psql))
            && SYSTEM_SOCKET_DIRECTORIES
                .iter()
                .any(|directory| Path::new(directory).is_dir()))
}

/// The psql `PATH` runs; unknown once a relative or empty entry precedes it.
fn first_psql(path: Option<&std::ffi::OsStr>) -> Option<std::path::PathBuf> {
    std::env::split_paths(path?)
        .map(|directory| directory.is_absolute().then(|| directory.join("psql")))
        .find(|candidate| candidate.as_ref().is_none_or(|psql| psql.is_file()))
        .flatten()
        .and_then(|psql| psql.canonicalize().ok())
}

/// Debian's client wrapper or a binary below its versioned client tree.
fn distribution_client(psql: &Path) -> bool {
    psql == Path::new("/usr/share/postgresql-common/pg_wrapper")
        || psql.starts_with("/usr/lib/postgresql")
}

fn admitted(
    arguments: &[String],
    default_socket: impl FnOnce(Option<&str>) -> bool,
    startup_files_absent: impl FnOnce() -> bool,
) -> bool {
    parse(arguments).is_some_and(|invocation| {
        (invocation.list || invocation.command)
            && match invocation.host.as_deref() {
                Some(host) => trusted_postgres_socket(host, invocation.port.as_deref()),
                None => default_socket(invocation.port.as_deref()),
            }
            && (invocation.no_psqlrc || startup_files_absent())
    })
}

/// No startup file psql would run without `-X`: `PSQLRC` unset or empty, no
/// `.psqlrc[-<version>]` in the account or shell `HOME` (`%APPDATA%\postgresql\psqlrc.conf`
/// on Windows), names compared without case as a case-insensitive filesystem opens them.
fn startup_files_absent(
    home_dir: Option<&str>,
    psqlrc: Option<&std::ffi::OsStr>,
    shell_home: Option<&std::ffi::OsStr>,
    appdata: Option<&std::ffi::OsStr>,
) -> bool {
    let Some(home) = home_dir.map(Path::new).filter(|home| home.is_absolute()) else {
        return false;
    };
    set(psqlrc).is_none()
        && std::env::var_os("PGSYSCONFDIR").is_none()
        && no_startup_file(home, ".psqlrc")
        && set(shell_home).is_none_or(|shell| no_startup_file(Path::new(shell), ".psqlrc"))
        && set(appdata).is_none_or(|appdata| {
            no_startup_file(&Path::new(appdata).join("postgresql"), "psqlrc.conf")
        })
}

fn set(value: Option<&std::ffi::OsStr>) -> Option<&std::ffi::OsStr> {
    value.filter(|value| !value.is_empty())
}

fn no_startup_file(directory: &Path, name: &str) -> bool {
    let versioned = format!("{name}-");
    match std::fs::read_dir(directory) {
        Ok(entries) => entries.into_iter().all(|entry| {
            entry.is_ok_and(|entry| {
                let file = entry.file_name().to_string_lossy().to_ascii_lowercase();
                file != name && !file.starts_with(&versioned)
            })
        }),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

fn parse(arguments: &[String]) -> Option<Invocation> {
    let mut invocation = Invocation::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if let Some(long) = argument.strip_prefix("--") {
            if long == "csv" {
                continue;
            }
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let option = long_option(name)?;
            if FLAGS.contains(option) {
                if attached.is_some() {
                    return None;
                }
                invocation.flag(option);
                continue;
            }
            let value = match attached {
                Some(value) => value,
                None => {
                    let value = arguments.get(index)?;
                    index += 1;
                    value.as_str()
                }
            };
            if !invocation.valued(option, value) {
                return None;
            }
        } else if let Some(cluster) = argument.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            if !cluster.is_ascii() {
                return None;
            }
            for (offset, option) in cluster.char_indices() {
                if FLAGS.contains(option) {
                    invocation.flag(option);
                    continue;
                }
                if !VALUED.contains(option) {
                    return None;
                }
                let rest = &cluster[offset + 1..];
                let value = if rest.is_empty() {
                    let value = arguments.get(index)?;
                    index += 1;
                    value.as_str()
                } else {
                    rest
                };
                if !invocation.valued(option, value) {
                    return None;
                }
                break;
            }
        } else {
            // `psql [DBNAME [USERNAME]]`.
            invocation.positionals += 1;
            if invocation.positionals > 2 || !postgres_name(argument) {
                return None;
            }
        }
    }
    Some(invocation)
}

#[cfg(test)]
mod tests {
    use super::{admitted, startup_files_absent};
    use std::ffi::OsStr;

    fn owned(arguments: &[&str]) -> Vec<String> {
        arguments.iter().map(|value| (*value).to_owned()).collect()
    }

    fn safe(arguments: &[&str]) -> bool {
        admitted(&owned(arguments), |_| true, || true)
    }

    #[test]
    fn a_startup_file_keeps_a_read_without_no_psqlrc_reviewed() {
        let read = ["-h", "localhost", "-c", "select 1"];
        assert!(!admitted(&owned(&read), |_| true, || false));
        let admitted = |arguments: &[&str]| admitted(&owned(arguments), |_| true, || false);
        assert!(admitted(&["-X", "-h", "localhost", "-c", "select 1"]));
        assert!(admitted(&["--no-psqlrc", "-l"]));
        assert!(admitted(&["-tAXc", "select 1"]));
        // `X` inside a value is not the flag.
        assert!(!admitted(&["-c", "select 'X'", "-UX"]));
        assert!(super::psql_reads_startup_files(&owned(&read)));
        assert!(!super::psql_reads_startup_files(&owned(&["-Xl"])));
    }

    #[test]
    fn startup_files_in_either_home_or_the_environment_are_found() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/psqlrc-homes")
            .join(std::process::id().to_string());
        let (home, shell) = (root.join("home"), root.join("shell"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&shell).unwrap();
        let home_text = home.to_str().unwrap();
        let absent = |psqlrc: Option<&str>, shell: Option<&std::path::Path>| {
            startup_files_absent(
                Some(home_text),
                psqlrc.map(OsStr::new),
                shell.map(|shell| shell.as_os_str()),
                None,
            )
        };
        assert!(absent(None, Some(&shell)));
        assert!(absent(Some(""), None));
        assert!(!absent(Some("/tmp/rc"), None));
        assert!(!startup_files_absent(None, None, None, None));
        assert!(!startup_files_absent(Some("relative"), None, None, None));
        for name in [".psqlrc", ".psqlrc-16", ".psqlrc-16.4", ".PSQLRC"] {
            std::fs::write(shell.join(name), "\\! id\n").unwrap();
            assert!(!absent(None, Some(&shell)), "{name}");
            std::fs::remove_file(shell.join(name)).unwrap();
            std::fs::write(home.join(name), "\\! id\n").unwrap();
            assert!(!absent(None, None), "{name}");
            std::fs::remove_file(home.join(name)).unwrap();
        }
        std::fs::write(home.join(".psqlrc.bak"), "").unwrap();
        assert!(absent(None, None));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn only_a_debian_packaged_psql_may_use_the_run_directory() {
        use super::{distribution_client, first_psql, Path};
        assert!(distribution_client(Path::new(
            "/usr/share/postgresql-common/pg_wrapper"
        )));
        assert!(distribution_client(Path::new(
            "/usr/lib/postgresql/16/bin/psql"
        )));
        assert!(!distribution_client(Path::new("/usr/local/bin/psql")));
        assert!(!distribution_client(Path::new(
            "/home/linuxbrew/.linuxbrew/bin/psql"
        )));
        assert!(!distribution_client(Path::new(
            "/usr/lib/postgresql-evil/psql"
        )));
        assert_eq!(first_psql(None), None);
        assert_eq!(
            first_psql(Some(std::ffi::OsStr::new("relative:/usr/bin"))),
            None
        );
        assert_eq!(first_psql(Some(std::ffi::OsStr::new(":/usr/bin"))), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_directory_another_user_can_plant_in_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/psql-socket-dirs")
            .join(std::process::id().to_string());
        let (open, sticky, private) =
            (root.join("open"), root.join("sticky"), root.join("private"));
        for (directory, mode) in [(&open, 0o777), (&sticky, 0o1777), (&private, 0o755)] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::fs::write(private.join(".s.PGSQL.5432"), "").unwrap();
        let list = |directory: &std::path::Path, port: Option<&str>| {
            let mut arguments = vec![
                "-h".to_owned(),
                directory.display().to_string(),
                "-l".to_owned(),
            ];
            if let Some(port) = port {
                arguments.extend(["-p".to_owned(), port.to_owned()]);
            }
            admitted(&arguments, |_| false, || true)
        };
        assert!(!list(&open, None));
        assert!(!list(&open, Some("5432")));
        // A sticky directory needs the socket to exist and belong to the user.
        assert!(!list(&sticky, Some("5432")));
        std::fs::write(sticky.join(".s.PGSQL.5432"), "").unwrap();
        assert!(list(&sticky, Some("5432")));
        assert!(list(&private, None));
        assert!(list(&private, Some("5432")));
        use crate::pretool::safe_scalar::steady_ancestry;
        assert_eq!(list(&private.join("missing"), None), steady_ancestry(&root));
        assert!(!list(&open.join("missing"), None));
        // Without `-h` the default socket check decides.
        assert!(!admitted(&owned(&["-l"]), |_| false, || true));
        assert!(!admitted(
            &owned(&["-l"]),
            |port| port == Some("55434"),
            || true
        ));
        assert!(admitted(
            &owned(&["-l", "-p", "55434"]),
            |port| port == Some("55434"),
            || true
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_lists_and_single_reads_are_admitted() {
        for arguments in [
            &[
                "-h",
                "localhost",
                "-p",
                "55434",
                "-U",
                "hol",
                "-d",
                "hol",
                "-c",
                "select current_user",
            ][..],
            &["-h", "127.0.0.1", "-U", "postgres", "-l"],
            &[
                "-h",
                "localhost",
                "-U",
                "app_user",
                "app_dev",
                "-c",
                "SELECT count(*) FROM items;",
            ],
            &["--host=127.0.0.1", "--port=5432", "--list"],
            &["-tAc", "select version()"],
            &["-XtA", "-d", "app_dev", "--command=show server_version"],
            &[
                "-h",
                "::1",
                "-v",
                "ON_ERROR_STOP=1",
                "-P",
                "pager=off",
                "-c",
                "select 1",
            ],
            &["-At", "-F", ",", "--csv", "-cselect id from items"],
            &["app_dev", "app_user", "-l"],
        ] {
            assert!(safe(arguments), "psql {arguments:?}");
        }
    }

    #[test]
    fn writes_files_remote_hosts_and_sessions_stay_reviewed() {
        assert!(!safe(&[]));
        for arguments in [
            &["-h", "localhost"][..],
            &["-d", "app_dev"],
            &["-c", "drop table x"],
            &["-c", "copy items to program 'id'"],
            &["-c", "select 1; drop table x"],
            &["-c", "\\! id"],
            &["-c", "select 1", "-c", "select 2"],
            &["-h", "db.example.com", "-c", "select 1"],
            &["-h", "/tmp,db.example.com", "-l"],
            &["--host=10.0.0.5", "-l"],
            &["-d", "postgresql://db.example.com/app", "-l"],
            &["-d", "host=db.example.com", "-l"],
            &["postgresql://db.example.com/app", "-l"],
            &["-f", "script.sql"],
            &["-l", "-o", "/tmp/out"],
            &["-l", "-L", "/tmp/log"],
            &["-v", "AUTOCOMMIT=off", "-l"],
            &["--set=PROMPT1=x", "-l"],
            &["-P", "pager=always", "-l"],
            &["-l", "-s"],
            &["-l", "-W"],
            &["-l", "--"],
            &["--list=yes"],
            &["-c"],
            &["-h"],
            &["a", "b", "c", "-l"],
        ] {
            assert!(!safe(arguments), "psql {arguments:?}");
        }
    }
}
