//! PostgreSQL server status: `pg_ctl status -D <dir>` and `pg_ctl --version`.
//!
//! `status` reads `postmaster.pid` and `postmaster.opts` in the data
//! directory and checks whether that process is alive. It starts, stops,
//! signals and writes nothing. Every other action (`start`, `stop`,
//! `restart`, `reload`, `promote`, `kill`, `init`, `logrotate`) keeps its
//! review, as do options such as `-o`, `-l`, `-m` and `-w` that only apply to
//! them.
//!
//! Keg-only PostgreSQL installs are not on `PATH`, so agents call `pg_ctl`
//! by its install path. Such a path is accepted only when both the named file
//! and its resolved target are called `pg_ctl` and sit in a trusted location:
//! outside home, the working directory and the temporary directories, with no
//! ancestor another user can write. That is the trust a bare name already
//! gets from `PATH`.

use std::path::Path;

#[path = "psql_reads.rs"]
mod psql_reads;
pub(super) use psql_reads::{psql_reads_startup_files, safe_psql_arguments};

pub(super) fn safe_pg_ctl_arguments(arguments: &[String]) -> bool {
    if arguments
        .iter()
        .any(|argument| argument.contains(['$', '`', '\n', '\r']))
    {
        return false;
    }
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    if matches!(words.as_slice(), ["--version" | "-V"]) {
        return true;
    }
    let mut status = false;
    let mut data_directory = false;
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        match word {
            "status" if !status => status = true,
            "-D" | "--pgdata" if !data_directory => {
                let Some(value) = words.get(index + 1) else {
                    return false;
                };
                if !directory_value(value) {
                    return false;
                }
                data_directory = true;
                index += 1;
            }
            _ => {
                let inline = word
                    .strip_prefix("--pgdata=")
                    .or_else(|| word.strip_prefix("-D"));
                match inline {
                    Some(value) if !data_directory && directory_value(value) => {
                        data_directory = true;
                    }
                    _ => return false,
                }
            }
        }
        index += 1;
    }
    status && data_directory
}

fn directory_value(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('-')
}

/// An install-path `pg_ctl` whose file and resolved target are both trusted.
pub(super) fn trusted_pg_ctl_path(executable: &str, context: super::PathContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let path = Path::new(executable);
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("pg_ctl") {
        return false;
    }
    let (home, cwd) = (Path::new(home), Path::new(cwd));
    let Ok(resolved) = std::fs::canonicalize(path) else {
        return false;
    };
    resolved.is_file()
        && resolved.file_name().and_then(|name| name.to_str()) == Some("pg_ctl")
        && [path, resolved.as_path()].iter().all(|candidate| {
            super::trusted_location::trusted_location(candidate, home, cwd)
                && std::fs::canonicalize(home)
                    .ok()
                    .is_none_or(|home| !candidate.starts_with(home))
                && std::fs::canonicalize(cwd)
                    .ok()
                    .is_none_or(|cwd| !candidate.starts_with(cwd))
        })
}

#[cfg(test)]
mod tests {
    use super::safe_pg_ctl_arguments;
    #[cfg(unix)]
    use super::trusted_pg_ctl_path;
    #[cfg(unix)]
    use crate::pretool::PathContext;

    fn safe(command: &str) -> bool {
        let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        safe_pg_ctl_arguments(&arguments)
    }

    #[test]
    fn status_and_version_are_read_only() {
        for command in [
            "-D /var/lib/acme-pg status",
            "status -D /var/lib/acme-pg",
            "status --pgdata /var/lib/acme-pg",
            "status --pgdata=/var/lib/acme-pg",
            "status -D/var/lib/acme-pg",
            "--version",
            "-V",
        ] {
            assert!(safe(command), "pg_ctl {command}");
        }
    }

    #[test]
    fn server_changes_stay_reviewed() {
        for command in [
            "",
            "status",
            "-D /var/lib/acme-pg",
            "-D /var/lib/acme-pg stop",
            "-D /var/lib/acme-pg start",
            "-D /var/lib/acme-pg restart",
            "-D /var/lib/acme-pg reload",
            "-D /var/lib/acme-pg promote",
            "-D /var/lib/acme-pg kill TERM 1",
            "-D /var/lib/acme-pg init",
            "-D /var/lib/acme-pg logrotate",
            "-D /var/lib/acme-pg status stop",
            "-D /var/lib/acme-pg status -o -k",
            "-D /var/lib/acme-pg -l log status",
            "-D /var/lib/acme-pg -D /srv/other status",
            "-D $PGDATA status",
            "-D status",
            "--version status",
        ] {
            assert!(!safe(command), "pg_ctl {command}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn install_paths_in_writable_trees_are_not_trusted() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("guard-pg-ctl-{}", std::process::id()));
        let home = root.join("home");
        let project = home.join("app-portal");
        let binary = project.join("bin").join("pg_ctl");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "#!/bin/sh\n").unwrap();
        let context = PathContext {
            home_dir: home.to_str(),
            cwd: project.to_str(),
            ..PathContext::default()
        };
        let planted = trusted_pg_ctl_path(binary.to_str().unwrap(), context);
        let missing = trusted_pg_ctl_path("/nonexistent-acme/bin/pg_ctl", context);
        let relative = trusted_pg_ctl_path("bin/pg_ctl", context);
        let renamed = trusted_pg_ctl_path("/bin/sh", context);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!planted);
        assert!(!missing);
        assert!(!relative);
        assert!(!renamed);
    }
}
