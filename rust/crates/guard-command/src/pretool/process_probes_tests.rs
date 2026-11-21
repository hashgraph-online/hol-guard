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
        "-a -p 22899 -d cwd",
        "-a -p 123,456 -d cwd,txt",
        "-ap 123 -dcwd",
        "-a -p 123 -d rtd",
        "-n -a -p 123 -d txt",
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
        "-p 123 -d cwd",
        "-d cwd",
        "-a -d cwd",
        "-a -d rtd,txt",
        "-a -p ^1 -d cwd",
        "-a -i -d cwd",
        "-a -i :3000 -d txt",
        "-a -p 123,^1 -d cwd",
        "-a -p^1 -dtxt",
        "-a -p 123 -d",
        "-a -p 123 -d 1",
        "-a -p 123 -d 0-255",
        "-a -p 123 -d ^cwd",
        "-a -p 123 -d cwd,mem",
        "-a -p 123 -d cwd,",
        "-a -p 123 -d cwd /etc",
        "-a -p 123 -d cwd -F n",
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
