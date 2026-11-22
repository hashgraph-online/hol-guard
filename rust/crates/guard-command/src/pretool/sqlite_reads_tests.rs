use super::{admitted, read_only_statement, startup_file_absent};
use crate::pretool::PathContext;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/sqlite-reads")
        .join(format!("{}-{name}", std::process::id()));
    std::fs::create_dir_all(root.join("home/site")).unwrap();
    std::fs::write(root.join("home/site/inventory.db"), b"SQLite format 3\0").unwrap();
    root
}

fn safe(root: &Path, arguments: &[&str]) -> bool {
    let home = root.join("home");
    let cwd = home.join("site");
    let owned: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    admitted(
        &owned,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        || true,
    )
}

#[test]
fn a_single_select_against_a_local_database_is_read_only() {
    let root = fixture("reads");
    let results: Vec<bool> = [
        &["inventory.db", "select count(*) from items"][..],
        &["-json", "inventory.db", "select id from items limit 5"],
        &["-line", "-header", "inventory.db", "SELECT * FROM items;"],
        &[
            "-separator",
            "|",
            "inventory.db",
            "with recent as (select id from items) select count(*) from recent",
        ],
        &[
            "inventory.db",
            "select replace(name, 'a', 'b') from items where name is not null",
        ],
        &[
            "inventory.db",
            "select case when size > 1 then 'big' else 'small' end from items",
        ],
        &[
            "-readonly",
            "inventory.db",
            "select name from sqlite_master",
        ],
        // An absent database is created empty, which `touch` already proves.
        &["catalog.db", "select 1"],
    ]
    .iter()
    .map(|arguments| safe(&root, arguments))
    .collect();
    let _ = std::fs::remove_dir_all(&root);
    for (index, result) in results.iter().enumerate() {
        assert!(result, "case {index}");
    }
}

#[test]
fn writes_dot_commands_and_second_statements_stay_reviewed() {
    let root = fixture("writes");
    let results: Vec<bool> = [
        &["inventory.db"][..],
        &["inventory.db", "select 1", "select 2"],
        &["inventory.db", "delete from items"],
        &["inventory.db", "select 1; drop table items"],
        &["inventory.db", ".dump"],
        &["inventory.db", ".tables"],
        &["inventory.db", "pragma journal_mode=wal"],
        &[
            "inventory.db",
            "with x as (select 1) insert into items select * from x",
        ],
        &["inventory.db", "attach database '/etc/passwd' as other"],
        &["inventory.db", "select load_extension('/tmp/evil.so')"],
        &["inventory.db", "select writefile('/tmp/out', 'x')"],
        &["inventory.db", "select readfile('/etc/passwd')"],
        &["-init", "setup.sql", "inventory.db", "select 1"],
        &["-cmd", ".shell id", "inventory.db", "select 1"],
        &["-A", "inventory.db", "select 1"],
        &["file:inventory.db?mode=rwc", "select 1"],
        &[":memory:", "select 1"],
        &["inventory.db?mode=rwc", "select 1"],
        &["../../.ssh/id_rsa", "select 1"],
        &["/etc/newplace.db", "select 1"],
    ]
    .iter()
    .map(|arguments| safe(&root, arguments))
    .collect();
    let _ = std::fs::remove_dir_all(&root);
    for (index, result) in results.iter().enumerate() {
        assert!(!result, "case {index}");
    }
}

#[test]
fn a_startup_file_in_either_home_keeps_the_read_reviewed() {
    let root = fixture("startup");
    let (home, shell) = (root.join("home"), root.join("shell"));
    std::fs::create_dir_all(&shell).unwrap();
    let home_text = home.to_str().unwrap();
    let absent = |shell: Option<&Path>| {
        startup_file_absent(Some(home_text), shell.map(|shell| shell.as_os_str()))
    };
    let mut results = vec![
        absent(None),
        absent(Some(&shell)),
        absent(Some(Path::new(""))),
        !absent(Some(Path::new("relative"))),
        !startup_file_absent(None, None),
        !startup_file_absent(Some("relative"), None),
    ];
    for directory in [&shell, &home] {
        std::fs::write(directory.join(".sqliterc"), ".shell id\n").unwrap();
        results.push(!absent(Some(&shell)));
        std::fs::remove_file(directory.join(".sqliterc")).unwrap();
    }
    // The real entry point reads the shell's own `HOME`.
    let arguments = ["inventory.db".to_owned(), "select 1".to_owned()];
    results.push(
        super::safe_sqlite3_arguments(
            &arguments,
            PathContext {
                home_dir: Some(home_text),
                cwd: home.join("site").to_str(),
                ..PathContext::default()
            },
        ) == startup_file_absent(
            Some(home_text),
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(OsStr::new),
        ),
    );
    let _ = std::fs::remove_dir_all(&root);
    for (index, result) in results.iter().enumerate() {
        assert!(result, "case {index}");
    }
}

#[test]
fn only_a_leading_select_reads() {
    for statement in [
        "select 1",
        "SELECT id, replace(name, 'a', 'b') FROM items",
        "with x as (select 1 as n) select n from x",
        "select case when n then 1 else 2 end from t",
        "select edit from notes",
    ] {
        assert!(read_only_statement(statement), "{statement}");
    }
    for statement in [
        "",
        "   ",
        ";",
        ".schema",
        "vacuum",
        "select 1; select 2",
        "update items set name = 'x'",
        "with x as (select 1) delete from items",
        "select edit(body) from notes",
        "select sqlite_dbpage(1)",
        "select replace into items values (1)",
    ] {
        assert!(!read_only_statement(statement), "{statement}");
    }
}
