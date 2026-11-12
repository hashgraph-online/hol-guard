use super::*;

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn programs(names: &[&str]) -> Shebang {
    Shebang::Runs(names.iter().map(|name| (*name).to_owned()).collect())
}

/// Read a script holding exactly `body`.
fn read(body: &[u8]) -> Shebang {
    let path = std::env::temp_dir().join(format!(
        "guard-shebang-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    fs::write(&path, body).unwrap();
    let parsed = shebang(&path);
    let _ = fs::remove_file(path);
    parsed
}

#[test]
fn an_interpreter_is_the_first_word_of_the_line() {
    assert_eq!(runs("/bin/sh"), programs(&["/bin/sh"]));
    assert_eq!(
        runs(" /usr/bin/python3 -I"),
        programs(&["/usr/bin/python3"])
    );
    assert_eq!(runs(""), Shebang::Absent);
}

#[test]
fn env_runs_the_first_operand_that_is_not_an_option_or_an_assignment() {
    let env = "/usr/bin/env";
    for (line, program) in [
        ("/usr/bin/env sh", "sh"),
        ("/usr/bin/env FOO=1 -i node --flag", "node"),
        ("/usr/bin/env -i -- FOO=1 sh", "sh"),
        ("/usr/bin/env -u FOO sh", "sh"),
        ("/usr/bin/env -uFOO sh", "sh"),
        ("/usr/bin/env --unset FOO sh", "sh"),
        ("/usr/bin/env --unset=FOO sh", "sh"),
        ("/usr/bin/env -iu FOO sh", "sh"),
        ("/usr/bin/env -S -u FOO sh", "sh"),
        ("/usr/bin/env -S sh -e", "sh"),
        ("/usr/bin/env -Ssh -e", "sh"),
        ("/usr/bin/env --split-string=sh -e", "sh"),
        ("/usr/bin/env -S \"sh\" -e", "sh"),
        ("/usr/bin/env -S 'lane sh' -e", "lane sh"),
        ("/usr/bin/env -S FOO=\"a b\" sh", "sh"),
        ("/usr/bin/env -S sh # comment", "sh"),
    ] {
        assert_eq!(runs(line), programs(&[env, program]), "{line}");
    }
}

#[test]
fn the_env_the_line_names_is_launched_too() {
    assert_eq!(runs("/opt/env sh"), programs(&["/opt/env", "sh"]));
    assert_eq!(runs("/usr/bin/env"), programs(&["/usr/bin/env"]));
    assert_eq!(runs("/usr/bin/env -i FOO=1"), programs(&["/usr/bin/env"]));
}

#[test]
fn a_line_that_could_move_the_lookup_or_does_not_parse_is_unclear() {
    for line in [
        "/usr/bin/env -P /opt/bin sh",
        "/usr/bin/env -C /opt sh",
        "/usr/bin/env --chdir=/opt sh",
        "/usr/bin/env -S \"sh -e",
        "/usr/bin/env -S 'sh -e",
        "/usr/bin/env -S $SHELL",
        "/usr/bin/env -S \"$SHELL\" -e",
        "/usr/bin/env -S sh\\ x",
        "/usr/bin/env -S",
    ] {
        assert_eq!(runs(line), Shebang::Unclear, "{line}");
    }
}

#[test]
fn only_a_whole_readable_first_line_is_read() {
    assert_eq!(read(b"echo no shebang\n"), Shebang::Absent);
    assert_eq!(read(b"#!/bin/sh\necho ok\n"), programs(&["/bin/sh"]));
    assert_eq!(read(b"#!/bin/sh"), programs(&["/bin/sh"]));
    assert_eq!(read(b"#!/bin/\xff\xfe\n"), Shebang::Unclear);
    let mut long = b"#!/".to_vec();
    long.extend(vec![b'a'; SHEBANG_BYTES]);
    assert_eq!(read(&long), Shebang::Unclear);
}

/// The sole interpreter a script holding exactly `body` names.
fn sole(body: &[u8]) -> Option<String> {
    let path = std::env::temp_dir().join(format!(
        "guard-shebang-sole-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    fs::write(&path, body).unwrap();
    let named = sole_interpreter(&path);
    let _ = fs::remove_file(path);
    named
}

#[test]
fn only_a_space_or_a_tab_ends_the_interpreter_the_kernel_starts() {
    // A script written with CRLF endings names an interpreter whose last byte
    // is the carriage return, because the kernel ends the name at a space or
    // a tab and nowhere else. Reading the name without that byte would admit
    // the file beside it while the kernel starts one a sibling can plant.
    assert_eq!(
        read(b"#!/opt/lane/bin/python3\r\nprint()\n"),
        programs(&["/opt/lane/bin/python3\r"])
    );
    assert_eq!(
        sole(b"#!/opt/lane/bin/python3\r\nprint()\n").as_deref(),
        Some("/opt/lane/bin/python3\r")
    );
    assert_eq!(
        read(b"#!/usr/bin/env\x0bsh\n"),
        programs(&["/usr/bin/env\x0bsh"])
    );
    // What the kernel does separate still separates.
    assert_eq!(
        sole(b"#!/opt/lane/bin/python3\nprint()\n").as_deref(),
        Some("/opt/lane/bin/python3")
    );
    assert_eq!(sole(b"#!/opt/lane/bin/python3 -I\n"), None);
    assert_eq!(read(b"#!\t/bin/sh\t-e\n"), programs(&["/bin/sh"]));
}
