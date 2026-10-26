use super::PatternClearance;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pattern-clearance")
        .join(format!("{}-{name}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn only_plain_patterns_are_cleared() {
    for plain in [
        "handler",
        "some_cookie_name",
        "COOKIE_NAME",
        "a.b",
        "foo|bar",
        "x = 1",
    ] {
        assert!(PatternClearance::new(plain).is_some(), "{plain}");
    }
    for unsafe_pattern in [
        "",
        "|",
        "a||b",
        "a|",
        "^KEY",
        "KEY$",
        "KEY.*",
        "a+",
        "a?",
        "[a-z]",
        "(a)",
        "a{2}",
        r"\w",
        r"a\|b",
        "caf\u{e9}",
        "a\nb",
    ] {
        assert!(
            PatternClearance::new(unsafe_pattern).is_none(),
            "{unsafe_pattern:?}"
        );
    }
    assert!(PatternClearance::new(&"a".repeat(513)).is_none());
}

#[test]
fn a_file_clears_only_when_the_pattern_cannot_match_it() {
    let root = scratch("match");
    let env = root.join(".env.bak");
    std::fs::write(&env, "SESSION_SECRET=placeholder\nCOOKIE_NAME=synthetic\n").unwrap();
    for (pattern, cleared) in [
        ("handler", true),
        ("some_cookie_name", true),
        ("COOKIE_NAME", false),
        ("cookie_name", false),
        ("cookie.name", false),
        ("handler|session_secret", false),
        ("session", false),
        ("a.b", true),
        ("SECRET=.l", false),
    ] {
        assert_eq!(
            PatternClearance::new(pattern).unwrap().clears(&env),
            cleared,
            "{pattern}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_dot_cannot_hide_a_match_in_a_file_with_bytes_past_ascii() {
    let root = scratch("dot-bytes");
    let latin = root.join(".env.latin1");
    std::fs::write(&latin, b"PASS=caf\xE9x\n").unwrap();
    let utf8 = root.join(".env.utf8");
    std::fs::write(&utf8, "PASS=caf\u{e9}x\n".as_bytes()).unwrap();
    for pattern in ["caf.x", "caf..x", "PASS=caf.x"] {
        let clearance = PatternClearance::new(pattern).unwrap();
        assert!(!clearance.clears(&latin), "{pattern}");
        assert!(!clearance.clears(&utf8), "{pattern}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_dot_crosses_a_line_break_so_a_split_match_is_not_cleared() {
    let root = scratch("dot");
    let env = root.join(".env");
    std::fs::write(&env, "AB\nCD\n").unwrap();
    assert!(!PatternClearance::new("b.c").unwrap().clears(&env));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn files_the_check_cannot_read_as_plain_text_are_not_cleared() {
    let root = scratch("unreadable");
    let clearance = PatternClearance::new("handler").unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    assert!(clearance.clears(&write(".env.a", b"X=1\n")));
    assert!(!clearance.clears(&write(".env.nul", b"X=1\0\n")));
    assert!(!clearance.clears(&write(".env.utf16le", b"\xFF\xFEX\x00=\x001\x00")));
    assert!(!clearance.clears(&write(".env.utf16be", b"\xFE\xFF\x00X")));
    // Any byte past ASCII is read differently by a C locale, a UTF-8 locale
    // and a Latin-1 one, so `.` could cover a different span than this check's.
    assert!(!clearance.clears(&write(".env.latin1", b"PASS=caf\xE9x\n")));
    assert!(!clearance.clears(&write(".env.utf8", "PASS=caf\u{e9}x\n".as_bytes())));
    assert!(!clearance.clears(&write(".env.bom", b"\xEF\xBB\xBFX=1\n")));
    assert!(!clearance.clears(&write(".env.big", &vec![b'x'; 300 * 1024])));
    assert!(!clearance.clears(&root.join(".env.missing")));
    assert!(!clearance.clears(&root));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn key_material_and_credential_stores_are_never_read() {
    let root = scratch("keys");
    let clearance = PatternClearance::new("handler").unwrap();
    for relative in [
        "server.key",
        "cert.pem",
        "bundle.p12",
        "id_rsa_private_key",
        ".git-credentials",
        ".netrc",
        ".ssh/config",
        ".aws/credentials",
        ".git/config",
        "credentials.json",
        "secrets/db.json",
        "password.txt",
    ] {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "X=1\n").unwrap();
        assert!(!clearance.clears(&path), "{relative}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_link_is_never_followed() {
    let root = scratch("link");
    std::fs::write(root.join("real.txt"), "X=1\n").unwrap();
    std::os::unix::fs::symlink(root.join("real.txt"), root.join(".env.link")).unwrap();
    assert!(!PatternClearance::new("handler")
        .unwrap()
        .clears(&root.join(".env.link")));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_read_budget_runs_out() {
    let root = scratch("budget");
    let clearance = PatternClearance::new("handler").unwrap();
    let mut cleared = 0;
    for index in 0..80 {
        let path = root.join(format!(".env.{index}"));
        std::fs::write(&path, "X=1\n").unwrap();
        cleared += usize::from(clearance.clears(&path));
    }
    assert_eq!(cleared, 64);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_a_plain_directory_may_be_descended() {
    let root = scratch("descend");
    let clearance = PatternClearance::new("handler").unwrap();
    std::fs::create_dir_all(root.join(".cache")).unwrap();
    std::fs::create_dir_all(root.join(".ssh")).unwrap();
    std::fs::create_dir_all(root.join(".env")).unwrap();
    assert!(clearance.may_descend(&root.join(".cache")));
    assert!(!clearance.may_descend(&root.join(".ssh")));
    assert!(!clearance.may_descend(&root.join(".env")));
    assert!(!clearance.may_descend(&root.join(".missing")));
    std::fs::remove_dir_all(root).unwrap();
}
