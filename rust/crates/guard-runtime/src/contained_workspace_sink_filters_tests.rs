use super::*;

fn stage(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn head_and_tail_keep_at_most_what_there_is() {
    let items = [1, 2, 3];
    assert_eq!(keep(&items, "head", 2), &[1, 2]);
    assert_eq!(keep(&items, "tail", 2), &[2, 3]);
    assert_eq!(keep(&items, "head", 3), &[1, 2, 3]);
    assert_eq!(keep(&items, "tail", 9), &[1, 2, 3]);
    assert!(keep(&items, "head", 0).is_empty());
    assert!(keep(&items, "tail", 0).is_empty());
    assert!(keep::<u8>(&[], "tail", 4).is_empty());
}

#[test]
fn lines_break_where_python_splitlines_does() {
    let text = b"a\r\nb\rc\xc2\x85d\xe2\x80\xa8e\x0bf\x1cg\nh";
    assert_eq!(
        lines(text),
        [
            &b"a\r\n"[..],
            b"b\r",
            b"c\xc2\x85",
            b"d\xe2\x80\xa8",
            b"e\x0b",
            b"f\x1c",
            b"g\n",
            b"h",
        ]
    );
    // Bytes that decode to nothing keep their place in the line they sit in.
    assert_eq!(
        lines(b"\xff\xc2\n\xe2\x80x"),
        [&b"\xff\xc2\n"[..], b"\xe2\x80x"]
    );
    assert!(lines(b"").is_empty());
    assert_eq!(lines(b"\n\n"), [&b"\n"[..], b"\n"]);
}

#[test]
fn a_chain_cuts_lines_and_bytes_in_turn() {
    let text = b"one\ntwo\nthr\xc3\xa9e\n";
    let (kept, diagnostics, status) = apply(text, &[stage(&["tail", "2"])]).unwrap();
    assert_eq!(kept, b"two\nthr\xc3\xa9e\n");
    assert!(diagnostics.is_empty());
    assert_eq!(status, 0);
    // A byte cut may split a character; the bytes go on as they are.
    let (kept, _, _) = apply(text, &[stage(&["tail", "2"]), stage(&["head", "-c", "7"])]).unwrap();
    assert_eq!(kept, b"two\nthr");
    let (kept, _, _) = apply(text, &[stage(&["head", "-c", "12"])]).unwrap();
    assert_eq!(kept, b"one\ntwo\nthr\xc3");
    let (kept, _, _) = apply(text, &[stage(&["tail", "-c", "0"])]).unwrap();
    assert!(kept.is_empty());
    let (kept, _, _) = apply(text, &[stage(&["head", "0"])]).unwrap();
    assert!(kept.is_empty());
}

#[test]
fn a_stage_the_chain_does_not_name_is_refused() {
    for refused in [
        stage(&["sort"]),
        stage(&["head"]),
        stage(&["head", "-n", "3"]),
        stage(&["tail", "x"]),
        Vec::new(),
    ] {
        assert!(apply(b"a\n", &[refused.clone()]).is_err(), "{refused:?}");
    }
}

#[test]
fn a_matcher_reads_the_captured_text() {
    if trusted_grep().is_none() {
        return;
    }
    let (kept, diagnostics, status) = apply(
        b"passed\nfailed\npassed\n",
        &[stage(&["grep", "-c", "passed"])],
    )
    .unwrap();
    assert_eq!(
        (kept.as_slice(), diagnostics.is_empty(), status),
        (&b"2\n"[..], true, 0)
    );
    let (kept, _, status) = apply(b"a\n", &[stage(&["fgrep", "b"])]).unwrap();
    assert_eq!((kept.as_slice(), status), (&b""[..], 1));
    let (kept, _, status) =
        apply(b"ab\n", &[stage(&["egrep", "a|z"]), stage(&["tail", "1"])]).unwrap();
    assert_eq!((kept.as_slice(), status), (&b"ab\n"[..], 0));
}

#[test]
fn a_missing_ripgrep_exits_as_a_missing_program() {
    if trusted_ripgrep().is_some() {
        return;
    }
    let (kept, diagnostics, status) = apply(b"a\n", &[stage(&["rg", "a"])]).unwrap();
    assert!(kept.is_empty());
    assert_eq!(diagnostics, b"hol-guard: rg: not found\n");
    assert_eq!(status, 127);
}

#[test]
fn a_ripgrep_others_could_rewrite_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().expect("tempdir");
    let planted = directory.path().join("rg");
    std::fs::write(&planted, "#!/bin/sh\n").expect("plant");
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o777)).expect("chmod");
    assert_eq!(trusted_ripgrep_in(&[directory.path()]), None);
}

#[test]
fn a_ripgrep_that_cannot_run_leaves_the_search_to_the_next_directory() {
    use std::os::unix::fs::PermissionsExt;
    let first = tempfile::tempdir().expect("tempdir");
    std::fs::write(first.path().join("rg"), "not the install\n").expect("plant");
    let second = tempfile::tempdir().expect("tempdir");
    let installed = second.path().join("rg");
    std::fs::write(&installed, "#!/bin/sh\ncat\n").expect("install");
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(
        trusted_ripgrep_in(&[first.path(), second.path()]),
        Some(std::fs::canonicalize(&installed).expect("canonical"))
    );
}

#[test]
fn a_grep_root_does_not_own_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    if getuid().is_root() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let planted = directory.path().join("grep");
    std::fs::write(&planted, "#!/bin/sh\n").expect("plant");
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let missing = directory.path().join("missing");
    assert_eq!(
        trusted_grep_in(&[planted.as_path(), missing.as_path()]),
        None
    );
}
