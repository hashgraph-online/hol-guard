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
