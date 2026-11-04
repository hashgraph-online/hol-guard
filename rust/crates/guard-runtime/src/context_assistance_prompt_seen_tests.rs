use super::*;

fn span(path: &str, start: u64, end: u64) -> Span {
    Span {
        path: path.into(),
        start,
        end,
    }
}

fn session(id: &str) -> Session {
    Session {
        root: PathBuf::from("/seen-tests"),
        app: "codex".into(),
        id: id.into(),
    }
}

#[test]
fn a_span_covers_only_lines_of_the_same_file_it_holds() {
    let shown = span("src/a.py", 10, 40);
    assert!(shown.covers(&span("src/a.py", 10, 40)));
    assert!(shown.covers(&span("src/a.py", 12, 30)));
    assert!(!shown.covers(&span("src/a.py", 5, 30)), "starts earlier");
    assert!(!shown.covers(&span("src/a.py", 30, 50)), "ends later");
    assert!(!shown.covers(&span("src/b.py", 12, 30)), "another file");
}

#[test]
fn each_session_keeps_its_own_spans() {
    let one = session("seen-one");
    let two = session("seen-two");
    remember(&one, &[span("src/a.py", 1, 9)]);
    remember(&one, &[span("src/b.py", 3, 4)]);
    remember(&one, &[]);
    assert_eq!(
        earlier(&one),
        vec![span("src/a.py", 1, 9), span("src/b.py", 3, 4)]
    );
    assert!(earlier(&two).is_empty());
}

#[test]
fn a_session_keeps_only_its_latest_spans() {
    let long = session("seen-long");
    for line in 0..(MAX_SPANS as u64 + 5) {
        remember(&long, &[span("src/a.py", line, line)]);
    }
    let kept = earlier(&long);
    assert_eq!(kept.len(), MAX_SPANS);
    assert_eq!(kept[0], span("src/a.py", 5, 5));
}
