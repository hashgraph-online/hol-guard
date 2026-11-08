use super::*;

fn span(path: &str, start: u64, end: u64) -> Span {
    Span::new(path, start, end, "text")
}

fn session(id: &str) -> Session {
    Session {
        root: PathBuf::from("/seen-tests"),
        app: "codex".into(),
        id: id.into(),
    }
}

#[test]
fn a_span_matches_only_the_same_lines_holding_the_same_text() {
    let shown = Span::new("src/a.py", 10, 40, "def run(): pass");
    assert_eq!(shown, Span::new("src/a.py", 10, 40, "def run(): pass"));
    assert_ne!(
        shown,
        Span::new("src/a.py", 10, 40, "def run(): return 1"),
        "edited since"
    );
    assert_ne!(
        shown,
        Span::new("src/a.py", 12, 30, "def run(): pass"),
        "other lines"
    );
    assert_ne!(
        shown,
        Span::new("src/b.py", 10, 40, "def run(): pass"),
        "another file"
    );
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

/// Pi and Oh My Pi may drop the context, so what it held is sent again.
#[test]
fn pi_sessions_record_nothing() {
    for app in ["pi", "omp"] {
        let pi = Session {
            app: app.into(),
            ..session("seen-pi")
        };
        remember(&pi, &[span("src/a.py", 1, 9)]);
        assert!(earlier(&pi).is_empty(), "{app}");
    }
}
