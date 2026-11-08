//! The definitions a commit changed, shown whole as they read now.
use super::super::labels::{render, Since};
use super::super::Hunk;

const STORE: &str = "class Store:
    def get(self):
        return 1

    def put(self, key):
        self.items.append(key)
        return len(self.items) // 2
";

/// A note about the newest commit shows each short definition it changed,
/// whole, as the file reads now, so the agent can edit it without reading it
/// first. A long definition, prose, and a note about a session's own changes
/// get no such code.
#[test]
fn the_newest_commits_short_changed_definitions_are_shown_whole() {
    let hunk = |path: &str, start, body: &str| Hunk {
        path: path.into(),
        start,
        body: body.into(),
    };
    let big = format!("def big():\n{}", "    x = 1\n".repeat(60));
    let changed = vec![
        hunk(
            "src/store.py",
            7,
            "-        return len(self.items)\n+        return len(self.items) // 2\n",
        ),
        hunk("src/store.py", 6, "+        self.items.append(key)\n"),
        hunk("src/big.py", 30, "+    y = 2\n"),
        hunk("README.md", 1, "+# Title\n"),
    ];
    let texts = vec![
        ("README.md".to_owned(), "# Title\n\nbody\n".to_owned()),
        ("src/big.py".to_owned(), big),
        ("src/store.py".to_owned(), STORE.to_owned()),
    ];
    let base = "0123456789abcdef0123456789abcdef01234567";
    let text = render(Since::Newest(base), &changed, &texts, &[], [None; 2], None).unwrap();
    let shown = concat!(
        "\n\nChanged definitions as they read now:\nsrc/store.py:5-7\n```\n",
        "    def put(self, key):\n",
        "        self.items.append(key)\n",
        "        return len(self.items) // 2\n```",
    );
    assert!(text.ends_with(shown), "{text}");
    assert_eq!(text.matches("def put(").count(), 1, "{text}");
    assert!(!text.contains("x = 1") && !text.contains("body"), "{text}");
    let session = render(Since::Start(base), &changed, &texts, &[], [None; 2], None).unwrap();
    assert!(!session.contains("as they read now"), "{session}");
}

/// A change spanning two short functions shows both, and a closing brace
/// after a line quoting one still ends the function shown.
#[test]
fn every_short_definition_a_change_spans_is_shown_to_its_closing_brace() {
    let text = "function f() {\n  return \"}\";\n}\n\nfunction g() {\n  return 2;\n}\n";
    let body: String = text.lines().map(|line| format!("+{line}\n")).collect();
    let changed = vec![Hunk {
        path: "src/f.js".into(),
        start: 1,
        body,
    }];
    let texts = vec![("src/f.js".to_owned(), text.to_owned())];
    let base = "0123456789abcdef0123456789abcdef01234567";
    let note = render(Since::Newest(base), &changed, &texts, &[], [None; 2], None).unwrap();
    let shown = concat!(
        "src/f.js:1-3\n```\nfunction f() {\n  return \"}\";\n}\n```\n",
        "src/f.js:5-7\n```\nfunction g() {\n  return 2;\n}\n```",
    );
    assert!(note.ends_with(shown), "{note}");
}

/// The note about the newest commit `changed` makes, with `path` holding
/// `text`.
fn newest(path: &str, text: &str, changed: &[(usize, &str)]) -> String {
    let changed: Vec<Hunk> = (changed.iter())
        .map(|&(start, body)| Hunk {
            path: path.into(),
            start,
            body: body.into(),
        })
        .collect();
    let texts = vec![(path.to_owned(), text.to_owned())];
    let base = "0123456789abcdef0123456789abcdef01234567";
    render(Since::Newest(base), &changed, &texts, &[], [None; 2], None).unwrap()
}

/// A change to a short class and a method inside it shows the class once,
/// without the method again on its own.
#[test]
fn a_definition_inside_one_shown_is_not_shown_again() {
    let text = "class Box:\n    size = 1\n\n    def grow(self):\n        return 2\n";
    let note = newest(
        "src/box.py",
        text,
        &[(1, " class Box:\n+    size = 1\n \n \n+        return 2\n")],
    );
    assert_eq!(note.matches("def grow(").count(), 1, "{note}");
    assert!(note.contains("src/box.py:1-5\n```\nclass Box:"), "{note}");
}

/// A change after a context line is labelled by the definition it is in,
/// not the one the context line is in.
#[test]
fn a_change_is_labelled_past_the_context_before_it() {
    let text = "def a():\n    return 1\ndef b():\n    return 2\n";
    let note = newest(
        "src/ab.py",
        text,
        &[(2, "     return 1\n-def c():\n+def b():\n")],
    );
    assert!(note.contains("src/ab.py: b 3-4"), "{note}");
    assert!(!note.contains("a 1-2"), "{note}");
}

/// In Rust a lifetime's `'` opens no quote, so a character literal after
/// lifetimes does not hide the brace before it.
#[test]
fn a_rust_function_with_lifetimes_is_shown_to_its_closing_brace() {
    let text = "fn pick<'a>(x: &'a str, y: &'a str) -> char { let c = 'x';\n    c\n}\n";
    let note = newest("src/lib.rs", text, &[(2, "+    c\n")]);
    assert!(note.ends_with("src/lib.rs:1-3\n```\nfn pick<'a>(x: &'a str, y: &'a str) -> char { let c = 'x';\n    c\n}\n```"), "{note}");
}
