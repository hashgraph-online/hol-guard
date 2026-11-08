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
