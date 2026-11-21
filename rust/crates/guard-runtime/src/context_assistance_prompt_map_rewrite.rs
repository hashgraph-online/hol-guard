//! The one command making a rename the note lists whole: from the project
//! root, a `perl` rewrite of each file holding the old name, then its tests.
use super::super::{Entry, File, Kind};
use std::path::Path;

/// A rename one command makes: every file holding the old name, from a
/// list that is complete, and the test files among them.
#[derive(Clone)]
pub(in super::super) struct Rewrite {
    old: String,
    new: String,
    files: Vec<String>,
    tests: Vec<String>,
}

impl Rewrite {
    /// The rewrite of `old` in `holders`, the files holding it, when it
    /// changes exactly the lines the list names. None when a changelog holds
    /// it, since a released entry keeps the name it shipped with, or when a
    /// line holds it where the list and `perl` read words apart.
    pub(super) fn new(old: &str, new: &str, holders: &[&File]) -> Option<Self> {
        let apart = |file: &&File| {
            file.kind == Kind::Changelog || !(file.lines.iter()).all(|line| alone(line, old))
        };
        if holders.iter().any(apart) {
            return None;
        }
        Some(Self {
            old: old.to_owned(),
            new: new.to_owned(),
            files: holders.iter().map(|file| file.path.to_owned()).collect(),
            tests: (holders.iter())
                .filter(|file| file.kind == Kind::Test && runnable(file.path))
                .map(|file| file.path.to_owned())
                .collect(),
        })
    }

    /// The note's block: a title and the command, which goes to `root`,
    /// writes the new name for each whole-word old one in those files and
    /// then runs their tests, or the tests the map lists when none of them
    /// is a test. None on Windows, where the shell may lack `perl`, or for a
    /// name or path a shell would read as more than itself.
    pub(in super::super) fn block(
        &self,
        listed: &[Entry],
        root: &Path,
    ) -> Option<(String, String)> {
        let root = quoted(root)?;
        if cfg!(windows) || !([&self.old, &self.new].iter()).all(|name| plain_name(name)) {
            return None;
        }
        // The map's test lines start with their file: "tests/test_a.py: 3 related tests".
        let listed = (listed.iter())
            .filter_map(|entry| entry.text.lines().next()?.split_once(": "))
            .map(|(path, _)| path)
            .filter(|path| runnable(path));
        let tests: Vec<&str> = if self.tests.is_empty() {
            listed.collect()
        } else {
            self.tests.iter().map(String::as_str).collect()
        };
        if !(self
            .files
            .iter()
            .map(String::as_str)
            .chain(tests.iter().copied()))
        .all(plain_path)
        {
            return None;
        }
        // A word as the lists read one: `-` and `_` join, so `x-old` is not `old`.
        let (old, new) = (&self.old, &self.new);
        let mut line = format!(
            "cd {root} && perl -pi -e 's/(?<![\\w-]){old}(?![\\w-])/{new}/g' {}",
            self.files.join(" ")
        );
        let run = !tests.is_empty() && tests.iter().all(|path| path.ends_with(".py"));
        if run {
            line.push_str(&format!(" && python -m pytest -q {}", tests.join(" ")));
        }
        let then = if run {
            ", then runs the tests named in it"
        } else {
            ""
        };
        let title = format!(
            "One command makes this whole rename: it writes `{new}` in place of every `{old}` \
written as a whole word, in each file holding it{then}. Run it instead of opening and editing \
each file, then check its output:"
        );
        Some((title, line))
    }
}

/// Whether each `name` in `line` stands alone the same way for the list and
/// for `perl`, which reads a file's bytes: no letter past ASCII touches it,
/// which the list reads as part of a name and `perl` as a break, and no
/// string part before it builds a longer name, as `f"{prefix}_evict"` or
/// `prefix + "_evict"` do.
fn alone(line: &str, name: &str) -> bool {
    let quote = |c: char| matches!(c, '"' | '\'' | '`');
    (line.match_indices(name)).all(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + name.len()..].chars().next();
        let joined = before.is_some_and(quote) && line[..at - 1].trim_end().ends_with('+');
        !([before, after].iter()).any(|c| c.is_some_and(|c| !c.is_ascii()))
            && before != Some('}')
            && !joined
            // `.. _cache algorithm:` is a link label `perl` would rewrite.
            && line[..at].trim() != ".."
    })
}

/// Whether `path` is a file pytest collects tests from, not a helper beside
/// them such as `tests/support.py` or `conftest.py`.
fn runnable(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.strip_suffix(".py").unwrap_or(name);
    stem.starts_with("test_") || stem.ends_with("_test")
}

/// `root` in single quotes, or None when it holds a quote or a control
/// character, which a shell would read as more than the path.
fn quoted(root: &Path) -> Option<String> {
    let root = root.to_str()?;
    let plain = !root.is_empty() && !root.chars().any(|c| c == '\'' || c.is_control());
    plain.then(|| format!("'{root}'"))
}

fn plain_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn plain_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('-')
        && (path.chars()).all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}
