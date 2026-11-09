//! How much of the diff a changes note shows: the lines around each change
//! when they fit, and only the files Guard's read accepted.
use super::*;

/// A commit that also deletes a file shows only the other files' diff: the
/// deleted file was never read, so the screen never saw what it held.
#[test]
fn a_commit_deleting_an_unread_file_shows_only_the_read_files() {
    let repo = Repo::new();
    repo.write("private/notes.txt", "meeting notes\nnot for the agent\n");
    repo.commit("add notes");
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    repo.write(
        "src/core.py",
        &CORE.replace("return value", "return value.strip()"),
    );
    repo.git(&["rm", "-q", "private/notes.txt"]);
    repo.commit("strip values");
    let text = repo.changes(Some(&base)).unwrap();
    assert!(text.contains("src/core.py: convert 4-5"), "{text}");
    let command = format!("git diff -U3 {} -- src/core.py", &base[..7]);
    let rest = format!("`git diff {}` also shows 1 other changed file", &base[..7]);
    assert!(
        text.contains(&format!("has what `{command}` prints now; {rest})"))
            && text.contains("strip values")
            && text.contains("\n+    return value.strip()\n"),
        "{text}"
    );
    assert!(
        !text.contains("not for the agent") && !text.contains("notes"),
        "{text}"
    );
}

/// A changed file Guard's read refused leaves the diff of the others in the
/// note, with the refused file named, so the agent runs the diff of that file
/// alone rather than the whole diff again.
#[test]
fn a_refused_file_leaves_the_others_diff_shown() {
    let repo = Repo::new();
    repo.write("src/urls.py", "def parse(url):\n    return url\n");
    repo.commit("add urls");
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    repo.write(
        "src/core.py",
        &CORE.replace("return value", "return value.strip()"),
    );
    repo.write("src/urls.py", "def parse(url):\n    return url.lower()\n");
    let screen = |paths: &[String]| -> Vec<(String, String)> {
        (paths.iter())
            .filter(|path| path.as_str() != "src/urls.py")
            .map(|path| {
                let text = fs::read_to_string(repo.path().join(path)).unwrap();
                (path.clone(), text)
            })
            .collect()
    };
    let text = changes(&repo.found(), Since::Start(&base), false, later(), screen).unwrap();
    let short = &base[..7];
    assert!(
        text.contains(&format!(
            "(the end of this note has what `git diff -U3 {short} -- src/core.py` prints now; \
`git diff {short} -- src/urls.py` shows the rest)"
        )) && text.contains("\n+    return value.strip()\n"),
        "{text}"
    );
    assert!(!text.contains("url.lower()"), "{text}");
    // Every changed file refused leaves no diff to show.
    let none = |_: &[String]| -> Vec<(String, String)> { Vec::new() };
    assert_eq!(
        changes(&repo.found(), Since::Start(&base), false, later(), none),
        None
    );
}

/// A diff small enough is shown with git's usual three lines around each
/// change, the lines an agent reviewing it runs `git diff -U3` again for; one
/// too big that way is shown with one line around each change.
#[test]
fn a_diff_is_shown_with_the_lines_around_its_changes_when_they_fit() {
    let repo = Repo::new();
    let lines = |changed: bool| -> String {
        (0..300)
            .map(|at| {
                let text = if changed && at % 10 == 9 {
                    "changed"
                } else {
                    "value"
                };
                format!("item_{at:03} = '{text} text'\n")
            })
            .collect()
    };
    repo.write("src/items.py", &lines(false));
    repo.commit("add items");
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let short = &base[..7];
    repo.write(
        "src/core.py",
        &CORE.replace("return value", "return value.strip()"),
    );
    let text = repo.changes(Some(&base)).unwrap();
    assert!(
        text.contains(&format!("`git diff -U3 {short}` prints:\n```diff\n"))
            && text.contains("\n \n \n def convert(value):\n-    return value\n"),
        "{text}"
    );
    repo.write("src/items.py", &lines(true));
    let text = repo.changes(Some(&base)).unwrap();
    assert!(
        text.contains(&format!("`git diff -U1 {short}` prints:\n```diff\n"))
            && text.matches("\n+item_").count() == 30
            && !text.contains("\n \n \n def convert(value):\n"),
        "{text}"
    );
}
