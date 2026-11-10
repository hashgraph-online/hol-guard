//! The lead of a note on the newest commit, for a prompt saying something
//! broke or fails. Shown the commit's diff and the definitions it changed
//! as they read now, an agent still ran the tests first to see the failure
//! and read each file whole before its edit, a request each. The lead says
//! the fix can start from the code shown, and names the one test run that
//! checks it.
use super::code::TITLE;
use super::used::Changed;
use std::path::Path;

/// The most test files the lead's command runs.
const MAX_TESTS: usize = 4;

/// Whether `prompt` says something broke or fails.
pub(super) fn about_failure(prompt: &str) -> bool {
    (prompt.to_lowercase().split(|c: char| !c.is_alphanumeric())).any(|word| {
        ["broke", "broken"].contains(&word)
            || word.starts_with("fail")
            || word.starts_with("regress")
    })
}

/// `changed` with the lead after its first paragraph, when `newest` is set,
/// `prompt` says something broke or fails and the note shows the changed
/// definitions.
pub(super) fn led(mut changed: Changed, newest: bool, prompt: &str, root: &Path) -> Changed {
    let shown = changed.text.contains(&format!("\n\n{TITLE}"));
    if !newest || !shown || !about_failure(prompt) {
        return changed;
    }
    let Some((head, tail)) = changed.text.split_once("\n\n") else {
        return changed;
    };
    let check = command(prompt, root).map_or_else(
        || "then run the tests that use it once to check".to_owned(),
        |command| format!("then run `{command}` once to check"),
    );
    changed.text = format!(
        "{head}\n\nThis note shows the newest change. Where it caused the failure, fix it from \
the code shown here without running the tests first: open just the range you change (a file \
must be read before it is edited), edit it, {check}.\n\n{tail}"
    );
    changed
}

/// The command that runs the test files `prompt` names, as `test_a.py` or
/// `tests/test_a.py::test_one`, from `root`, where each one is. None on
/// Windows, whose shell may not chain commands, when the prompt names no
/// such file, or for a path a shell would read as more than itself.
fn command(prompt: &str, root: &Path) -> Option<String> {
    let root = root.to_str()?;
    if cfg!(windows) || root.is_empty() || root.chars().any(|c| c == '\'' || c.is_control()) {
        return None;
    }
    let mut tests: Vec<&str> = Vec::new();
    let words = prompt.split(|c: char| c.is_whitespace() || matches!(c, '`' | '"' | '\''));
    for word in words {
        let path = word.split("::").next().unwrap_or(word);
        let path = path.trim_end_matches([',', '.', ';', ':', ')']);
        let name = path.rsplit('/').next().unwrap_or(path);
        let Some(stem) = name.strip_suffix(".py") else {
            continue;
        };
        let runnable = stem.starts_with("test_") || stem.ends_with("_test");
        if runnable && plain(path) && !tests.contains(&path) && Path::new(root).join(path).is_file()
        {
            tests.push(path);
        }
    }
    tests.truncate(MAX_TESTS);
    (!tests.is_empty()).then(|| format!("cd '{root}' && python -m pytest -q {}", tests.join(" ")))
}

fn plain(path: &str) -> bool {
    !path.starts_with(['-', '/'])
        && !path.split('/').any(|part| part == "..")
        && (path.chars()).all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}
