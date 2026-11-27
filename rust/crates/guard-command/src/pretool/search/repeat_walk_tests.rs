//! One submission reads a recursive `grep` again for every pass the envelope
//! makes over it: each projection a rewrite reaches, each floor that re-reads
//! a segment. Every one of those readings proves the same tree with the same
//! pattern and globs, so the walks behind the proof must run once per
//! submission. Walked again for each reading, they spent the whole hook
//! decision budget on a loaded host and the command was denied for running
//! out of time.

use super::take_walks;

#[test]
fn a_submission_walks_each_include_tree_once() {
    // A hidden component anywhere in the path fails the read screens, and
    // `tempfile`'s default prefix is `.tmp`, so the fixture names its root.
    let root = tempfile::Builder::new()
        .prefix("guard-repeat-walk")
        .tempdir()
        .expect("temp root");
    let home = std::fs::canonicalize(root.path()).expect("canonical home");
    let worktree = home.join("projects").join("feature");
    for (path, body) in [
        ("src/App.tsx", "export const App = () => null;\n"),
        ("src/index.ts", "import './App';\n"),
        ("web/page.html", "<p>web</p>\n"),
        ("docs/notes.md", "# notes\n"),
        ("node_modules/lib/index.js", "module.exports = {};\n"),
        // A credential file the pattern cannot match: the plain walk refuses
        // the tree, and only the pattern clearance or the include admits it.
        (".env", "API_TOKEN=placeholder\n"),
    ] {
        let file = worktree.join(path);
        std::fs::create_dir_all(file.parent().expect("parent")).expect("directory");
        std::fs::write(file, body).expect("fixture file");
    }
    let command = format!(
        "grep -rln \"web-client by app\" {} --include=\"*.tsx\" --include=\"*.ts\" \
         --include=\"*.js\" --include=\"*.jsx\" --include=\"*.html\" --include=\"*.md\" \
         2>/dev/null | grep -v node_modules | head",
        worktree.display()
    );
    take_walks();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "shell",
            "tool_input": {"command": command},
            "cwd": worktree.to_str().expect("cwd text"),
        }),
        None,
        None,
        home.to_str(),
        worktree.to_str(),
    );
    let walks = take_walks();
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", "native_exact_safe_command"),
        "walks: {walks:?}"
    );
    assert!(!walks.is_empty(), "the proof walked nothing");
    let mut distinct = walks.clone();
    distinct.sort();
    distinct.dedup();
    // Unshared, this submission walked the same tree 108 times.
    assert_eq!(
        walks.len(),
        distinct.len(),
        "{} walks for {} distinct trees: {distinct:?}",
        walks.len(),
        distinct.len()
    );
}

/// `rg -g` proves the tree under its globs for every reading of the
/// submission too. Unshared, a search of a large application tree walked
/// it once per floor and ran past the hook's decision budget.
#[test]
fn a_submission_walks_each_rg_glob_tree_once() {
    let root = tempfile::Builder::new()
        .prefix("guard-repeat-rg-walk")
        .tempdir()
        .expect("temp root");
    let home = std::fs::canonicalize(root.path()).expect("canonical home");
    let worktree = home.join("projects").join("storefront");
    for (path, body) in [
        ("app/items/page.tsx", "export const Page = () => null;\n"),
        (
            "app/items/__tests__/page.test.tsx",
            "test('page', () => {});\n",
        ),
        ("src/lib/consent.ts", "export const showBanner = true;\n"),
        ("src/lib/notes.md", "# notes\n"),
    ] {
        let file = worktree.join(path);
        std::fs::create_dir_all(file.parent().expect("parent")).expect("directory");
        std::fs::write(file, body).expect("fixture file");
    }
    let command = format!(
        "cd {} && rg -n \"showBanner|hideBanner\" -g '*.ts*' -g '!__tests__/**' app src | head -30",
        worktree.display()
    );
    take_walks();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": worktree.to_str().expect("cwd text"),
        }),
        None,
        None,
        home.to_str(),
        worktree.to_str(),
    );
    let walks = take_walks();
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", "native_exact_safe_command"),
        "walks: {walks:?}"
    );
    let glob_walks: Vec<_> = walks
        .iter()
        .filter(|walk| walk.starts_with("rg-glob-walk "))
        .cloned()
        .collect();
    let mut distinct = glob_walks.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 2, "one walk per root: {glob_walks:?}");
    assert_eq!(
        glob_walks.len(),
        distinct.len(),
        "{} walks for {} distinct trees: {distinct:?}",
        glob_walks.len(),
        distinct.len()
    );
}

/// `rg -g` is proven by two walks of the same tree: the content walk under
/// its globs and the walk for ignore rules that re-include hidden entries.
/// Each listed every directory, so a large application tree was read twice
/// over and the decision ran close to the hook's deadline. The walks share
/// one listing of each directory.
#[test]
fn a_submission_lists_each_rg_directory_once() {
    let root = tempfile::Builder::new()
        .prefix("guard-repeat-rg-listing")
        .tempdir()
        .expect("temp root");
    let home = std::fs::canonicalize(root.path()).expect("canonical home");
    let worktree = home.join("projects").join("storefront");
    for (path, body) in [
        ("app/items/page.tsx", "export const Page = () => null;\n"),
        ("app/items/view.tsx", "export const View = () => null;\n"),
        ("src/lib/consent.ts", "export const showBanner = true;\n"),
        ("src/lib/format/date.ts", "export const day = 1;\n"),
    ] {
        let file = worktree.join(path);
        std::fs::create_dir_all(file.parent().expect("parent")).expect("directory");
        std::fs::write(file, body).expect("fixture file");
    }
    let command = format!(
        "cd {} && rg -n \"showBanner\" app src -g '*.ts*' | head",
        worktree.display()
    );
    take_walks();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": worktree.to_str().expect("cwd text"),
        }),
        None,
        None,
        home.to_str(),
        worktree.to_str(),
    );
    let walks = take_walks();
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", "native_exact_safe_command"),
        "walks: {walks:?}"
    );
    let listings: Vec<_> = walks
        .iter()
        .filter(|walk| walk.starts_with("dir-listing "))
        .cloned()
        .collect();
    let mut distinct = listings.clone();
    distinct.sort();
    distinct.dedup();
    // Both roots and every directory below them: app, app/items, src,
    // src/lib and src/lib/format.
    assert!(distinct.len() >= 5, "listed: {distinct:?}");
    assert_eq!(
        listings.len(),
        distinct.len(),
        "{} listings of {} directories: {listings:?}",
        listings.len(),
        distinct.len()
    );
}

/// A content search over shell globs expands and screens each glob once per
/// submission. Expanded again for every reading, `grep -rn` over a test
/// tree's `*.py` globs ran past the hook's decision budget.
#[test]
fn a_submission_expands_each_search_glob_once() {
    let root = tempfile::Builder::new()
        .prefix("guard-repeat-glob")
        .tempdir()
        .expect("temp root");
    let home = std::fs::canonicalize(root.path()).expect("canonical home");
    let worktree = home.join("projects").join("storefront");
    for (path, body) in [
        ("tests/test_items.py", "def test_items():\n    pass\n"),
        ("tests/unit/test_cart.py", "def test_cart():\n    pass\n"),
        ("tests/unit/test_notes.py", "def test_notes():\n    pass\n"),
    ] {
        let file = worktree.join(path);
        std::fs::create_dir_all(file.parent().expect("parent")).expect("directory");
        std::fs::write(file, body).expect("fixture file");
    }
    let command = format!(
        "cd {} && grep -rn \"test_cart\\|test_notes\" tests/*.py tests/**/*.py 2>/dev/null | head -20",
        worktree.display()
    );
    take_walks();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": worktree.to_str().expect("cwd text"),
        }),
        None,
        None,
        home.to_str(),
        worktree.to_str(),
    );
    let expansions: Vec<_> = take_walks()
        .into_iter()
        .filter(|walk| walk.starts_with("glob-search-operand "))
        .collect();
    let mut distinct = expansions.clone();
    distinct.sort();
    distinct.dedup();
    assert!(
        !distinct.is_empty(),
        "no glob was expanded: {}",
        result.reason_code
    );
    assert_eq!(
        expansions.len(),
        distinct.len(),
        "{} expansions for {} distinct globs: {distinct:?}",
        expansions.len(),
        distinct.len()
    );
}
