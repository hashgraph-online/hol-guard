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
