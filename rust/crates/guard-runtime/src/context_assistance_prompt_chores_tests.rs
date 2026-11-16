use super::*;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

/// A flit project like the ones agents failed to build: the version in the
/// package's `__init__.py`, a reStructuredText changelog, a CI workflow.
fn flit_project() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let files = [
        (
            "pyproject.toml",
            "[project]\nname = \"clicky\"\ndynamic = [\"version\"]\ndependencies = [\"colorama\"]\n\n\
[project.optional-dependencies]\ndocs = [\"sphinx\"]\n\n\
[build-system]\nrequires = [\"flit_core<4\"]\nbuild-backend = \"flit_core.buildapi\"\n\n\
[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n",
        ),
        ("src/clicky/__init__.py", "\"\"\"Clicky.\"\"\"\n__version__ = \"1.2.3\"\n"),
        (
            "CHANGES.rst",
            ".. currentmodule:: clicky\n\nVersion 1.2.3\n-------------\n\nReleased 2026-01-02\n",
        ),
        (".github/workflows/publish.yaml", "on: push\n"),
        ("Makefile", "VERSION := 1\n.PHONY: test\ntest:\n\tpytest\ndist: test\n\tflit build\n"),
    ];
    for (path, text) in files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    (dir, root)
}

fn note_for(root: &Path, prompt: &str) -> Option<String> {
    asks(prompt).and_then(|asks| note(root, &asks))
}

#[test]
fn a_wheel_build_gets_a_build_command_that_works_offline() {
    let (_dir, root) = flit_project();
    let note = note_for(&root, "build the wheel and check it installs").unwrap();
    assert!(note.contains("backend `flit_core.buildapi`"), "{note}");
    assert!(note.contains("`python -m pip wheel --no-build-isolation --no-deps -w dist .`"));
    assert!(note.contains("`python -m flit_core.wheel`"), "{note}");
    assert!(
        note.contains("Make targets (Makefile): test, dist"),
        "{note}"
    );
    assert!(!note.contains("VERSION"), "{note}");
}

#[test]
fn a_release_gets_the_version_changelog_and_workflows() {
    let (_dir, root) = flit_project();
    let prompt = "bump the version and update the changelog for a patch release";
    let note = note_for(&root, prompt).unwrap();
    assert!(
        note.contains("`__version__ = \"1.2.3\"` in src/clicky/__init__.py"),
        "{note}"
    );
    assert!(note.contains("Changelog: CHANGES.rst; its newest entry is headed `Version 1.2.3`"));
    assert!(
        note.contains("CI workflows (.github/workflows): publish.yaml"),
        "{note}"
    );
}

#[test]
fn a_dependency_change_gets_where_dependencies_are_declared() {
    let (_dir, root) = flit_project();
    let note = note_for(
        &root,
        "update the dependencies and make sure the build still works",
    );
    let note = note.unwrap();
    assert!(
        note.contains("`dependencies` in pyproject.toml [project] (1 now)"),
        "{note}"
    );
    assert!(
        note.contains("[project.optional-dependencies]: docs"),
        "{note}"
    );
    assert!(note.contains("Tests: `python -m pytest`"), "{note}");
}

#[test]
fn a_markdown_changelog_and_a_static_version_are_found() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let pyproject = "[project]\nname = \"t\"\nversion = \"2.2.1\"\n\n[build-system]\n\
build-backend = \"setuptools.build_meta\"\n";
    fs::write(root.join("pyproject.toml"), pyproject).unwrap();
    fs::write(
        root.join("CHANGELOG.md"),
        "# Changelog\n\n## 2.2.0\n\n- Added\n",
    )
    .unwrap();
    fs::write(root.join(".bumpversion.cfg"), "[bumpversion]\n").unwrap();
    let note = note_for(&root, "tag a release and publish it").unwrap();
    assert!(
        note.contains("Version: `2.2.1` in pyproject.toml [project]"),
        "{note}"
    );
    assert!(
        note.contains("its newest entry is headed `## 2.2.0`"),
        "{note}"
    );
    assert!(
        note.contains(".bumpversion.cfg lists every file a bump edits"),
        "{note}"
    );
    assert!(!note.contains("flit_core.wheel"), "{note}");
}

#[test]
fn coding_prompts_and_plain_plans_get_no_chore_note() {
    let (_dir, root) = flit_project();
    for prompt in [
        "build a function that parses ISO dates",
        "rebuild the index after many deletes",
        "create a roadmap for version 9",
        "break this project's next release into a checklist",
        "explain how the parser handles nested tables",
    ] {
        assert!(note_for(&root, prompt).is_none(), "{prompt}");
    }
}

#[test]
fn a_project_without_config_files_gets_no_note() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::write(root.join("notes.txt"), "build the wheel\n").unwrap();
    assert!(note_for(&root, "build the wheel and check it installs").is_none());
}

#[test]
fn an_ignored_config_file_is_not_read() {
    let (_dir, root) = flit_project();
    fs::write(root.join(".gitignore"), "CHANGES.rst\nMakefile\n").unwrap();
    let note = note_for(&root, "update the changelog").unwrap_or_default();
    assert!(!note.contains("CHANGES.rst"), "{note}");
    let note = note_for(&root, "build the wheel").unwrap();
    assert!(!note.contains("Make targets"), "{note}");
}

#[test]
fn the_note_holds_no_code_range() {
    let (_dir, root) = flit_project();
    let prompt = "bump the version, update the changelog and dependencies, run the test suite";
    let note = note_for(&root, prompt).unwrap();
    assert!(note.len() <= MAX_NOTE_CHARS, "{}", note.len());
    for line in note.lines() {
        let first = line
            .trim_start()
            .split_whitespace()
            .next()
            .unwrap_or_default();
        assert!(
            !first.contains(".py:") && !first.contains(".rst:"),
            "{line}"
        );
    }
}

#[test]
fn a_prompt_naming_code_keeps_the_code_search() {
    let (_dir, root) = flit_project();
    let mut response = json!({ "hookSpecificOutput": { "hookEventName": "UserPromptSubmit" } });
    let on = || true;
    assert!(added(
        &mut response,
        &root,
        "build the wheel and check it installs",
        &on
    ));
    let prompt = "build the wheel; `clicky.core.main` fails to import in it";
    assert!(!added(&mut response, &root, prompt, &on));
    let text = response["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert_eq!(text.matches(HEADER).count(), 2, "{text}");
    let off = || false;
    let mut untouched = json!({ "hookSpecificOutput": {} });
    assert!(!added(&mut untouched, &root, "build the wheel", &off));
    assert!(untouched["hookSpecificOutput"]
        .get("additionalContext")
        .is_none());
}
