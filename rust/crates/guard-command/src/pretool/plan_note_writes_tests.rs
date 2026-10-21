use super::{plan_note_name, plan_note_path};
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/plan-note-writes")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home/.codex/plans")).unwrap();
    std::fs::create_dir_all(root.join("home/.claude/plans")).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn only_visible_markdown_names_that_are_not_instruction_files_qualify() {
    for name in [
        "closeout.md",
        "2026-10-19-acme-closeout.md",
        "Acme Plan.md",
        "notes.MD",
        "a.b.md",
    ] {
        assert!(plan_note_name(name), "{name}");
    }
    for name in [
        "",
        ".md",
        ".hidden.md",
        "notes.txt",
        "hooks.json",
        "config.toml",
        "closeout",
        "closeout.md.sh",
        "closeout.mdx",
        "AGENTS.md",
        "agents.md",
        "Claude.md",
        "GEMINI.md",
        "copilot-instructions.md",
        "a:stream.md",
        "a\\b.md",
        "a\nb.md",
    ] {
        assert!(!plan_note_name(name), "{name:?}");
    }
}

#[test]
fn a_note_directly_inside_a_plan_directory_qualifies() {
    let root = scratch("direct");
    let home = root.join("home");
    for relative in [
        ".codex/plans/closeout.md",
        ".claude/plans/closeout.md",
        ".codex/plans/Closeout Report.md",
    ] {
        assert!(plan_note_path(&home.join(relative), &home), "{relative}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nothing_else_below_a_harness_home_qualifies() {
    let root = scratch("others");
    let home = root.join("home");
    for relative in [
        ".codex/hooks.json",
        ".codex/config.toml",
        ".codex/AGENTS.md",
        ".codex/notes.md",
        ".codex/rules/default.md",
        ".codex/skills/demo/SKILL.md",
        ".codex/plans/AGENTS.md",
        ".codex/plans/notes.txt",
        ".codex/plans/hooks.json",
        ".codex/plans/.hidden.md",
        ".codex/plans/evidence/closeout.md",
        ".codex/plans/evidence/run-1/closeout.md",
        ".codex/plan/closeout.md",
        ".codex/Plans/closeout.md",
        ".claude/settings.md",
        ".claude/plans/CLAUDE.md",
        ".agent/artifacts/closeout.md",
        ".agents/plans/closeout.md",
        ".config/plans/closeout.md",
        "plans/closeout.md",
        ".codex/plans",
    ] {
        assert!(!plan_note_path(&home.join(relative), &home), "{relative}");
    }
    // Outside the home nothing qualifies, and a home must lie inside no
    // harness directory.
    assert!(!plan_note_path(
        &root.join(".codex/plans/closeout.md"),
        &home
    ));
    let nested = root.join(".claude/home");
    assert!(!plan_note_path(
        &nested.join(".codex/plans/closeout.md"),
        &nested
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_missing_plan_directory_does_not_qualify() {
    let root = scratch("missing");
    let home = root.join("home");
    std::fs::remove_dir_all(home.join(".codex/plans")).unwrap();
    assert!(!plan_note_path(
        &home.join(".codex/plans/closeout.md"),
        &home
    ));
    assert!(plan_note_path(
        &home.join(".claude/plans/closeout.md"),
        &home
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_plan_directory_that_is_a_link_does_not_qualify() {
    let root = scratch("linked");
    let home = root.join("home");
    std::fs::remove_dir_all(home.join(".claude/plans")).unwrap();
    std::fs::create_dir_all(root.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(root.join("elsewhere"), home.join(".claude/plans")).unwrap();
    // The caller passes the resolved path; the link directory is not a plan
    // directory by its own metadata either.
    assert!(!plan_note_path(
        &home.join(".claude/plans/closeout.md"),
        &home
    ));
    std::fs::remove_dir_all(root).unwrap();
}
