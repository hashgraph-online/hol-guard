//! A tool keeps its own notes and skills in its own home directory, and an
//! agent looks them up by the word it remembers (`-name "*usage-rollup*"`) or
//! by walking the skill folder it just named. Both print names only, so both
//! are ordinary work, while a pattern that names a kind of file rather than a
//! word, one that can reach a credential name, and a tree that is not a skill
//! tree all keep review.
use crate::pretool_home_layout_reads::{assert_decision, layout};
use std::path::Path;

fn tool_home(home: &Path) {
    for directory in [
        ".web-client/skills/usage-rollup/scripts",
        ".web-client/artifacts/2026-10",
        ".report-lane/usage-rollup/2026-10",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    std::fs::write(
        home.join(".web-client/skills/usage-rollup/SKILL.md"),
        "---\nname: usage-rollup\n---\nSynthetic skill body.\n",
    )
    .unwrap();
    std::fs::write(
        home.join(".web-client/skills/usage-rollup/scripts/collect.sh"),
        "#!/bin/sh\necho fixture\n",
    )
    .unwrap();
    std::fs::write(
        home.join(".web-client/artifacts/2026-10/settings.json"),
        "{\"theme\": \"dark\"}\n",
    )
    .unwrap();
    std::fs::write(
        home.join(".report-lane/usage-rollup/2026-10/web-client-summary.md"),
        "# Summary\nInert report text.\n",
    )
    .unwrap();
}

#[test]
fn a_word_glob_under_a_tool_home_directory_is_allowed() {
    let layout = layout("tool-home-word-glob");
    tool_home(&layout.home);
    for command in [
        r#"find ~/.web-client -maxdepth 4 -type d -name "*usage-rollup*""#,
        r#"find ~/.report-lane -maxdepth 4 -name "*web-client*" 2>/dev/null"#,
        r#"find ~/.web-client ~/.report-lane -maxdepth 4 -type d -name "*usage-rollup*" 2>/dev/null"#,
        r#"find ~/.report-lane -maxdepth 4 -iname "*WEB-CLIENT*""#,
    ] {
        assert_decision(&layout.org, &layout.home, command, true);
    }
}

#[test]
fn a_glob_that_names_a_kind_of_file_rather_than_a_word_is_still_reviewed() {
    let layout = layout("tool-home-extension-glob");
    tool_home(&layout.home);
    for command in [
        r#"find ~/.web-client -maxdepth 4 -name "*.json""#,
        r#"find ~/.web-client -maxdepth 4 -name "*.toml""#,
        r#"find ~/.web-client -maxdepth 4 -name "*.sh""#,
        // Three letters is a kind of file spelled without its dot, not a name
        // anyone chose.
        r#"find ~/.web-client -maxdepth 4 -name "*log""#,
    ] {
        assert_decision(&layout.org, &layout.home, command, false);
    }
}

#[test]
fn a_glob_that_can_reach_a_credential_name_is_still_reviewed() {
    let layout = layout("tool-home-secret-glob");
    tool_home(&layout.home);
    for command in [
        r#"find ~/.web-client -maxdepth 4 -name "*credential-notes*""#,
        r#"find ~/.web-client -maxdepth 4 -name "*keyring-export*""#,
        r#"find ~/.web-client -maxdepth 4 -name "*password-reset*""#,
        r#"find ~/.web-client -maxdepth 4 -name "*.env.local""#,
        // A bracket stands for letters that reading the literal run cannot
        // see, so the run is not read as a word at all.
        r#"find ~/.web-client -maxdepth 4 -name "[ac]uth.json""#,
    ] {
        assert_decision(&layout.org, &layout.home, command, false);
    }
}

#[test]
fn the_skills_tree_of_a_tool_guard_does_not_know_is_listed_without_review() {
    let layout = layout("tool-home-skills");
    tool_home(&layout.home);
    for command in [
        "find ~/.web-client/skills/usage-rollup -type f",
        "find ~/.web-client/skills -type d",
        "ls ~/.web-client/skills",
        "ls ~/.web-client/skills/usage-rollup",
    ] {
        assert_decision(&layout.org, &layout.home, command, true);
    }
}

#[test]
fn a_tool_directory_that_is_not_a_skills_tree_still_asks_for_an_unbounded_walk() {
    let layout = layout("tool-home-not-skills");
    tool_home(&layout.home);
    for command in [
        // No pattern bounds what the walk prints, and `artifacts` is the
        // tool's own state rather than a tree of skill folders.
        "find ~/.web-client/artifacts -type f",
        "find ~/.web-client -type f",
    ] {
        assert_decision(&layout.org, &layout.home, command, false);
    }
}

#[test]
fn a_hidden_or_credential_named_entry_below_a_skills_tree_is_still_reviewed() {
    let layout = layout("tool-home-skills-screens");
    tool_home(&layout.home);
    for directory in [
        ".web-client/skills/.private",
        ".web-client/skills/credentials",
        ".ssh/skills",
    ] {
        std::fs::create_dir_all(layout.home.join(directory)).unwrap();
    }
    for command in [
        "find ~/.web-client/skills/.private -type f",
        "find ~/.web-client/skills/credentials -type f",
        "find ~/.ssh/skills -type f",
    ] {
        assert_decision(&layout.org, &layout.home, command, false);
    }
}
