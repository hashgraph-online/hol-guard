//! A search widened past ignore rules keeps its review: a hidden file an
//! ignore rule puts back in reach may hold a secret the sandbox does not list.
use crate::pretool::workspace_contained_tests::{reason, workspace, CONTAINED};

#[test]
fn a_search_widened_past_ignore_rules_keeps_its_review() {
    let ws = workspace("search-widening", true);
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(ws.join(".gitignore"), ".env*\n").unwrap();
    std::fs::write(ws.join("src/.gitignore"), "!.env.test.ts\n").unwrap();
    std::fs::write(ws.join("src/.env.test.ts"), "KEY=SYNTHETIC_MARKER_ONLY\n").unwrap();
    std::fs::write(ws.join("src/app.ts"), "export const KEY = 1;\n").unwrap();
    for command in [
        "rg -n KEY --glob '**'",
        "rg -n KEY src --glob 'src/*.ts'",
        "rg -n KEY --context-separator -- --iglob '*.TS'",
        "rg -n KEY -g'*.ts'",
        "rg -nuu KEY",
        "rg -n --hidden KEY",
        "rg -n --no-ignore-vcs KEY",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn an_inclusion_glob_that_brings_back_no_hidden_file_still_runs_contained() {
    let ws = workspace("search-widening-plain", true);
    for directory in ["src", "docs", ".github/workflows"] {
        std::fs::create_dir_all(ws.join(directory)).unwrap();
    }
    std::fs::write(ws.join(".gitignore"), "output\n").unwrap();
    std::fs::write(ws.join(".env"), "KEY=SYNTHETIC_MARKER_ONLY\n").unwrap();
    std::fs::write(ws.join("README.md"), "# TODO\n").unwrap();
    std::fs::write(ws.join("docs/guide.md"), "TODO\n").unwrap();
    std::fs::write(ws.join("src/app.ts"), "export const route = 1;\n").unwrap();
    std::fs::write(ws.join(".github/workflows/ci.yml"), "on: push # TODO\n").unwrap();
    for command in [
        "rg --files -g 'README.md' -g 'src/**' -g '*settings*'",
        "rg --files -g '**/docs/**' -g '!output'",
        "rg --files -g '**/*.md'",
        "rg -n \"TODO\" -g '**/*.{md,yml}' .",
        "rg -n route --glob 'src/**'",
    ] {
        assert_eq!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn an_inclusion_glob_naming_a_hidden_directory_keeps_its_review() {
    let ws = workspace("search-widening-hidden-dir", true);
    std::fs::create_dir_all(ws.join("src/.local")).unwrap();
    std::fs::write(ws.join("src/app.ts"), "export const KEY = 1;\n").unwrap();
    std::fs::write(
        ws.join("src/.local/settings.ts"),
        "KEY=SYNTHETIC_MARKER_ONLY\n",
    )
    .unwrap();
    for command in ["rg -n KEY -g 'src/**'", "rg -n KEY --glob '**/*.ts'"] {
        let expected_contained = command.ends_with("'**/*.ts'");
        assert_eq!(
            reason("omp", command, &ws, true) == CONTAINED,
            expected_contained,
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(&ws);
}
