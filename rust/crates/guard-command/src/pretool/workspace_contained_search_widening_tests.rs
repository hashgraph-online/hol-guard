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
