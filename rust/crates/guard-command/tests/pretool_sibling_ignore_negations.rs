//! Sibling repositories whose `.gitignore` re-includes a literal path, such
//! as `.vscode/*` with `!.vscode/settings.json` or `*.log` with `!keep.log`.
//! A negation that names an ordinary file cannot widen the search to a
//! secret, so the search stays quiet; one that names a secret, a plainly
//! ignored directory or a glob, or that re-includes a hidden entry holding a
//! secret, keeps its review.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn sibling_search_with_literal_negations_is_allowed() {
    let layout = layout("rg-sibling-literal-negations");
    let sibling = layout.org.join("service-api");
    write(
        sibling.join(".gitignore"),
        "dist/\n*.log\n!keep.log\n.vscode/*\n!.vscode/settings.json\n!/.gitkeep\n",
    );
    write(sibling.join("keep.log"), "fixture\n");
    write(sibling.join(".gitkeep"), "");
    write(sibling.join(".vscode/settings.json"), "{}\n");
    write(sibling.join("src/.gitignore"), "generated/\n!README.md\n");
    write(sibling.join("src/README.md"), "fixture\n");
    write(sibling.join("web/.gitignore"), "!.gitkeep\n");
    write(sibling.join("web/src/main.rs"), "fn main() {} // fixture\n");
    write(sibling.join(".git/info/exclude"), "*.tmp\n!notes.tmp\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ../service-api",
        "rg -n fixture ../service-api/src",
        "rg -n fixture ../service-api/web/src",
        "rg -n fixture ~/Code/org/service-api",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn sibling_search_whose_negations_could_reach_a_secret_is_reviewed() {
    let cases: [(&str, &[(&str, &str)]); 8] = [
        (
            "env-example",
            &[
                (".gitignore", ".env*\n!.env.example\n"),
                (".env.example", "TOKEN=fixture\n"),
            ],
        ),
        ("env-absent", &[(".gitignore", ".env*\n!.env.local\n")]),
        ("glob", &[(".gitignore", "*.pem\n!server*.pem\n")]),
        ("double-star", &[(".gitignore", "!**/notes.md\n")]),
        ("pruned", &[(".gitignore", "target/\n!target\n")]),
        (
            "nested-pruned",
            &[
                (".gitignore", "node_modules/\n"),
                ("src/.gitignore", "!node_modules/pkg/index.js\n"),
            ],
        ),
        ("credential", &[("src/.gitignore", "!credentials.json\n")]),
        (
            "hidden-directory",
            &[
                (".gitignore", "!.github\n"),
                (".github/credentials.json", "{}\n"),
            ],
        ),
    ];
    for (name, files) in cases {
        let layout = layout(&format!("rg-sibling-negation-{name}"));
        let sibling = layout.org.join("service-api");
        for (path, text) in files {
            write(sibling.join(path), text);
        }
        let cwd = layout.org.join("app-portal");
        assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", false);
    }
}
