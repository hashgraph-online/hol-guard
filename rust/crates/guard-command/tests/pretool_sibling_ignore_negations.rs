//! Sibling repositories whose `.gitignore` re-includes a literal path, such
//! as `.vscode/*` with `!.vscode/settings.json` or `*.log` with `!keep.log`.
//! A negation that names an ordinary file cannot widen the search to a
//! secret, so the search stays quiet; one that names a plainly ignored
//! directory or a glob, or that re-includes a hidden entry holding a secret
//! the search reaches, keeps its review. A rule naming a file that is not
//! there, or one beside the directory being searched, decides nothing.
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
fn a_double_star_negation_naming_an_ordinary_file_is_allowed() {
    // `!**/notes.md` re-includes that one name however deep it sits, which
    // is what the bare name already means, and the name is an ordinary
    // document. The rule decides nothing about the directories the pattern
    // crosses, so `dist/` stays pruned and the search stays proven.
    for (name, files) in [
        (
            "nested",
            [
                (".gitignore", "dist/\n!**/notes.md\n"),
                ("docs/team/notes.md", "fixture\n"),
            ],
        ),
        (
            "root",
            [
                (".gitignore", "dist/\n!**/notes.md\n"),
                ("notes.md", "fixture\n"),
            ],
        ),
        (
            "absent",
            [
                (".gitignore", "dist/\n!**/notes.md\n"),
                ("src/main.rs", "fn main() {} // fixture\n"),
            ],
        ),
    ] {
        let layout = layout(&format!("rg-sibling-negation-double-star-{name}"));
        let sibling = layout.org.join("service-api");
        for (path, text) in files {
            write(sibling.join(path), text);
        }
        write(sibling.join("dist/bundle.js"), "// fixture\n");
        let cwd = layout.org.join("app-portal");
        assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", true);
    }
}

#[test]
fn sibling_search_whose_negations_could_reach_a_secret_is_reviewed() {
    let cases: [(&str, &[(&str, &str)]); 10] = [
        (
            "env-example",
            &[
                (".gitignore", ".env*\n!.env.example\n"),
                (".env.example", "TOKEN=fixture\n"),
            ],
        ),
        ("glob", &[(".gitignore", "*.pem\n!server*.pem\n")]),
        (
            "double-star",
            &[
                (".gitignore", "!**/.env\n"),
                ("services/api/.env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "anchored-double-star",
            &[
                (".gitignore", "!src/**/.env\n"),
                ("src/a/b/.env", "TOKEN=fixture\n"),
            ],
        ),
        ("pruned", &[(".gitignore", "target/\n!target\n")]),
        // A trailing `**` re-includes every entry there is, the pruned
        // directory among them, so the search reads whatever it holds.
        (
            "bare-double-star",
            &[
                (".gitignore", "dist/\n!**\n"),
                ("dist/.env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "trailing-slash-double-star",
            &[
                (".gitignore", "dist/\n!**/\n"),
                ("dist/.env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "rooted-double-star",
            &[
                (".gitignore", "dist/\n!/**\n"),
                ("dist/.env", "TOKEN=fixture\n"),
            ],
        ),
        (
            "nested-pruned",
            &[
                (".gitignore", "node_modules/\n"),
                ("src/.gitignore", "!node_modules/pkg/index.js\n"),
            ],
        ),
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

#[test]
fn a_negation_the_search_cannot_reach_leaves_it_allowed() {
    // The rule names a file the repository does not hold, so nothing it
    // re-includes is ever searched.
    for (name, files) in [
        ("env-absent", [(".gitignore", ".env*\n!.env.local\n")]),
        (
            "credential-absent",
            [("src/.gitignore", "!credentials.json\n")],
        ),
    ] {
        let layout = layout(&format!("rg-sibling-negation-{name}"));
        let sibling = layout.org.join("service-api");
        for (path, text) in files {
            write(sibling.join(path), text);
        }
        write(sibling.join("src/main.rs"), "fn main() {} // fixture\n");
        let cwd = layout.org.join("app-portal");
        assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", true);
    }
}

#[test]
fn a_root_negation_beside_the_searched_directory_leaves_it_allowed() {
    // `.env*` with `!.env.example` is the ordinary JavaScript repository
    // layout. The template sits at the root, so a search named at a
    // subdirectory never reaches it.
    let layout = layout("rg-sibling-negation-out-of-reach");
    let sibling = layout.org.join("service-api");
    write(sibling.join(".gitignore"), ".env*\n!.env.example\n");
    write(sibling.join(".env.example"), "TOKEN=fixture\n");
    write(sibling.join("src/main.rs"), "fn main() {} // fixture\n");
    write(sibling.join("db/migrate.sql"), "-- fixture\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ../service-api/src",
        "rg -n fixture ../service-api/src ../service-api/db",
        "rg -n fixture ~/Code/org/service-api/src",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
    // The root itself still holds the template the rule re-includes.
    assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", false);
}

#[test]
fn an_anchored_negation_decides_only_its_own_path() {
    let layout = layout("rg-sibling-anchored-negation");
    let sibling = layout.org.join("service-api");
    // `!/.env.example` re-includes the root file and says nothing about the
    // one in `src`, which `rg` keeps skipping as an ordinary hidden entry.
    write(sibling.join(".gitignore"), ".env*\n!/.env.example\n");
    write(sibling.join(".env.example"), "TOKEN=fixture\n");
    write(sibling.join("src/.env.example"), "TOKEN=fixture\n");
    write(sibling.join("src/main.rs"), "fn main() {} // fixture\n");
    let cwd = layout.org.join("app-portal");
    assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api/src", true);
    // The search that reaches the root does meet the re-included file.
    assert_decision(&cwd, &layout.home, "rg -n fixture ../service-api", false);
}
