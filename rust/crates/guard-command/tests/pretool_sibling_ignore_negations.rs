//! Sibling repositories whose `.gitignore` re-includes a path, literal as in
//! `.vscode/*` with `!.vscode/settings.json`, or globbed as in a JavaScript
//! repository's `!src/icons/**/*.js`. A negation that names ordinary files
//! cannot widen the search to a secret, so the search stays quiet; one that
//! can name a plainly ignored directory, or that re-includes a hidden entry
//! holding a secret the search reaches, keeps its review. A rule naming a
//! file that is not there, or one beside the directory being searched,
//! decides nothing.
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
fn a_globbed_negation_naming_ordinary_files_is_allowed() {
    // The shape a JavaScript repository writes: a vendored directory is
    // ignored and one bundle of generated sources inside it is re-included.
    // The pattern names `.js` files, so no hidden entry and no pruned
    // directory is back in reach, and every search in the repository stays
    // proven rather than the whole tree going to review over one rule.
    let layout = layout("rg-sibling-negation-globbed-sources");
    let sibling = layout.org.join("service-api");
    write(
        sibling.join(".gitignore"),
        "node_modules\n*.log\n!src/components/icons/react-icons/**/*.js\n",
    );
    write(
        sibling.join("src/components/icons/react-icons/fa/index.js"),
        "// fixture\n",
    );
    write(sibling.join("src/app/page.tsx"), "// fixture\n");
    write(sibling.join("__tests__/page.test.ts"), "// fixture\n");
    write(sibling.join("node_modules/pkg/index.js"), "// fixture\n");
    write(sibling.join(".DS_Store"), "fixture\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ../service-api",
        "rg -n fixture ../service-api/src",
        "rg -ln fixture ../service-api/__tests__",
        "rg -n fixture ~/Code/org/service-api/src/components",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn sibling_search_whose_negations_could_reach_a_secret_is_reviewed() {
    let cases: [(&str, &[(&str, &str)]); 14] = [
        (
            "env-example",
            &[
                (".gitignore", ".env*\n!.env.example\n"),
                (".env.example", "TOKEN=fixture\n"),
            ],
        ),
        // The glob re-includes a hidden key the search would then read.
        (
            "glob",
            &[
                (".gitignore", "*.pem\n!.server*.pem\n"),
                (".server-prod.pem", "-----BEGIN FIXTURE-----\n"),
            ],
        ),
        // The glob can name the pruned directory itself, so `rg` reads a
        // subtree this walk never screened.
        (
            "glob-reaches-pruned",
            &[
                (".gitignore", "dist/\n!di*\n"),
                ("dist/.env", "TOKEN=fixture\n"),
            ],
        ),
        // A negated character class re-includes what the case-folded matcher
        // would read as excluded, so the negation is not read at all.
        (
            "glob-negated-class",
            &[
                (".gitignore", ".*\n!.[!A-Z]*\n"),
                (".env", "TOKEN=fixture\n"),
            ],
        ),
        // A POSIX class the matcher reads as a flat class is refused the same
        // way.
        (
            "glob-posix-class",
            &[
                (".gitignore", ".*\n!.[[:alpha:]]*\n"),
                (".env", "TOKEN=fixture\n"),
            ],
        ),
        // A hidden environment file a glob re-includes is still a secret.
        (
            "glob-hidden-env",
            &[
                (".gitignore", ".env*\n!.env.*\n"),
                (".env.local", "TOKEN=fixture\n"),
            ],
        ),
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
