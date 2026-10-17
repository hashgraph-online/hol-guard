//! A sibling repository named one file at a time: `rg PATTERN
//! ~/Code/org/service-api/src/main.rs`, and the same spelling for a file that
//! is not there. `rg` opens a named file whatever the ignore rules say and
//! prints an error for a missing one, so both answers rest on the path's own
//! components rather than on a walk. Hidden, credential and linked-away
//! spellings keep their review.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, repository, write};

#[test]
fn naming_a_file_in_a_sibling_repository_is_allowed() {
    let layout = layout("rg-sibling-named-file");
    let sibling = layout.org.join("service-api");
    write(
        sibling.join("src/journey/runner.ts"),
        "export const x = 1;\n",
    );
    write(
        sibling.join(".github/workflows/release.yml"),
        "name: release\n",
    );
    write(sibling.join("dist/bundle.js"), "// fixture\n");
    write(sibling.join(".gitignore"), "dist/\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/org/service-api/src/main.rs",
        "rg -n export ~/Code/org/service-api/src/journey/runner.ts",
        "rg -n release ~/Code/org/service-api/.github/workflows/release.yml",
        // `rg` searches a named file even where the walk would prune it.
        "rg -n fixture ~/Code/org/service-api/dist/bundle.js",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn naming_a_missing_file_in_a_sibling_repository_is_allowed() {
    let layout = layout("rg-sibling-missing-file");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/org/service-api/src/lib.rs",
        "rg -n fixture ~/Code/org/service-api/src/journey/runner.ts | head -6",
        "rg -n fixture ~/Code/org/service-api/src/main.rs ~/Code/org/service-api/src/lib.rs",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn source_code_named_after_what_it_handles_is_still_source_code() {
    let layout = layout("rg-sibling-named-source");
    let sibling = layout.org.join("service-api");
    write(sibling.join("src/auth.ts"), "export const x = 1;\n");
    write(sibling.join("src/token.ts"), "export const x = 1;\n");
    write(sibling.join("lib/password.py"), "X = 1\n");
    write(sibling.join("tests/fixtures/tokens.json"), "{}\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n export ~/Code/org/service-api/src/auth.ts",
        "rg -n export ~/Code/org/service-api/src/token.ts",
        "rg -n X ~/Code/org/service-api/lib/password.py",
        // A test tree names its vectors for what they exercise.
        "rg -n fixture ~/Code/org/service-api/tests/fixtures/tokens.json",
        // The same spelling before the file is written.
        "rg -n export ~/Code/org/service-api/src/session-auth.ts",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn a_named_path_that_could_reach_a_secret_is_reviewed() {
    let layout = layout("rg-sibling-named-secret");
    let sibling = layout.org.join("service-api");
    write(sibling.join(".env"), "TOKEN=fixture\n");
    write(sibling.join("src/credentials.json"), "{}\n");
    write(sibling.join(".secrets/notes.md"), "fixture\n");
    std::os::unix::fs::symlink(layout.home.join(".ssh"), sibling.join("src/keys")).unwrap();
    write(layout.home.join(".ssh/id_rsa"), "fixture\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/org/service-api/.env",
        "rg -n fixture ~/Code/org/service-api/src/credentials.json",
        "rg -n fixture ~/Code/org/service-api/.secrets/notes.md",
        "rg -n fixture ~/Code/org/service-api/.git/config",
        "rg -n fixture ~/Code/org/service-api/src/keys/id_rsa",
        // A missing name is screened the same way the file would be. A key
        // that is there already has an answer before this rule is asked:
        // the ordinary read screen admits a named file below home whose
        // name is not a credential's, as it does inside the project.
        "rg -n fixture ~/Code/org/service-api/src/.env.local",
        "rg -n fixture ~/Code/org/service-api/src/secrets/prod.pem",
        // Nothing below home that is not a repository gets this route.
        "rg -n fixture ~/Code/org/notes/todo.md",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}

#[test]
fn a_repository_inside_a_credential_store_keeps_its_review() {
    let layout = layout("rg-sibling-store-repository");
    // A repository directory named the way source code is, inside a store:
    // the file screen stands aside for a source-code name, and a screen of
    // the components below the repository root never sees the store above it.
    let sibling = layout.home.join("Code/secrets/service.ts");
    repository(&sibling);
    write(sibling.join("prod.json"), "{}\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/secrets/service.ts/prod.json",
        // A name that is not there yet is held to the same screen.
        "rg -n fixture ~/Code/secrets/service.ts/staging.json",
        // A missing directory that would be a store is screened as well, not
        // only the last name in the spelling.
        "rg -n fixture ~/Code/org/service-api/src/secrets/prod.json",
        "rg -n fixture ~/Code/org/service-api/src/api-tokens/prod.json",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}
