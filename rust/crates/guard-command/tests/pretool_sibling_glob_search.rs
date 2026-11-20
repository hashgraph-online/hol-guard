//! `grep` and `ls` over a shell glob in a sibling repository, through a
//! project-metadata directory such as `.github`, spelled with `../`, or
//! across the sibling repositories themselves (`~/Code/org/*/README.md`).
//! Every name the shell can expand the glob to must lie in a git working tree
//! beside the session's own and clear the same screens as a literal operand.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn sibling_globs_through_metadata_and_across_repositories_are_allowed() {
    let layout = layout("sibling-glob-search");
    let org = layout.org.display().to_string();
    let cwd = layout.org.join("app-portal");
    for repository in ["app-portal", "service-api"] {
        write(layout.org.join(repository).join("README.md"), "# fixture\n");
    }
    let sibling = format!("{org}/service-api");
    for command in [
        format!("grep -rn \"node\\|test\" {sibling}/.github/workflows/*.yml | head -4"),
        "grep -rn node ../service-api/.github/workflows/*.yml".to_owned(),
        format!("rg -n node {sibling}/.github/workflows/*.yml"),
        format!("ls {sibling}/.github/workflows/*.yml"),
        format!("ls {org}/*/README.md"),
        format!("ls {org}/*/.github/workflows/*.yml"),
        "ls ../*/README.md".to_owned(),
        "ls ~/Code/org/*/README.md".to_owned(),
        format!("wc -l {sibling}/src/*.rs"),
        format!("cat {sibling}/src/*.rs"),
        // Optional config probes that match nothing print only an error.
        format!("ls {sibling}/vitest.config.* {sibling}/vite.config.*"),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    // From the directory that holds the repositories.
    for command in [
        format!("ls {org}/*/README.md"),
        format!("ls {sibling}/vitest.config.* {sibling}/vite.config.*"),
    ] {
        assert_decision(&layout.org, &layout.home, &command, true);
    }
}

#[test]
fn sibling_globs_reaching_secrets_or_leaving_the_repositories_stay_reviewed() {
    let layout = layout("sibling-glob-search-negative");
    let org = layout.org.display().to_string();
    let cwd = layout.org.join("app-portal");
    let sibling = format!("{org}/service-api");
    write(layout.org.join("service-api/.env"), "TOKEN=fixture\n");
    write(
        layout.org.join("service-api/.github/credentials.json"),
        "{}\n",
    );
    write(layout.org.join("service-api/README.md"), "# fixture\n");
    write(layout.home.join("Code/notes/README.md"), "# fixture\n");
    for command in [
        format!("grep -rn KEY {sibling}/.env*"),
        format!("ls {org}/*/.env"),
        format!("cat {org}/*/.git/config"),
        format!("grep -rn url {org}/*/.git/config"),
        format!("ls {sibling}/.git/*"),
        format!("ls {sibling}/.github/*"),
        format!("grep -rn -f {sibling}/.env node {sibling}/.github/workflows/*.yml"),
        format!("grep -rn --file={sibling}/.env node {sibling}/.github/workflows/*.yml"),
        format!("ls -R {org}/*"),
        format!("ls {org}/*/[R]EADME.md"),
        format!("ls {org}/**/README.md"),
        format!("ls {sibling}/missing/vite.config.*"),
        "ls ../../*/README.md".to_owned(),
        "ls ~/Code/*/README.md".to_owned(),
        "ls ~/*/README.md".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

#[test]
fn org_globs_that_could_match_outside_a_repository_stay_reviewed() {
    let cases: [(&str, &str); 3] = [
        // A plain directory beside the repositories.
        ("plain", "plain-notes/README.md"),
        // A hidden directory `*` matches under `dotglob`.
        ("hidden", ".private/README.md"),
        // A hidden file `*` matches under `dotglob`.
        ("dotfile", "service-api/.github/workflows/.token.yml"),
    ];
    for (name, path) in cases {
        let layout = layout(&format!("sibling-glob-search-{name}"));
        let org = layout.org.display().to_string();
        write(layout.org.join(path), "fixture\n");
        write(layout.org.join("service-api/README.md"), "# fixture\n");
        let cwd = layout.org.join("app-portal");
        let command = if name == "dotfile" {
            format!("ls {org}/service-api/.github/workflows/*")
        } else {
            format!("ls {org}/*/README.md")
        };
        assert_decision(&cwd, &layout.home, &command, false);
    }
    let layout = layout("sibling-glob-search-link");
    let elsewhere = layout.home.join("elsewhere");
    write(elsewhere.join("README.md"), "# fixture\n");
    std::os::unix::fs::symlink(&elsewhere, layout.org.join("linked")).unwrap();
    let command = format!("ls {}/*/README.md", layout.org.display());
    assert_decision(
        &layout.org.join("app-portal"),
        &layout.home,
        &command,
        false,
    );
}

/// A glob naming more files than the expansion lists is proven by walking
/// the literal directory it expands below, the same proof a recursive search
/// of that directory clears.
#[test]
fn wide_sibling_globs_are_proven_by_their_directory() {
    let layout = layout("sibling-glob-search-wide");
    let cwd = layout.org.join("app-portal");
    let sibling = format!("{}/service-api", layout.org.display());
    for index in 0..300 {
        write(
            layout.org.join(format!("service-api/src/module{index}.ts")),
            "export {};\n",
        );
    }
    write(
        layout.org.join("service-api/src/nested/deep.ts"),
        "export {};\n",
    );
    for command in [
        format!("rg -n export {sibling}/src/*.ts"),
        format!("grep -n export {sibling}/src/*.ts | head -4"),
        format!("rg -n export {sibling}/src/**/*.ts"),
        format!("rg -n export {sibling}/src/*/*.ts"),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    // No shell option makes `*.ts` name `.env`, so a key beside the matches
    // leaves the search as it was; a pattern that can name it does not.
    write(layout.org.join("service-api/src/.env"), "TOKEN=fixture\n");
    for command in [
        format!("rg -n export {sibling}/src/*.ts"),
        format!("grep -n export {sibling}/src/*.ts"),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    for command in [
        format!("rg -n TOKEN {sibling}/src/.*"),
        format!("rg -n TOKEN {sibling}/src/*"),
        format!("grep -n TOKEN {sibling}/src/*env"),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

/// A wide glob whose only pattern is its last component reads nothing but
/// the entries that pattern names. A test fixture's `.env` deeper in the
/// directory does not hold it. A key the pattern can name under `dotglob` or
/// `nocaseglob`, or one inside a matched directory that `-r` walks, does.
#[test]
fn wide_globs_are_proven_by_the_entries_they_name() {
    let layout = layout("sibling-glob-search-named");
    let cwd = layout.org.join("app-portal");
    for index in 0..300 {
        write(cwd.join(format!("tests/test_guard_{index}.py")), "x = 1\n");
    }
    write(
        cwd.join("tests/fixtures/bad-plugin/.env"),
        "TOKEN=fixture\n",
    );
    for command in [
        "grep -n x tests/test_*.py",
        "grep -rn -e x -e y tests/test_*.py | head -8",
        "rg -n x tests/test_*.py",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
    write(cwd.join("tests/test_guard_cases/.env"), "TOKEN=fixture\n");
    write(cwd.join("tests/TEST_id_rsa"), "fixture\n");
    for command in [
        "grep -rn TOKEN tests/*",
        "grep -rn TOKEN tests/test_guard_*",
        "grep -n x tests/test_*",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}

/// The entry list holds files alone. A matched directory, whose name such as
/// `credentials` only the walk of its parent keeps in view, and a pattern the
/// list cannot match the way the shell does, such as a `[[:alpha:]]` class,
/// both fall back to that walk, which a key anywhere in the directory holds.
#[test]
fn wide_globs_walk_the_directory_for_matched_directories_and_classes() {
    let layout = layout("sibling-glob-search-named-fallback");
    let cwd = layout.org.join("app-portal");
    for index in 0..300 {
        write(cwd.join(format!("tests/test_guard_{index}.py")), "x = 1\n");
    }
    write(cwd.join("tests/a]x.py"), "x = 1\n");
    write(cwd.join("tests/credentials/prod.json"), "{}\n");
    for command in ["grep -rn TOKEN tests/c*", "grep -rn TOKEN tests/*"] {
        assert_decision(&cwd, &layout.home, command, false);
    }
    // The shell reads `[[:alpha:]]` as one letter, so both name `id_rsa`.
    write(cwd.join("tests/id_rsa"), "fixture\n");
    for command in [
        "grep -n x tests/[[:alpha:]]*",
        "grep -n x tests/[[:alpha:]]d_rsa",
        "rg -n x tests/[[:lower:]]d_rsa",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
    assert_decision(&cwd, &layout.home, "grep -n x tests/test_*.py", true);
}

/// The directory proof stands in only for an expansion that ran out of room.
/// A glob that steps back out of the directory, or that the shell would
/// expand to a link the search then follows, stays reviewed whether or not
/// it is wide.
#[test]
fn wide_globs_refuse_parent_steps_and_links() {
    let layout = layout("sibling-glob-search-wide-escape");
    let cwd = layout.org.join("app-portal");
    let sibling = format!("{}/service-api", layout.org.display());
    for index in 0..300 {
        write(
            layout
                .org
                .join(format!("service-api/src/m{index}/index.ts")),
            "export {};\n",
        );
    }
    write(
        layout.org.join("service-api/private/key.pem"),
        "-----BEGIN PRIVATE KEY-----\n",
    );
    write(layout.org.join("service-api/lib/a.ts"), "export {};\n");
    write(layout.org.join("service-api/lib/b.ts"), "export {};\n");
    assert_decision(
        &cwd,
        &layout.home,
        &format!("rg -n export {sibling}/src/*/index.ts"),
        true,
    );
    assert_decision(
        &cwd,
        &layout.home,
        &format!("grep -n KEY {sibling}/src/*/../../private/*.pem"),
        false,
    );
    let secret = layout.home.join("notes/secret.txt");
    write(secret.clone(), "TOKEN=fixture\n");
    std::os::unix::fs::symlink(&secret, layout.org.join("service-api/lib/link.ts")).unwrap();
    std::os::unix::fs::symlink(&secret, layout.org.join("service-api/src/link.ts")).unwrap();
    std::os::unix::fs::symlink(&secret, layout.org.join("service-api/src/m7/link.ts")).unwrap();
    for command in [
        format!("grep -n TOKEN {sibling}/lib/*.ts"),
        format!("grep -n TOKEN {sibling}/src/*.ts"),
        format!("rg -n TOKEN {sibling}/src/*/*.ts"),
        format!("rg -n TOKEN {sibling}/src/**/*.ts"),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

/// A test directory with thousands of files, as large web projects keep in
/// `__tests__`. Each file the glob names is proven as a root of its own, and
/// one evaluation remembers every one of those proofs. Remembering them in a
/// list searched from the front made the decision quadratic in the number of
/// files: these two searches took 12 and 32 seconds in a debug build, the
/// hook ran out of time, and the agent got an error with no way to approve.
#[test]
fn thousands_of_globbed_files_are_decided_within_the_hook_budget() {
    let layout = layout("sibling-glob-search-thousands");
    let cwd = layout.org.join("app-portal");
    let sibling = format!("{}/service-api", layout.org.display());
    for index in 0..4900 {
        write(
            layout
                .org
                .join(format!("service-api/__tests__/case-{index}.test.ts")),
            "export {};\n",
        );
    }
    let started = std::time::Instant::now();
    for command in [
        format!("grep -l PGlite {sibling}/__tests__/*.ts"),
        format!("grep -rln PGlite {sibling}/__tests__/*.ts | head -4"),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
    // About six seconds in a debug build with the memo keyed by hash, and
    // forty-four with the list.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "deciding the wide globs took {:?}",
        started.elapsed()
    );
}
