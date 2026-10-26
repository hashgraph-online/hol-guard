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
