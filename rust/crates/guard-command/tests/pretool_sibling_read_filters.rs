//! Reads of a sibling repository below home that add a multi-range `sed -n`
//! print filter, a shell glob, or several search roots including `.github`.
//! These are the same reads Guard already allows in the session's own
//! repository; writes through `sed`, sensitive matches and roots outside a
//! repository still go to review.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn sibling_reads_with_multi_range_print_filters_are_allowed() {
    let layout = layout("sibling-sed-ranges");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api").display().to_string();
    for command in [
        format!("grep -n fixture {sibling}/src/main.rs | sed -n '1,12p;28,40p'"),
        format!("grep -n fixture {sibling}/src/main.rs | sed -n '1,12p'"),
        format!("cat {sibling}/src/main.rs | sed -n '1,5p; $p'"),
        format!("sed -n '1,12p;28,40p' {sibling}/src/main.rs"),
        "grep -n fixture src/main.rs | sed -n '1,12p;28,40p'".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
}

#[test]
fn sed_programs_that_write_execute_or_match_text_stay_reviewed() {
    let layout = layout("sibling-sed-negative");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    write(sibling.join(".env"), "TOKEN=fixture\n");
    let sibling = sibling.display().to_string();
    let read = format!("grep -n fixture {sibling}/src/main.rs");
    for command in [
        format!("{read} | sed -n '1p;w {sibling}/copy.txt'"),
        format!("{read} | sed -n '1p;W copy.txt'"),
        format!("{read} | sed -n '1p;e id'"),
        format!("{read} | sed -n '1p;r /etc/hosts'"),
        // A regex address may itself hold `;`, so only numeric ranges qualify.
        format!("{read} | sed -n '/fixture/p;1p'"),
        format!("{read} | sed -n '1p;'"),
        format!("{read} | sed -n -i '1p;2p'"),
        format!("sed -n '1p;2p' {sibling}/.env"),
        format!("sed -i -n '1p;2p' {sibling}/src/main.rs"),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

#[test]
fn glob_operands_inside_a_sibling_repository_are_allowed() {
    let layout = layout("sibling-glob");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    write(sibling.join("src/lib.rs"), "pub fn fixture() {}\n");
    let sibling = sibling.display().to_string();
    for command in [
        format!("grep -rln fixture {sibling}/src/*.rs | head -8"),
        format!("grep -ln fixture {sibling}/src/*.rs"),
        format!("rg -n fixture {sibling}/src/*.rs"),
        "rg -n fixture ~/Code/org/service-api/src/*.rs".to_owned(),
        format!("grep -rn fixture {sibling}/*"),
        // Every match lies in a sibling repository of the session's own.
        format!("grep -n fixture {}/*/src/*.rs", layout.org.display()),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
}

#[test]
fn globs_outside_a_repository_or_matching_sensitive_files_stay_reviewed() {
    let layout = layout("sibling-glob-negative");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    write(sibling.join("config/credentials.txt"), "TOKEN=fixture\n");
    write(sibling.join("src/server.pem"), "fixture\n");
    write(layout.org.join("plain-notes/todo.md"), "fixture\n");
    let org = layout.org.display().to_string();
    let sibling = sibling.display().to_string();
    for command in [
        format!("grep -n fixture {sibling}/config/*"),
        format!("grep -rl fixture {sibling}/*"),
        format!("grep -n fixture {sibling}/src/*.pem"),
        format!("rg -n fixture {sibling}/src/*.pem"),
        format!("grep -n fixture {sibling}/.git/*"),
        // The match lies in a directory beside the repositories, not in one.
        format!("grep -n fixture {org}/*/todo.md"),
        format!("grep -n fixture {org}/plain-notes/*.md"),
        "grep -n fixture ~/*".to_owned(),
        "rg -n fixture /*".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}

#[test]
fn several_sibling_search_roots_including_github_metadata_are_allowed() {
    let layout = layout("sibling-github-root");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api").display().to_string();
    for command in [
        format!("rg -n fixture {sibling}/src {sibling}/.github"),
        format!("rg -rn fixture {sibling}/src {sibling}/.github 2>/dev/null | head"),
        "rg -n fixture ../service-api/.github/workflows".to_owned(),
        "rg -n fixture ~/Code/org/service-api/.github".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
}

#[test]
fn hidden_sibling_search_roots_that_could_hold_secrets_stay_reviewed() {
    let base = layout("sibling-hidden-root");
    let cwd = base.org.join("app-portal");
    let sibling = base.org.join("service-api");
    write(sibling.join(".secrets/token.txt"), "TOKEN=fixture\n");
    write(sibling.join(".github/credentials.json"), "{}\n");
    for operand in [
        "../service-api/.secrets",
        "../service-api/.git",
        "../service-api/.github",
    ] {
        let command = format!("rg -n fixture {operand}");
        assert_decision(&cwd, &base.home, &command, false);
    }
    let cases: [(&str, &str, &str); 2] = [
        ("ignored", ".gitignore", ".github\n"),
        ("rgignore", ".github/.rgignore", "!.env\n"),
    ];
    for (name, path, text) in cases {
        let case = layout(&format!("sibling-hidden-root-{name}"));
        write(case.org.join("service-api").join(path), text);
        let cwd = case.org.join("app-portal");
        assert_decision(
            &cwd,
            &case.home,
            "rg -n fixture ../service-api/.github",
            false,
        );
    }
}
