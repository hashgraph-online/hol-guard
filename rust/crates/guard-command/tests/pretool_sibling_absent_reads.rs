//! Reads that name a file inside a repository beside the session's own, where
//! the name is not there yet. `grep` and `rg` already open such a name
//! through the sibling screen, and a reader that prints the file reads no
//! more than they do: `cat ../service-api/package.json` in a repository that
//! turns out to use another manifest prints an error and asks for nothing.
//! Hidden components, credential names and Git's own directory keep their
//! review whether or not the path exists.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn absent_names_inside_a_sibling_repository_are_read_without_review() {
    let layout = layout("sibling-absent-reads");
    let cwd = layout.org.join("app-portal");
    write(layout.org.join("service-api/README.md"), "# fixture\n");
    let sibling = layout.org.join("service-api").display().to_string();
    for command in [
        format!("cat {sibling}/package.json"),
        format!("head -20 {sibling}/package.json"),
        format!("tail -5 {sibling}/CHANGELOG.md"),
        format!("wc -l {sibling}/src/server.ts"),
        format!("sed -n '1,40p' {sibling}/docs/setup.md"),
        "cat ~/Code/org/service-api/package.json".to_owned(),
        // The same files named with a parent step, the spelling an agent
        // working in the checkout beside them reaches for first.
        "cat ../service-api/package.json".to_owned(),
        "head -20 ../service-api/src/server.ts".to_owned(),
        "sed -n '1,40p' ../service-api/docs/setup.md".to_owned(),
        "cat ./../service-api/package.json".to_owned(),
        // The names that are there read as they already did.
        format!("cat {sibling}/README.md"),
        format!("head -20 {sibling}/src/main.rs"),
        "cat ../service-api/README.md".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, true);
    }
}

#[test]
fn hidden_credential_and_git_names_stay_reviewed() {
    let layout = layout("sibling-absent-reads-negative");
    let cwd = layout.org.join("app-portal");
    let sibling = layout.org.join("service-api");
    write(sibling.join(".env"), "TOKEN=fixture\n");
    write(sibling.join("config/credentials.txt"), "TOKEN=fixture\n");
    write(layout.home.join(".ssh/id_rsa"), "not-a-real-key\n");
    let sibling = sibling.display().to_string();
    for command in [
        format!("cat {sibling}/.env"),
        // Absent hidden names are screened as the present ones are.
        format!("cat {sibling}/.env.local"),
        format!("head -5 {sibling}/.git/config"),
        format!("cat {sibling}/config/credentials.txt"),
        format!("wc -l {sibling}/config/credentials.json"),
        "cat ~/.ssh/id_rsa".to_owned(),
        // A parent step keeps every screen the full spelling has.
        "cat ../service-api/.env".to_owned(),
        "cat ../service-api/.env.local".to_owned(),
        "head -5 ../service-api/.git/config".to_owned(),
        "cat ../service-api/config/credentials.txt".to_owned(),
        // A parent step that climbs out of the sibling set reaches no
        // repository root below home, so it is reviewed as before.
        "cat ../../../.ssh/id_rsa".to_owned(),
        "cat ../../../.ssh/id_ed25519".to_owned(),
    ] {
        assert_decision(&cwd, &layout.home, &command, false);
    }
}
