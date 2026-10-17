//! `test -f <path>` and `[ -f <path> ]` ask one bit about a path: a script
//! branches on whether the file it needs is there. The answer carries no
//! content, so the question survives both a name that reads like a
//! credential's and a target that does not exist yet, while the directories
//! a secret is actually kept in keep their review.

use crate::pretool_home_layout_reads::{assert_decision, layout};

#[test]
fn a_metadata_predicate_answers_for_a_credential_named_file() {
    let layout = layout("predicate-credential-name");
    let (home, org) = (&layout.home, &layout.org);
    let service = org.join("service-api");
    std::fs::write(org.join("kubeconfig.digitalocean"), "clusters: []\n").unwrap();
    std::fs::write(service.join("deploy-kubeconfig.yaml"), "clusters: []\n").unwrap();
    let cwd = org.join("app-portal");
    for command in [
        format!(
            "test -f {}/kubeconfig.digitalocean && echo VISIBLE",
            org.display()
        ),
        format!("[ -f {}/kubeconfig.digitalocean ]", org.display()),
        format!("test -s {}/deploy-kubeconfig.yaml", service.display()),
        format!("test -r {}/kubeconfig.digitalocean", org.display()),
    ] {
        assert_decision(&cwd, home, &command, true);
    }
}

#[test]
fn a_metadata_predicate_answers_for_a_path_that_is_not_there() {
    let layout = layout("predicate-missing");
    let (home, org) = (&layout.home, &layout.org);
    let service = org.join("service-api");
    let cwd = org.join("app-portal");
    for command in [
        format!("test -f {}/dist/bundle.js && echo built", service.display()),
        format!("test -d {}/dist", service.display()),
        "test -f ../service-api/dist/bundle.js".to_owned(),
        format!("[ -e {}/target/release/app ]", service.display()),
    ] {
        assert_decision(&cwd, home, &command, true);
    }
}

#[test]
fn a_predicate_on_a_credential_store_keeps_its_review() {
    let layout = layout("predicate-stores");
    let (home, org) = (&layout.home, &layout.org);
    let service = org.join("service-api");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join(".config/gh")).unwrap();
    std::fs::write(home.join(".ssh/id_rsa"), "synthetic\n").unwrap();
    std::fs::write(home.join(".ssh/known_hosts"), "synthetic\n").unwrap();
    std::fs::write(home.join(".config/gh/hosts.yml"), "synthetic\n").unwrap();
    std::fs::write(service.join(".env"), "TOKEN=synthetic\n").unwrap();
    let cwd = org.join("app-portal");
    for command in [
        "test -f ~/.ssh/id_rsa && echo VISIBLE".to_owned(),
        "test -f ~/.ssh/known_hosts".to_owned(),
        // Absent below a store: the answer would map the store's contents.
        "test -f ~/.ssh/id_ed25519".to_owned(),
        "test -f ~/.config/gh/hosts.yml".to_owned(),
        format!("test -s {}/.env", service.display()),
        // A missing hidden name is where a tool keeps its own login.
        format!("test -f {}/.aws-session", service.display()),
    ] {
        assert_decision(&cwd, home, &command, false);
    }
}
