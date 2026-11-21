//! A checkout keeps its own dotfiles: a generated `tsconfig` check, a local
//! ledger, a lint baseline. Reading one is ordinary work in the repository
//! the agent is already in, while a tool's own login, an environment file and
//! anything named for a credential keep their review.

use crate::pretool_home_layout_reads::{assert_decision, layout, repository};

#[test]
fn reading_a_project_dotfile_in_a_checkout_is_allowed() {
    let layout = layout("project-dotfile");
    let sibling = layout.org.join("service-api");
    let cwd = layout.org.join("app-portal");
    for (name, body) in [
        (".tsconfig-lb-check.json", "{\"strict\": true}\n"),
        (".local-ledger.md", "# ledger\n"),
        (".release-notes.markdown", "# notes\n"),
        (".lint-baseline.yaml", "rules: []\n"),
        (".build.toml", "[build]\n"),
        (".coverage-report.txt", "100%\n"),
    ] {
        std::fs::write(sibling.join(name), body).unwrap();
    }
    for command in [
        "cat ../service-api/.tsconfig-lb-check.json",
        "tail -8 ../service-api/.local-ledger.md",
        "head -3 ../service-api/.release-notes.markdown",
        "cat ../service-api/.lint-baseline.yaml",
        "cat ../service-api/.build.toml ../service-api/.coverage-report.txt",
        "cat ~/Code/org/service-api/.local-ledger.md",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn reading_a_login_environment_or_credential_dotfile_is_reviewed() {
    let layout = layout("project-dotfile-negative");
    let sibling = layout.org.join("service-api");
    for (name, body) in [
        // A harness keeps its own login in a file shaped like any other.
        (".mcp.json", "{\"servers\": {}}\n"),
        (".claude.json", "{}\n"),
        (".codex-auth.json", "{}\n"),
        // An environment file is named for what it holds wherever it sits.
        (".env.staging", "TOKEN=fixture\n"),
        (".service-secrets.yaml", "token: fixture\n"),
        (".deploy-credentials.json", "{}\n"),
        // No document extension: the shape a store of logins has.
        (".npmrc", "//registry:_authToken=fixture\n"),
        (".netrc", "machine example login fixture\n"),
        // A credential name keeps its review when the leading dot hides it.
        (".private-key.txt", "fixture\n"),
        (".id_rsa.txt", "fixture\n"),
        (".id_ed25519.json", "{}\n"),
        (".passwords.json", "{}\n"),
        (".aws-config.json", "{}\n"),
    ] {
        std::fs::write(sibling.join(name), body).unwrap();
    }
    let cwd = layout.org.join("app-portal");
    for name in [
        ".mcp.json",
        ".claude.json",
        ".codex-auth.json",
        ".env.staging",
        ".service-secrets.yaml",
        ".deploy-credentials.json",
        ".npmrc",
        ".netrc",
        ".private-key.txt",
        ".id_rsa.txt",
        ".id_ed25519.json",
        ".passwords.json",
        ".aws-config.json",
    ] {
        assert_decision(
            &cwd,
            &layout.home,
            &format!("cat ../service-api/{name}"),
            false,
        );
    }
    // A hidden directory on the way down is a store of its own, whatever the
    // file at the end is called.
    let hidden = sibling.join(".private/notes.md");
    std::fs::create_dir_all(hidden.parent().unwrap()).unwrap();
    std::fs::write(&hidden, "# notes\n").unwrap();
    assert_decision(
        &cwd,
        &layout.home,
        "cat ../service-api/.private/notes.md",
        false,
    );
}

#[test]
fn a_dotfiles_repository_in_the_home_directory_keeps_its_review() {
    let layout = layout("project-dotfile-home");
    repository(&layout.home);
    std::fs::write(layout.home.join(".shell-aliases.toml"), "[alias]\n").unwrap();
    let cwd = layout.org.join("app-portal");
    assert_decision(&cwd, &layout.home, "cat ~/.shell-aliases.toml", false);
}

/// A loose dotfile is no project's document, and a repository the home
/// directory itself sits in does not make it one: the work tree a dotfile
/// reads under has to be one of the home directory's own.
#[test]
fn a_project_dotfile_outside_a_checkout_keeps_its_review() {
    let layout = layout("project-dotfile-loose");
    let loose = layout.home.join("notes");
    std::fs::create_dir_all(&loose).unwrap();
    std::fs::write(loose.join(".scratch-ledger.md"), "# ledger\n").unwrap();
    let cwd = layout.org.join("app-portal");
    assert_decision(&cwd, &layout.home, "cat ~/notes/.scratch-ledger.md", false);
    std::fs::create_dir_all(layout.home.parent().unwrap().join(".git")).unwrap();
    assert_decision(&cwd, &layout.home, "cat ~/notes/.scratch-ledger.md", false);
}
