//! What a hidden directory's own configuration document is read as. The
//! stems these files share with a credential store are settled by reading
//! the document itself, so the cases that answer for that reading live here.

use super::*;

#[test]
fn a_hidden_directorys_configuration_document_reads_when_it_holds_no_credential() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    // `config`, `configuration` and `settings` name a credential store as
    // often as they name an ordinary project document, so the name alone used
    // to hold every one of these back while `cat` of the same bytes ran
    // contained.
    for document in [
        ".circleci/config.yml",
        ".changeset/config.json",
        ".cargo/config.toml",
        ".storybook/settings.json",
        ".husky/configuration.json",
    ] {
        plant(&repo.join(document), "[build]\njobs = 4\n");
        assert!(read(&repo.join(document), &home, &repo), "{document}");
    }
    // The same name over a credential keeps its review: the document is read
    // against the detector, not waved past on its extension.
    let token = format!("{}{}{}", "AKIA", "QYLPT3K7", "R4FXM2WD");
    plant(
        &repo.join(".cargo/config.toml"),
        &format!("[registries.internal]\ntoken = \"{token}\"\n"),
    );
    assert!(!read(&repo.join(".cargo/config.toml"), &home, &repo));
    // A credential store's own directory is untouched by this: the parent
    // answers before the leaf is read at all.
    for document in [
        ".aws/config.json",
        ".ssh/config.toml",
        ".vscode/settings.json",
    ] {
        plant(&repo.join(document), "{}\n");
        assert!(!read(&repo.join(document), &home, &repo), "{document}");
    }
    // And a name that holds material rather than describing a job stays held
    // however clean the bytes are.
    for document in [".github/credentials.json", ".github/keys.json"] {
        plant(&repo.join(document), "{}\n");
        assert!(!read(&repo.join(document), &home, &repo), "{document}");
    }
    // A credential short enough to have no shape the detector recognises is
    // still written under a word that names it, so the word holds the review.
    for body in [
        "database:\n  password: hunter2\n",
        "[registry]\napi_key = \"abc123\"\n",
        "passphrase: letmein\n",
        // The word carries the answer wherever it sits in the key, not only
        // at its end.
        "secret_key: abc123\n",
        "aws_secret_access_key = \"abc\"\n",
        // A line can hold more than one pair: an inline table, a flow
        // mapping, a document written on one line.
        "[registries]\ninternal = { token = \"abc123\" }\n",
        "{\"db\": {\"password\": \"hunter2\"}}\n",
        // A literal often carries a `$` or a brace of its own, which names a
        // credential like any other character does.
        "database:\n  password: hunter$2\n",
        "[registry]\ntoken = \"ab$cd\"\n",
        // A mapping may leave its value for the next line, indented deeper.
        // That line carries no key of its own, so the key above answers for
        // it, quoted or bare.
        "database:\n  password:\n    hunter2\n",
        "database:\n  password:\n    \"hunter2\"\n",
        "database:\n  password:\n\n    # chosen by the team\n    hunter2\n",
        // YAML asks for a space after the colon of a mapping, so a value
        // holding a bare colon is a scalar rather than a key of its own.
        "database:\n  password:\n    hunter:2\n",
    ] {
        plant(&repo.join(".circleci/config.yml"), body);
        assert!(
            !read(&repo.join(".circleci/config.yml"), &home, &repo),
            "{body}"
        );
    }
    // A value the CI system fills in later names no credential of its own.
    for body in [
        "deploy:\n  token: ${{ secrets.NPM_TOKEN }}\n",
        "[registry]\ntoken = \"$CARGO_REGISTRY_TOKEN\"\n",
        "deploy:\n  token: ${REGISTRY_TOKEN}\n",
        "[registry]\ntoken = \"{{ registry_token }}\"\n",
        "password:\n",
        // A deeper line that is a mapping of its own is not the value the
        // key above left empty, and a line at the same depth is the next
        // key rather than a continuation.
        "database:\n  password:\n    name: bob\n",
        "database:\n  password:\n  username: bob\n",
    ] {
        plant(&repo.join(".circleci/config.yml"), body);
        assert!(
            read(&repo.join(".circleci/config.yml"), &home, &repo),
            "{body}"
        );
    }
    // A literal written right after a placeholder is still a literal: the
    // hole has to be the whole value, so the sentinel it masks to cannot run
    // into the characters beside it. A bare `$NAME` is the exception the
    // shell itself makes — the letters after it belong to the name.
    for body in [
        "deploy:\n  token: ${{ secrets.NPM_TOKEN }}abc123\n",
        "deploy:\n  token: ${REGISTRY_TOKEN}hunter2\n",
        "[registry]\ntoken = \"{{ registry_token }}hunter2\"\n",
    ] {
        plant(&repo.join(".circleci/config.yml"), body);
        assert!(
            !read(&repo.join(".circleci/config.yml"), &home, &repo),
            "{body}"
        );
    }
    // A value written across several lines keeps its credential off the line
    // that names it, and the scan reads a line at a time, so the opener
    // answers for the whole literal.
    for body in [
        "[registries.internal]\ntoken = \"\"\"\nhunter2\n\"\"\"\n",
        "[registry]\npassword = '''\nletmein\n'''\n",
    ] {
        plant(&repo.join(".cargo/config.toml"), body);
        assert!(
            !read(&repo.join(".cargo/config.toml"), &home, &repo),
            "{body}"
        );
    }
    // The words a document writes for "nothing here" say that only while they
    // are bare. Quoted, each is a literal of its own, and a four-character
    // password has no shape for the detector to recognise.
    for body in [
        "{\"db\": {\"password\": \"null\"}}\n",
        "[registry]\ntoken = \"true\"\n",
    ] {
        plant(&repo.join(".circleci/config.yml"), body);
        assert!(
            !read(&repo.join(".circleci/config.yml"), &home, &repo),
            "{body}"
        );
    }
    // Bare, they hold nothing, and the document reads.
    for body in [
        "database:\n  password: null\n",
        "[registry]\ntoken = false\n",
    ] {
        plant(&repo.join(".circleci/config.yml"), body);
        assert!(
            read(&repo.join(".circleci/config.yml"), &home, &repo),
            "{body}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_configuration_line_of_unclosed_placeholders_answers_at_once() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    // A placeholder opener that never closes used to be searched for its
    // closing delimiter again at every opener after it, so one long line cost
    // the square of its length and held the read up for half a minute. The
    // line below is as long as the rule will read, and the answer it gives is
    // unchanged: the value is a literal, so the document keeps its review.
    let line = format!("token = {}\n", "${".repeat(127_000));
    plant(&repo.join(".cargo/config.toml"), &line);
    let started = std::time::Instant::now();
    assert!(!read(&repo.join(".cargo/config.toml"), &home, &repo));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a single line took {:?}",
        started.elapsed()
    );
    std::fs::remove_dir_all(root).unwrap();
}
