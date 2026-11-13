//! How `--include`, `--exclude` and `--exclude-dir` decide what a `grep`
//! search can open.

/// A wildcard `--include` narrows what `grep` opens, so the files it selects
/// below the searched directory decide the reading. Before this, every glob
/// the name screen could not clear ended the proof, and `--include '*.md'`
/// kept a review for a search that cannot open anything but Markdown.
#[test]
fn a_wildcard_include_is_proven_by_what_it_selects_below_the_root() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-include-scope")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(repo.join("docs/notes.md"), "# notes\n").unwrap();
    std::fs::write(repo.join("docs/README.md"), "# readme\n").unwrap();
    std::fs::write(repo.join("src/index.ts"), "export const x = 1;\n").unwrap();
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    let h = home.display();
    for (command, allowed) in [
        ("-rn x --include *.md docs".to_owned(), true),
        ("-rn x --include=*.md docs".to_owned(), true),
        ("-rn x --include *.md --include *.mdx docs".to_owned(), true),
        // BSD grep matches an include against the whole path as well as
        // the name, but `README` is not how a path below `docs` begins, so
        // only the name match is left and both greps answer alike.
        ("-rn x --include README* docs".to_owned(), true),
        ("-rn x --include *.md docs src".to_owned(), true),
        // A literal name never reached this proof and still passes the
        // name screen on its own.
        ("-rn x --include README.md docs".to_owned(), true),
        // A root spelled from the home is the directory the shell expands
        // it to, and the include is proven below that directory.
        ("-rn x --include *.md ~/work/app/docs".to_owned(), true),
        ("-rln x ~/work/app/docs --include=*.md".to_owned(), true),
        ("-rn x --include *.md ~/.ssh".to_owned(), false),
        ("-rn x --include *.md ~".to_owned(), false),
        ("-rn x --include *.md ~root/docs".to_owned(), false),
        // `grep` matches a glob holding a separator against the whole name
        // it reached the file by, which this walk does not render.
        ("-rn x --include docs/*.md .".to_owned(), false),
        // An include and an exclude together are still unread: their
        // precedence differs across implementations.
        (
            "-rn x --include *.md --exclude notes.md docs".to_owned(),
            false,
        ),
        // GNU grep reads a file matching neither list once an exclude comes
        // first, so a wildcard exclude widens the include too.
        (
            "-rn x --exclude *.min.js --include *.md docs".to_owned(),
            false,
        ),
        (
            "-rn x --exclude=*.min.js --include=*.md docs".to_owned(),
            false,
        ),
        // A value the shell expands can split into extra operands.
        ("-rn x --exclude-dir=$X docs".to_owned(), false),
        ("-rn x --exclude-dir $X docs".to_owned(), false),
        ("-rn x --exclude=`pick` docs".to_owned(), false),
        // The root decides as it always did.
        (format!("-rn x --include *.md {h}/.ssh"), false),
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_grep_arguments(&arguments, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A `grep` with no operand opens nothing an include could select: it reads
/// the pipe it was handed. Proving a glob against the working directory there
/// let a file the search never opens decide a filter's reading.
#[test]
fn an_include_without_an_operand_is_read_against_the_pipe() {
    for command in [
        "--include=*.md review",
        "--include *.md review",
        "-n --include=*.md review",
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert!(super::safe_stdin_arguments(&arguments, &[]), "{command}");
        assert!(
            super::safe_grep_arguments(&arguments, crate::pretool::PathContext::default()),
            "{command}"
        );
    }
}

/// The include decides the recursive walk too. `grep -rn KEY --include '*.md'
/// docs` opens no file but Markdown, so a secret the globs never select
/// cannot be printed. Before this, the walk below the root knew nothing of
/// the include and refused the search for any sensitive file it reached.
#[test]
fn an_include_narrows_the_recursive_walk_below_the_root() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-include-walk")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::create_dir_all(repo.join("deploy/secrets")).unwrap();
    std::fs::write(repo.join("docs/notes.md"), "# notes\n").unwrap();
    std::fs::write(repo.join("docs/.env"), "TOKEN=value\n").unwrap();
    std::fs::write(repo.join("docs/credentials.json"), "{}\n").unwrap();
    std::fs::write(repo.join("README.md"), "# app\n").unwrap();
    std::fs::write(repo.join("deploy/deploy.md"), "# deploy\n").unwrap();
    std::fs::write(repo.join("deploy/secrets/id_rsa"), "key\n").unwrap();
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    for (command, allowed) in [
        ("-rn KEY --include *.md docs".to_owned(), true),
        ("-rn KEY --include=*.md docs".to_owned(), true),
        // A secret in a directory below the root is as unselected as one
        // beside it.
        ("-rn KEY --include *.md .".to_owned(), true),
        ("-rn KEY --include *.md deploy".to_owned(), true),
        // Every glob on the line opens files, including one the name screen
        // cleared on its own, so all of them decide the walk. `*.json` is a
        // glob that screen passes, and it still selects the credential store
        // beside the Markdown, which no commit here records as ordinary.
        (
            "-rn KEY --include *.md --include *.json docs".to_owned(),
            false,
        ),
        (
            "-rn KEY --include *.md --include .env docs".to_owned(),
            false,
        ),
        ("-rn KEY --include * docs".to_owned(), false),
        // macOS `grep` matches `deploy*` against `deploy/secrets/id_rsa`
        // too, which the name this walk renders never matches. The glob is
        // only free to cross the separator because the operand it runs over
        // is spelled the way its literal head begins.
        ("-rn KEY --include deploy* deploy".to_owned(), false),
        // The same glob over a root it cannot spell matches no path at all,
        // so the name match is the whole of it and nothing below `docs` is
        // selected.
        ("-rn KEY --include deploy* docs".to_owned(), true),
        ("-rn KEY --include README* .".to_owned(), true),
        // `[[:punct:]]` is one character class to `grep` and an ordinary
        // set of bytes to this matcher, so the search opens `docs/.env`
        // while the model reads the glob as a five-byte name nothing here
        // carries.
        ("-rn KEY --include [[:punct:]]env docs".to_owned(), false),
        // `?` consumes one byte here and one character in `grep`, so a name
        // whose first character is multi-byte is modeled as unselected while
        // the search opens it. Every `?` inclusion is left unmodeled.
        ("-rn KEY --include ?.env docs".to_owned(), false),
        // Without an include the walk reads whatever it reaches.
        ("-rn KEY docs".to_owned(), false),
        // `-R` follows the links this walk steps over, so it cannot stand
        // for what that search opens.
        ("-Rn KEY --include *.md docs".to_owned(), false),
        (
            "--dereference-recursive -n KEY --include *.md docs".to_owned(),
            false,
        ),
        // A glob holding a separator is matched against a name this walk
        // does not render.
        ("-rn KEY --include docs/*.md .".to_owned(), false),
        // `fnmatch` has no brace expansion, so `grep` selects the one file
        // whose name is spelled with the braces while the filter would stand
        // for the two suffixes around them.
        ("-rn KEY --include *.{md,rs} docs".to_owned(), false),
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_grep_arguments(&arguments, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// `--exclude-dir` skips a directory whatever the includes say: GNU and BSD
/// grep match an include against files, never against a directory, so the
/// walk does not go back into one. The proof dropped every exclusion once an
/// include appeared, and `grep -rln --include='*.ts' --exclude-dir=fixtures
/// KEY tests` stayed under review while the same search without the include
/// passed. A file exclusion keeps the review wherever it stands: a later
/// include can re-enable the file it names, and when an `--exclude` comes
/// first GNU grep opens every file neither glob matches.
#[test]
fn a_directory_exclusion_holds_beside_an_include() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-include-exclude-dir")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("tests/fixtures")).unwrap();
    std::fs::create_dir_all(repo.join("lib")).unwrap();
    std::fs::write(repo.join("tests/app.test.ts"), "export {};\n").unwrap();
    std::fs::write(repo.join("tests/fixtures/server.key"), "key\n").unwrap();
    std::fs::write(repo.join("tests/fixtures/token.ts"), "export {};\n").unwrap();
    std::fs::write(
        repo.join("tests/fixtures/.env.ts"),
        "export const KEY = 1;\n",
    )
    .unwrap();
    std::fs::write(repo.join("lib/index.ts"), "export {};\n").unwrap();
    std::fs::write(repo.join("lib/.env"), "KEY=value\n").unwrap();
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    for (command, allowed) in [
        ("-rln --exclude-dir=fixtures KEY tests", true),
        // `*.ts` selects `fixtures/.env.ts`, so only the directory exclusion
        // clears the walk.
        ("-rln --include=*.ts KEY tests", false),
        ("-rln --include=*.ts --exclude-dir=fixtures KEY tests", true),
        ("-rln --exclude-dir=fixtures --include=*.ts KEY tests", true),
        ("-rln --include *.ts --exclude-dir fixtures KEY tests", true),
        // A file exclusion does not stand in for one: a later include can
        // re-enable the file it names.
        ("-rln --include=*.ts --exclude=.env.ts KEY tests", false),
        // An `--exclude` before the include makes GNU grep open `lib/.env`,
        // which neither glob matches.
        ("-rln --exclude=*.md --include=*.ts KEY lib", false),
        ("-rln --exclude=.env --include=*.ts KEY lib", false),
        ("-rln --include=*.ts --exclude=*.md KEY lib", false),
        (
            "-rln --exclude-dir=fixtures --include=*.ts --exclude=*.md KEY lib",
            false,
        ),
        // A directory exclusion alone leaves the include narrowing the walk.
        ("-rln --include=*.ts --exclude-dir=fixtures KEY lib", true),
        // Without any include the walk reads whatever it reaches.
        ("-rln KEY tests", false),
        ("-rln KEY lib", false),
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_grep_arguments(&arguments, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
