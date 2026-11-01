#[test]
fn a_missing_root_beside_real_ones_is_proven_but_not_a_sensitive_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-absent-roots")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
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
    let r = repo.display();
    let h = home.display();
    for (command, allowed) in [
        (format!("-rln x {r}/src {r}/lib"), true),
        (format!("-n x {r}/src/index.ts {r}/lib/index.ts"), true),
        ("-rn x src tests".to_owned(), true),
        (format!("-rln x {r}/src {h}/.ssh/missing"), false),
        (format!("-rln x {r}/src {r}/missing/.env"), false),
        (format!("-rln x {r}/src {r}/missing/id_rsa"), false),
        (format!("-n x {h}/.ssh/missing"), false),
        // A root that is not there opens nothing, on its own as much as
        // beside a real one. With no operand `-r` walks the cwd instead.
        (format!("-rln x {r}/missing"), true),
        ("-rln x lib".to_owned(), true),
        ("-rln x".to_owned(), false),
        (format!("-rln x {h}/.ssh/missing"), false),
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

#[test]
fn a_missing_operand_is_not_proven_beside_a_step_that_could_create_it() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-absent-chains")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("src")).unwrap();
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
    let r = repo.display();
    for (command, allowed) in [
        (format!("grep -rln x {r}/src {r}/cfg"), true),
        (format!("grep -rn x {r}/src {r}/cfg | head -5"), true),
        (format!("cd {r} && grep -rn x src cfg"), true),
        (
            format!("cat {r}/src/index.ts && grep -n x {r}/cfg/app.json"),
            true,
        ),
        (
            format!("ln -s {r}/src {r}/cfg && grep -rn . {r}/cfg/"),
            false,
        ),
        (
            format!("ln -s {r}/src {r}/cfg && grep -n x {r}/cfg/app.json"),
            false,
        ),
        (format!("mkdir -p {r}/cfg && grep -rn x {r}/cfg"), false),
        (format!("touch {r}/cfg && grep -n x {r}/cfg"), false),
        (format!("echo x > {r}/cfg; grep -n x {r}/cfg"), false),
        (format!("cat {r}/src/index.ts && grep -rn x {r}/cfg"), false),
        (format!("grep -rln x {r}/cfg"), true),
        (format!("mkdir -p {r}/cfg; grep -rln x {r}/cfg"), false),
        (format!("grep -rln x {r}/cfg; mkdir -p {r}/cfg"), false),
        // A branch that only prints puts nothing at the missing root, so the
        // probe shape agents write keeps the proof.
        (format!("grep -rln x {r}/cfg || echo none"), true),
        (format!("grep -rln x {r}/cfg || printf 'none\\n'"), true),
        (format!("grep -rln x {r}/cfg || touch {r}/cfg"), false),
        (format!("grep -rln x {r}/cfg || echo none > {r}/cfg"), false),
    ] {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.clone(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        // An output redirect leaves the model uncertain with no
        // segments, which no proof admits.
        let Some(segment) = model
            .segments
            .iter()
            .find(|segment| segment.executable.as_deref() == Some("grep"))
        else {
            assert!(!allowed, "{command}");
            continue;
        };
        assert_eq!(
            super::safe_grep_segment(&model, segment, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn stdin_proof_cannot_open_files_or_recurse() {
    for (arguments, allowed) in [
        (vec!["-n", "-e", "fixture"], true),
        (vec!["-efixt"], true),
        (vec!["--regexp=fixture"], true),
        (vec!["-f", "one.txt"], false),
        (vec!["-nfone.txt"], false),
        (vec!["--file=one.txt"], false),
        (vec!["fixture", "one.txt"], false),
        (vec!["-r", "fixture"], false),
        (vec!["--directories=recurse", "fixture"], false),
        (vec!["-e", "fixture", "-f", "one.txt"], false),
        (vec!["--", "fixture", "one.txt"], false),
        (vec![], false),
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
        assert_eq!(
            super::safe_stdin_arguments(&arguments),
            allowed,
            "{arguments:?}"
        );
    }
}

#[test]
fn a_plain_pattern_clears_the_sensitive_files_it_cannot_match() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-clearance")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    let held = home.join("work/held");
    let write = |base: &std::path::Path, relative: &str, text: &str| {
        let path = base.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(&repo, "src/index.ts", "export const handler = 1;\n");
    write(&repo, "workers/api/.dev.vars", "API_TOKEN=placeholder\n");
    write(&repo, ".env.bak", "COOKIE_NAME=synthetic\n");
    // A folder with files that are never read stays held, even at the root.
    write(&held, "src/index.ts", "export const handler = 1;\n");
    write(&held, "keys/server.key", "placeholder\n");
    write(&held, "stores/.aws/credentials", "placeholder\n");
    write(&held, "links/real.txt", "placeholder\n");
    // Creating a symlink on Windows needs a privilege the test cannot assume.
    #[cfg(unix)]
    std::os::unix::fs::symlink(held.join("links/real.txt"), held.join("links/.env.link")).unwrap();
    let (home, repo, held) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&held).unwrap(),
    );
    for (cwd, command, allowed) in [
        (&repo, "-rn handler .", true),
        (&repo, "-rn handler workers", true),
        (&repo, "-rni HANDLER workers", true),
        (&repo, "-rn foo|handler .", true),
        (&repo, "-rn -e handler .", true),
        (&repo, "-rn api_token workers", false),
        (&repo, "-rn API_TOKEN workers", false),
        (&repo, "-rn foo|cookie_name .", false),
        (&repo, "-rn cookie.name .", false),
        (&repo, "-rn ha.*er .", false),
        (&repo, "-rn ^handler .", false),
        (&repo, "-rn -ehandler .", false),
        (&repo, "-rn -e handler -e other .", false),
        (&repo, "-rnv handler .", false),
        (&repo, "-rnL handler .", false),
        (&repo, "-rn --invert-match handler .", false),
        (&repo, "-rnc handler .", false),
        (&repo, "-rn handler src", true),
        (&held, "-rn handler src", true),
        (&held, "-rn handler .", false),
        (&held, "-rn handler keys", false),
        (&held, "-rn handler stores", false),
        // Without the link this folder holds only an ordinary file.
        (&held, "-rn handler links", !cfg!(unix)),
    ] {
        let context = crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..Default::default()
        };
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_grep_arguments(&arguments, context),
            allowed,
            "{command} in {}",
            cwd.display()
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A stdin filter's pattern is the text it matches, not a path, but the shell
/// expands the word before the filter ever sees it. `grep -v .env{,.local}`
/// leaves `.env` as the pattern and `.env.local` as an operand `grep` then
/// opens, so the word is not matching text and the stdin proof refuses it.
#[test]
fn an_expandable_pattern_is_not_proven_stdin_text() {
    for (command, proven) in [
        ("-v .env", true),
        ("-v .git", true),
        ("-i secret", true),
        ("-E ^[a-z]+[0-9]{2}$", true),
        ("-i auth.*provider", true),
        ("token.*expired", true),
        ("-i credentials.*", false),
        ("secrets.*", false),
        ("-i token.?", false),
        ("-v .env{,.local}", false),
        ("-v .env*", false),
        ("-v .en{v..v}", false),
        ("-e .env{,.local}", false),
        (".ssh/*", false),
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_stdin_arguments(&arguments),
            proven,
            "grep {command}"
        );
    }
}

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
        // `grep` matches a glob holding a separator against the whole name
        // it reached the file by, which this walk does not render.
        ("-rn x --include docs/*.md .".to_owned(), false),
        // An include and an exclude together are still unread: their
        // precedence differs across implementations.
        (
            "-rn x --include *.md --exclude notes.md docs".to_owned(),
            false,
        ),
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
        assert!(super::safe_stdin_arguments(&arguments), "{command}");
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
