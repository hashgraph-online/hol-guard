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
