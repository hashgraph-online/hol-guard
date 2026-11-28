//! A `grep -r` root spelled through `..`, such as `../../tests` from a folder
//! deeper in the same checkout, is the tree `grep -rn pat tests` searches
//! from the checkout root. A sensitive file the pattern cannot match
//! prints nothing in either spelling, so it must not hold only the first.

#[test]
fn a_parent_spelled_root_clears_the_sensitive_files_its_pattern_cannot_match() {
    // Below the build tree, not the system temp folder, whose prefix the
    // location screen treats on its own.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-parent-root")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work").join("app");
    let write = |relative: &str, text: &str| {
        let path = repo.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    write("rust/crates/engine/src/lib.rs", "pub fn handler() {}\n");
    write("tests/test_handler.py", "def test_handler():\n    pass\n");
    write("tests/fixtures/.env.test", "COOKIE_NAME=synthetic\n");
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let crates = repo.join("rust").join("crates");
    for (cwd, command, allowed) in [
        (&repo, "-rln handler tests", true),
        (&crates, "-rln handler ../../tests", true),
        (&crates, "-rn handler ../../tests", true),
        // The pattern can match the sensitive file's contents, or its absence
        // from that file is what prints.
        (&repo, "-rln cookie_name tests", false),
        (&crates, "-rln cookie_name ../../tests", false),
        (&crates, "-rnL handler ../../tests", false),
        (&crates, "-rnv handler ../../tests", false),
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
