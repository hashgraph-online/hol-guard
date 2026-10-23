#[test]
fn a_leaf_glob_lists_hidden_names_in_a_listable_directory_only() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/listing-leaf-glob")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let project = home.join("work/project");
    let run = home.join("work/run");
    for directory in [
        project.join("src"),
        run.join(".cache-x"),
        run.join("data"),
        home.join(".ssh"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    for file in [
        run.join(".s.PGSQL.5432.lock"),
        run.join(".env"),
        run.join("data/notes.txt"),
        home.join(".ssh/id_rsa"),
    ] {
        std::fs::write(file, "synthetic\n").unwrap();
    }
    let (home, project) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&project).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: project.to_str(),
        ..Default::default()
    };
    let w = home.join("work").display().to_string();
    let h = home.display().to_string();
    for (command, allowed) in [
        (format!("ls {w}/run/.s.PGSQL*"), true),
        (
            format!("ls -la {w}/run/.s.PGSQL* {w}/run/.s.MISSING*"),
            true,
        ),
        (format!("ls {w}/run/d*"), true),
        (format!("ls -R {w}/run/.s.PGSQL*"), false),
        (format!("ls {w}/run/.c*"), false),
        (format!("ls {w}/run/.e*"), false),
        (format!("ls {w}/run/.*"), false),
        (format!("ls {w}/*/.s.PGSQL*"), false),
        (format!("ls {h}/.ssh/*"), false),
        (format!("ls {h}/.ssh/id*"), false),
    ] {
        let words: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_listing_segment(&command, &words[1..], context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// `ls -R` prints no hidden name and descends into no hidden directory, so
/// a repository's `.git` is not part of its output and must not decide the
/// proof. `-a`, `-A` and `-f` ask for those names and restore the screen.
/// A visible key file is refused either way.
#[test]
fn a_recursive_listing_screens_what_it_can_print() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/listing-recursive-hidden")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let project = home.join("work/project");
    let keyed = home.join("work/keyed");
    for directory in [
        project.join("src"),
        project.join(".git/refs"),
        keyed.join("certs"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    for file in [
        project.join("src/app.ts"),
        project.join(".git/config"),
        project.join(".env"),
        keyed.join("certs/service.pem"),
    ] {
        std::fs::write(file, "synthetic\n").unwrap();
    }
    let (home, project) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&project).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: project.to_str(),
        ..Default::default()
    };
    let keyed = home.join("work/keyed").display().to_string();
    for (command, allowed) in [
        ("ls -R .".to_owned(), true),
        ("ls -R".to_owned(), true),
        ("ls -R src".to_owned(), true),
        ("ls -aR .".to_owned(), false),
        ("ls -R -A .".to_owned(), false),
        ("ls -R --all .".to_owned(), false),
        ("ls -Rf .".to_owned(), false),
        ("ls -fR .".to_owned(), false),
        (format!("ls -R {keyed}"), false),
    ] {
        let words: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_listing_segment(&command, &words[1..], context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
