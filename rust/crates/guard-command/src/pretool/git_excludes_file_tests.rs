use super::names_an_ignore_list;
use std::path::Path;

fn home() -> &'static Path {
    Path::new(if cfg!(windows) {
        r"C:\Users\fixture"
    } else {
        "/home/fixture"
    })
}

#[test]
fn the_repository_exclude_file_and_home_ignore_lists_are_ignore_lists() {
    for value in [
        ".git/info/exclude",
        "~/.gitignore",
        "~/.gitignore_global",
        "~/.config/git/ignore",
        "~/./.gitignore_global",
    ] {
        assert!(names_an_ignore_list(value, home()), "{value}");
    }
    let absolute = home().join(".gitignore_global");
    assert!(names_an_ignore_list(absolute.to_str().unwrap(), home()));
}

#[test]
fn any_other_file_keeps_the_review() {
    let outside = home().join(".ssh").join("id_ed25519");
    for value in [
        "~/.ssh/id_ed25519",
        "~/.aws/credentials",
        "~/.config/git/credentials",
        "~/../other/.gitignore",
        "~other/.gitignore",
        ".git/config",
        "../.git/info/exclude",
        "./.git/info/exclude/../../config",
        "notes/.gitignore",
        "/etc/gitignore",
        outside.to_str().unwrap(),
    ] {
        assert!(!names_an_ignore_list(value, home()), "{value}");
    }
}
