//! A configuration line this reads differently from Git hides an attributes
//! file the removal proof has to keep.

use super::{attribute_sources, config_entries, ConfigEntry, SourceRoots};
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/removal-git-sources")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::create_dir_all(root.join("git")).unwrap();
    Scratch(std::fs::canonicalize(root).unwrap())
}

/// No system files and no user configuration directory, so only the
/// fixture's own files count.
fn isolated() -> SourceRoots {
    SourceRoots {
        system_configs: Vec::new(),
        system_attributes: Vec::new(),
        xdg: None,
    }
}

fn sources(scratch: &Scratch, roots: &SourceRoots) -> Option<Vec<PathBuf>> {
    attribute_sources(
        roots,
        Some(&scratch.0.join("home")),
        &[scratch.0.join("git")],
    )
}

fn values(text: &str, section: &str, key: &str) -> Vec<String> {
    config_entries(text)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.section == section && entry.key == key)
        .map(|entry| entry.value)
        .collect()
}

#[test]
fn configured_and_included_attributes_files_are_sources() {
    let scratch = scratch("sources");
    let home = scratch.0.join("home");
    std::fs::write(scratch.0.join("global.attrs"), "*.txt quiet\n").unwrap();
    std::fs::write(scratch.0.join("included.attrs"), "*.md quiet\n").unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\tattributesFile = ~/../global.attrs\n[include]\n\tpath = ../extra.conf\n",
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("extra.conf"),
        format!(
            "[core]\n\tattributesfile = \"{}\"\n",
            scratch.0.join("included.attrs").display()
        ),
    )
    .unwrap();
    let sources = sources(&scratch, &isolated()).unwrap();
    assert!(
        sources.contains(&scratch.0.join("global.attrs")),
        "{sources:?}"
    );
    assert!(
        sources.contains(&scratch.0.join("included.attrs")),
        "{sources:?}"
    );
}

#[test]
fn settings_git_reads_past_comments_headers_and_continuations_are_sources() {
    let scratch = scratch("syntax");
    for name in ["a.attrs", "b.attrs", "c.attrs", "d.attrs"] {
        std::fs::write(scratch.0.join(name), "*.txt quiet\n").unwrap();
    }
    let root = scratch.0.display();
    std::fs::write(
        scratch.0.join("git/config"),
        format!(
            "[core] attributesFile = {root}/a.attrs ; global\n\
             [include] path = {root}/more.conf # more\n"
        ),
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("more.conf"),
        format!(
            "[core]\n\tattributesFile = {root}/\\\n\
             b.attrs\n\
             [includeIf \"gitdir:/\"]\n\tpath = \"{root}/last.conf\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("last.conf"),
        format!("[CORE]\nattributesfile=\"{root}/c.attrs\"#x\n"),
    )
    .unwrap();
    let xdg = scratch.0.join("xdg");
    std::fs::create_dir_all(xdg.join("git")).unwrap();
    std::fs::write(
        xdg.join("git/config"),
        format!("[core]\n\tattributesFile = {root}/d.attrs\n"),
    )
    .unwrap();
    let roots = SourceRoots {
        xdg: Some(xdg),
        ..isolated()
    };
    let sources = sources(&scratch, &roots).unwrap();
    for name in ["a.attrs", "b.attrs", "c.attrs", "d.attrs"] {
        assert!(
            sources.contains(&scratch.0.join(name)),
            "{name}: {sources:?}"
        );
    }
}

#[test]
fn a_path_outside_an_include_section_is_not_followed() {
    let scratch = scratch("tool-path");
    // A tool too large to read as configuration: following it as an include
    // would leave the sources unknown.
    let tool = scratch.0.join("tool");
    std::fs::write(&tool, vec![b'x'; 1 << 20]).unwrap();
    std::fs::write(
        scratch.0.join("git/config"),
        format!(
            "[mergetool \"vimdiff\"]\n\tpath = {}\n[core]\n\tpath = relative-tool\n",
            tool.display()
        ),
    )
    .unwrap();
    assert!(sources(&scratch, &isolated()).is_some());
}

#[cfg(unix)]
#[test]
fn a_linked_info_attributes_file_is_its_target() {
    let scratch = scratch("linked");
    let git = scratch.0.join("git");
    std::fs::write(scratch.0.join("quiet.txt"), "*.txt quiet\n").unwrap();
    std::fs::create_dir(git.join("info")).unwrap();
    std::os::unix::fs::symlink(scratch.0.join("quiet.txt"), git.join("info/attributes")).unwrap();
    let sources = sources(&scratch, &isolated()).unwrap();
    assert!(
        sources.contains(&scratch.0.join("quiet.txt")),
        "{sources:?}"
    );
}

#[test]
fn an_attributes_path_that_cannot_be_placed_keeps_the_review() {
    for config in [
        "[core]\n\tattributesFile = attrs\n",
        "[core]\n\tattributesFile = ~other/attrs\n",
        "[include]\n\tpath = ~other/extra.conf\n",
        "[include]\n\tpath = %(prefix)/etc/extra.conf\n",
        // Syntax Git refuses.
        "[core]\n\tattributesFile = \"/tmp/unterminated\n",
        "[core]\n\tattributesFile = /tmp/\\q\n",
        "[core\n",
    ] {
        let scratch = scratch("unplaced");
        std::fs::write(scratch.0.join("git/config"), config).unwrap();
        assert_eq!(sources(&scratch, &isolated()), None, "{config:?}");
    }
}

#[test]
fn values_decode_the_way_git_reads_them() {
    assert_eq!(
        values(
            "[core]\n\tattributesFile = /a b ; c\n",
            "core",
            "attributesfile"
        ),
        ["/a b"]
    );
    assert_eq!(
        values(
            "[core]\n\tattributesFile = \"/a ;b\" # c\n",
            "core",
            "attributesfile"
        ),
        ["/a ;b"]
    );
    assert_eq!(
        values(
            "[core]attributesFile=\"/a\\\"b\\\\c\"\n",
            "core",
            "attributesfile"
        ),
        ["/a\"b\\c"]
    );
    assert_eq!(values("\u{feff}[core]\n\tbare\n", "core", "bare"), ["true"]);
    let entries =
        config_entries("[core \"x\"]\n\tattributesFile = /a\n[core.y]\n\tk = v\n").unwrap();
    assert_eq!(
        entries,
        [
            ConfigEntry {
                section: "core".into(),
                subsection: true,
                key: "attributesfile".into(),
                value: "/a".into(),
            },
            ConfigEntry {
                section: "core".into(),
                subsection: true,
                key: "k".into(),
                value: "v".into(),
            },
        ]
    );
}
