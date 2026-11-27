//! An `rg` root that is a glob matching nothing reads nothing: bash hands
//! `rg` the literal word, which names no file, and zsh's `nomatch` fails the
//! command. Agents probe for an optional file this way, and a step after a
//! `cd` that may not have happened searches the starting folder, where the
//! glob usually matches nothing.

use super::rg::safe_rg_segment;

fn decide(command: &str, context: super::ReadContext<'_>) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    model
        .segments
        .iter()
        .filter(|segment| segment.executable.as_deref() == Some("rg"))
        .all(|segment| safe_rg_segment(&model, segment, context))
}

#[test]
fn a_root_glob_that_matches_nothing_reads_nothing() {
    // A hidden component anywhere in the path fails the read screens, and
    // `tempfile`'s default prefix is `.tmp`, so the fixture names its root.
    let root = tempfile::Builder::new()
        .prefix("guard-rg-unmatched")
        .tempdir()
        .unwrap();
    let home = std::fs::canonicalize(root.path()).unwrap();
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(repo.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(repo.join("lib.rs"), "pub fn run() {}\n").unwrap();
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ripgrep_config_absent: true,
        gem_config_absent: true,
        ..Default::default()
    };
    let r = repo.display();
    for (command, allowed) in [
        ("rg -ln run lib.rs".to_owned(), true),
        // No `handlers_*.rs` here: the search prints an error and exits,
        // alone, beside a real root, or with a relative spelling.
        ("rg -ln run handlers_*.rs".to_owned(), true),
        ("rg -ln run src handlers_*.rs".to_owned(), true),
        (format!("rg -ln run {r}/handlers_*.rs"), true),
        ("rg -ln run src/*_test.rs | head".to_owned(), true),
        // A step that could create a match first takes the proof away.
        (
            "touch handlers_a.rs && rg -ln run handlers_*.rs".to_owned(),
            false,
        ),
        (
            "rg -ln run handlers_*.rs; touch handlers_a.rs".to_owned(),
            false,
        ),
        // An unquoted bracket class is not a `*` or `?` glob this proof reads.
        ("rg -ln run handlers_[ab]*.rs".to_owned(), false),
        // A glob that could select a credential name keeps its review even
        // when it matches nothing.
        ("rg -n run auth.*provider".to_owned(), false),
        ("rg -n run src secrets_*.json".to_owned(), false),
    ] {
        assert_eq!(decide(&command, context), allowed, "{command}");
    }

    // Under `nullglob` every unmatched root disappears and `rg` walks the
    // working directory, so that walk has to be proven too. A folder whose
    // `.ignore` re-includes `.env` is not.
    let notes = home.join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    std::fs::write(notes.join(".ignore"), "!.env\n").unwrap();
    std::fs::write(notes.join(".env"), "MODE=dev\n").unwrap();
    let in_notes = crate::pretool::PathContext {
        cwd: notes.to_str(),
        ..context
    };
    for (command, allowed) in [
        ("rg -ln run".to_owned(), false),
        ("rg -ln run handlers_*.rs".to_owned(), false),
        (format!("rg -ln run {r}/src handlers_*.rs"), true),
    ] {
        assert_eq!(decide(&command, in_notes), allowed, "{command}");
    }
}
