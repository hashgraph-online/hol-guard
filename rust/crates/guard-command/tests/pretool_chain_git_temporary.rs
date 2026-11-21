#![cfg(unix)]

//! A chain may save a Git object read in a temporary file and inspect it in
//! the same command: `git -C app show <rev>:src/a.ts > /tmp/a.ts && wc -l /tmp/a.ts`.
//! Git object reads change no directory, rename nothing and create no link, so
//! they may share a chain with that file. `stat` may take an output format.
//! Working-tree Git commands, execution sinks, `cd`, hidden and credential
//! paths keep their review.

use crate::pretool_home_layout_reads::{decide, layout};
use std::path::{Path, PathBuf};

struct Temporary(PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Check every command before failing, so one run reports each mismatch.
fn assert_decisions(cwd: &Path, home: &Path, commands: &[String], allowed: bool) {
    let mismatches: Vec<String> = commands
        .iter()
        .filter_map(|command| {
            let result = decide(cwd, home, command);
            ((result.decision == "allow") != allowed)
                .then(|| format!("{command}: {} {}", result.decision, result.reason_code))
        })
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

fn temporary(name: &str) -> Temporary {
    let path = PathBuf::from(format!(
        "/tmp/hg-git-chain-{name}-{}.ts",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    Temporary(path)
}

#[test]
fn git_object_reads_share_a_chain_with_their_temporary_file() {
    let layout = layout("git-temporary");
    let staged = temporary("allowed");
    let file = staged.0.display();
    let reads = [
        format!("git -C app-portal show HEAD:src/main.rs > {file} && wc -l {file}"),
        format!("git -C app-portal show HEAD:src/main.rs > {file}; wc -l {file}"),
        format!("git -C app-portal log --oneline -3 > {file} && head -2 {file}"),
        format!("git -C app-portal ls-files > {file} && wc -l {file}"),
        format!(
            "git -C app-portal show HEAD:src/main.rs > {file} && grep -n main {file} | head -5"
        ),
    ];
    assert_decisions(&layout.org, &layout.home, &reads, true);
    std::fs::write(&staged.0, "fn main() {}\n").unwrap();
    // A BSD `-f` format GNU stat would read as one name in the working
    // directory, a metadata lookup, so it passes on either stat.
    let stats = [
        format!("stat -c '%n %s' {file}; file {file}"),
        format!("stat -c '%n %s' {file}"),
        "stat -x app-portal/src/main.rs".to_owned(),
        format!("stat -f \"%N %Sm\" {file}; file {file}"),
        format!("stat -f \"%N %Sm\" {file}"),
        "stat -f '%N %z' app-portal/src/main.rs".to_owned(),
    ];
    assert_decisions(&layout.org, &layout.home, &stats, true);
}

#[test]
fn temporary_git_chains_keep_working_tree_sink_and_path_boundaries() {
    let layout = layout("git-temporary-reviewed");
    let staged = temporary("reviewed");
    let file = staged.0.display();
    std::fs::create_dir_all(layout.home.join(".ssh")).unwrap();
    std::fs::write(layout.home.join(".ssh/id_rsa"), "synthetic key\n").unwrap();
    std::fs::write(layout.org.join("app-portal/.env"), "TOKEN=synthetic\n").unwrap();
    let home = layout.home.display();
    let reviewed = [
        // Working-tree Git commands and a write flag stay out of the chain.
        // (`git status` is left out: this harness enables its permission,
        // and `checkout -b` is a local write Guard already allows.)
        format!("git -C app-portal pull --ff-only > {file}; cat {file}"),
        format!("git -C app-portal diff --output={file}.out > {file}; wc -l {file}"),
        // The saved text reaches an execution sink, or the chain re-anchors.
        format!("git -C app-portal show HEAD:src/main.rs > {file} && sh {file}"),
        format!("git -C app-portal show HEAD:src/main.rs > {file} && cat {file} | sh"),
        format!(
            "git -C app-portal show HEAD:src/main.rs > {file} && cd app-portal && cp {file} b.rs"
        ),
        format!("git -C app-portal show HEAD:src/main.rs > {home}/.zshrc && wc -l {home}/.zshrc"),
        // Credential, hidden and unproven stat operands.
        format!("stat -f '%N %Sm' {home}/.ssh/id_rsa"),
        "stat -f '%N %Sm' ~/.ssh/id_rsa".to_owned(),
        "stat -f '%N' app-portal/.env".to_owned(),
        format!("stat -f '%N' {home}/.ssh"),
        "stat -f".to_owned(),
        "stat -f '%N'".to_owned(),
        "stat --file-system app-portal/src/main.rs".to_owned(),
        "stat -f '%N' $(cat app-portal/src/main.rs)".to_owned(),
        // A format that names a path is still screened as a read target.
        format!("stat -f ~/.ssh/id_ed25519 {file}"),
        format!("stat -f /etc/x {file}"),
        format!("stat -t '%N' {home}/.ssh/id_rsa"),
    ];
    assert_decisions(&layout.org, &layout.home, &reviewed, false);
}
