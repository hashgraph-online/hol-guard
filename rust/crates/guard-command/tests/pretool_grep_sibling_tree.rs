//! `grep -r` rooted in a neighbouring repository: `grep -rln PATTERN
//! ~/Code/org/service-api/tests`. `grep` reads no ignore file, so the walk it
//! would perform is the whole proof, and it is the same walk a root inside
//! the current directory gets. A root whose tree holds `.git`, a credential
//! name or a link out keeps its review, as does one outside a repository.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn a_recursive_search_of_a_sibling_subdirectory_is_allowed() {
    let layout = layout("grep-sibling-tree");
    let sibling = layout.org.join("service-api");
    write(sibling.join("tests/journey/runner.spec.ts"), "fixture\n");
    write(sibling.join("tests/fixtures/sample.json"), "{}\n");
    write(sibling.join("src/main.rs"), "fn main() {}\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "grep -rln fixture ~/Code/org/service-api/tests",
        "grep -rn fixture ~/Code/org/service-api/tests/",
        "grep -rn fixture ~/Code/org/service-api/src",
        "grep -rn fixture ~/Code/org/service-api/src ~/Code/org/service-api/tests",
        "grep -rn fixture ../service-api/tests",
        "grep -rn fixture ~/Code/org/service-api/tests 2>&1 | head -20",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn naming_a_file_in_a_sibling_repository_is_allowed() {
    let layout = layout("grep-sibling-file");
    let sibling = layout.org.join("service-api");
    write(
        sibling.join("src/journey/runner.ts"),
        "export const x = 1;\n",
    );
    let cwd = layout.org.join("app-portal");
    for command in [
        "grep -n export ~/Code/org/service-api/src/journey/runner.ts",
        // A path that is not there prints an error, as a probe `ls` does.
        "grep -n export ~/Code/org/service-api/src/journey/missing.ts",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn a_sibling_tree_that_could_reach_a_secret_is_reviewed() {
    let layout = layout("grep-sibling-secret");
    let sibling = layout.org.join("service-api");
    write(sibling.join("tests/.env"), "TOKEN=fixture\n");
    write(sibling.join("config/credentials.json"), "{}\n");
    write(sibling.join("certs/server.pem"), "fixture\n");
    write(layout.home.join(".ssh/id_rsa"), "fixture\n");
    std::os::unix::fs::symlink(layout.home.join(".ssh"), sibling.join("keys")).unwrap();
    let cwd = layout.org.join("app-portal");
    for command in [
        // The repository root itself carries `.git`.
        "grep -rn fixture ~/Code/org/service-api",
        "grep -rn fixture ~/Code/org/service-api/tests",
        "grep -rn fixture ~/Code/org/service-api/config",
        "grep -rn fixture ~/Code/org/service-api/certs",
        "grep -rn fixture ~/Code/org/service-api/keys",
        "grep -rn fixture ~/Code/org/service-api/.git",
        // A hidden directory of the home directory is no repository's tree.
        "grep -rn fixture ~/.ssh",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}

#[test]
fn a_missing_sibling_root_a_peer_segment_would_create_keeps_its_review() {
    let layout = layout("grep-sibling-plant");
    write(
        layout.org.join("service-api/tests/runner.spec.ts"),
        "fixture\n",
    );
    let cwd = layout.org.join("app-portal");
    assert_decision(
        &cwd,
        &layout.home,
        "mkdir -p ~/Code/org/service-api/out && grep -rn fixture ~/Code/org/service-api/out",
        false,
    );
}

#[test]
fn a_hidden_link_or_a_store_named_as_the_root_keeps_its_review() {
    let layout = layout("grep-sibling-store-root");
    let sibling = layout.org.join("service-api");
    write(sibling.join("docs/guide.md"), "fixture\n");
    write(sibling.join("secrets/prod.json"), "{}\n");
    write(sibling.join("ops/api-tokens/prod.json"), "{}\n");
    // A hidden name that resolves to an ordinary directory: the walk reads
    // where the link lands, so the spelling is what carries the name.
    std::os::unix::fs::symlink(sibling.join("docs"), sibling.join(".private")).unwrap();
    let cwd = layout.org.join("app-portal");
    for command in [
        "grep -rn fixture ~/Code/org/service-api/.private",
        "grep -rn fixture ../service-api/.private",
        "grep -rn fixture ~/Code/org/service-api/secrets",
        "grep -rn fixture ~/Code/org/service-api/ops/api-tokens",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
    assert_decision(
        &cwd,
        &layout.home,
        "grep -rn fixture ~/Code/org/service-api/docs",
        true,
    );
}

/// An ordinary repository is bigger than ten thousand entries, and this walk
/// used to stop counting there and return false on the entry that crossed the
/// bound. Nothing about the search was unsafe; the walk simply stopped looking
/// before it could say so, and every search named at a directory with more
/// files than that below it went to review. hol-guard's own tree is already
/// past the old bound.
#[test]
fn a_sibling_repository_past_ten_thousand_entries_is_still_proven() {
    let layout = layout("grep-sibling-entry-count");
    let sibling = layout.org.join("service-api");
    for shard in 0..102u32 {
        let directory = sibling.join(format!("src/generated/shard-{shard:03}"));
        std::fs::create_dir_all(&directory).unwrap();
        for index in 0..100u32 {
            std::fs::write(
                directory.join(format!("case-{index:03}.rs")),
                "// fixture\n",
            )
            .unwrap();
        }
    }
    let cwd = layout.org.join("app-portal");
    for command in [
        "grep -rn fixture ~/Code/org/service-api/src",
        "grep -rn fixture ~/Code/org/service-api/src/generated",
        "rg -n fixture ../service-api/src",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}
