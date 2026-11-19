//! Searches of a path whose brackets were escaped or quoted.
//!
//! `grep -rn foo trap/\[k\]` searches the entry literally named `trap/[k]`.
//! The screen sees the word after the shell has removed the backslashes, so
//! it cannot tell it from the pattern `trap/[k]`, which matches `trap/k`.
//! Proving `trap/k` said nothing about `trap/[k]`, and when that entry was a
//! link to a credential store the search was allowed. A literal entry with
//! the bracketed name now has to clear the search screen itself.
//!
//! The same screen lets a recursive grep of a route folder or route file
//! through, as `grep -n` and `rg` of that path already were. Under `nullglob`
//! an unquoted bracket class that matches nothing disappears, and `grep -r`
//! with no path left walks the working directory, so that directory has to
//! pass the screen as well.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn a_recursive_grep_of_a_route_folder_is_allowed() {
    let layout = layout("grep-bracket-route");
    let project = layout.org.join("service-api");
    write(
        project.join("app/api/groups/[slug]/route.ts"),
        "export {};\n",
    );
    for command in [
        r"grep -rn foo app/api/groups/\[slug\]/route.ts",
        "grep -rn foo 'app/api/groups/[slug]/route.ts'",
        r"grep -rn foo app/api/groups/\[slug\]",
        "grep -rln foo app/api/groups/[slug]",
    ] {
        assert_decision(&project, &layout.home, command, true);
    }
}

#[test]
fn a_bracketed_search_root_is_screened_where_it_leads() {
    let layout = layout("grep-bracket-link");
    let project = layout.org.join("service-api");
    write(layout.home.join(".ssh/id_ed25519"), "fixture\n");
    write(project.join("trap/k/a.txt"), "ordinary fixture\n");
    std::os::unix::fs::symlink(layout.home.join(".ssh"), project.join("trap/[k]")).unwrap();
    assert_decision(&project, &layout.home, "grep -rn foo trap/k", true);
    // The literal `trap/[k]` is a link to the credential store, while the
    // pattern `trap/[k]` matches the ordinary `trap/k`.
    for command in [
        r"grep -rn foo trap/\[k\]",
        "grep -rn foo 'trap/[k]'",
        "grep -rn foo \"trap/[k]\"",
        r"grep -rln foo trap/\[k\]",
        r"grep -n foo trap/\[k\]/id_ed25519",
        r"rg foo trap/\[k\]",
        "rg foo 'trap/[k]'",
    ] {
        assert_decision(&project, &layout.home, command, false);
    }
}

#[test]
fn an_unquoted_route_root_needs_the_working_directory_proven_too() {
    let layout = layout("grep-bracket-nullglob");
    let project = layout.org.join("service-api");
    write(
        project.join("app/api/groups/[slug]/route.ts"),
        "export {};\n",
    );
    write(project.join("id_ed25519"), "fixture\n");
    // The quote map shows the word quoted, so it stays the one root.
    assert_decision(
        &project,
        &layout.home,
        "grep -rn foo 'app/api/groups/[slug]'",
        true,
    );
    // Unquoted or escaped, the screen cannot rule out `nullglob` dropping the
    // word and leaving `grep -r` to walk the key file beside it.
    for command in [
        "grep -rln foo app/api/groups/[slug]",
        r"grep -rn foo app/api/groups/\[slug\]",
    ] {
        assert_decision(&project, &layout.home, command, false);
    }
}
