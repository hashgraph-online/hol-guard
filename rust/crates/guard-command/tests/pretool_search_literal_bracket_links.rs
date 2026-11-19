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
//! through, as `grep -n` and `rg` of that path already were.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn a_recursive_grep_of_a_route_folder_is_allowed() {
    let layout = layout("grep-bracket-route");
    let portal = layout.org.join("app-portal");
    write(
        portal.join("app/api/groups/[slug]/route.ts"),
        "export {};\n",
    );
    for command in [
        r"grep -rn foo app/api/groups/\[slug\]/route.ts",
        "grep -rn foo 'app/api/groups/[slug]/route.ts'",
        r"grep -rn foo app/api/groups/\[slug\]",
        "grep -rln foo app/api/groups/[slug]",
    ] {
        assert_decision(&portal, &layout.home, command, true);
    }
}

#[test]
fn a_bracketed_search_root_is_screened_where_it_leads() {
    let layout = layout("grep-bracket-link");
    let portal = layout.org.join("app-portal");
    write(layout.home.join(".ssh/id_ed25519"), "fixture\n");
    write(portal.join("trap/k/a.txt"), "ordinary fixture\n");
    std::os::unix::fs::symlink(layout.home.join(".ssh"), portal.join("trap/[k]")).unwrap();
    assert_decision(&portal, &layout.home, "grep -rn foo trap/k", true);
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
        assert_decision(&portal, &layout.home, command, false);
    }
}
