//! `fd` rooted at a framework route: `fd -e tsx . app/blog/[slug]`.
//! The bracket class matches nothing on disk, so the shell hands `fd` the word
//! as it was typed and the search starts in the route directory the word
//! names. That directory is screened as the same path without brackets would
//! be, and a class the shell could expand keeps its review.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn a_names_only_search_of_a_route_directory_is_allowed() {
    let layout = layout("fd-bracket-route");
    let portal = layout.org.join("app-portal");
    write(
        portal.join("app/blog/[slug]/page.tsx"),
        "export const x = 1;\n",
    );
    write(
        portal.join("app/blog/[slug]/blog-post-content.tsx"),
        "export const y = 2;\n",
    );
    write(
        portal.join("app/[locale]/layout.tsx"),
        "export const z = 3;\n",
    );
    let sibling = layout.org.join("service-api");
    write(
        sibling.join("app/[locale]/page.tsx"),
        "export const w = 4;\n",
    );
    let cwd = portal.clone();
    for command in [
        "fd . app/blog/[slug]",
        "fd -e tsx . app/[locale]",
        "fd page app/blog/[slug]",
        "fd --max-depth 2 . app/blog/[slug]",
        "fd . ~/Code/org/app-portal/app/blog/[slug]",
        "fd . ~/Code/org/service-api/app/[locale]",
        "fd . app/blog/[slug] | head -20",
        "fd . --search-path app/blog/[slug]",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
    // The shell globs the whole `--search-path=` word, not the part after
    // `=`, so a directory named `--search-path=app/b` would send fd somewhere
    // the bracket proof never walked. The attached spelling keeps its review,
    // as the attached `~` one does.
    assert_decision(
        &cwd,
        &layout.home,
        "fd . --search-path=app/blog/[slug]",
        false,
    );
}

#[test]
fn a_bracket_root_the_shell_could_expand_keeps_its_review() {
    let layout = layout("fd-bracket-expands");
    let portal = layout.org.join("app-portal");
    write(
        portal.join("app/[sidebar]/page.tsx"),
        "export const x = 1;\n",
    );
    // A sibling the folded matcher reaches, so the word may name this
    // directory instead of the route.
    write(portal.join("app/S/page.tsx"), "export const y = 2;\n");
    write(
        portal.join("app/blog/[slug]/page.tsx"),
        "export const z = 3;\n",
    );
    let cwd = portal.clone();
    for command in [
        "fd . app/[sidebar]",
        // No directory of that name, so the proof describes nothing.
        "fd . app/blog/[missing]",
        // A negated class matches whatever the directory happens to hold.
        "fd . app/[!x]",
        // `--hidden` prints the entries the walk proves nothing about.
        "fd --hidden . app/blog/[slug]",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}

#[test]
fn a_route_tree_that_could_name_a_secret_is_reviewed() {
    let layout = layout("fd-bracket-secret");
    let portal = layout.org.join("app-portal");
    write(portal.join("app/admin/[id]/service.pem"), "SYNTHETIC KEY\n");
    write(layout.home.join(".ssh/id_rsa"), "fixture\n");
    let keys = portal.join("app/keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::os::unix::fs::symlink(layout.home.join(".ssh"), keys.join("[id]")).unwrap();
    let cwd = portal.clone();
    for command in ["fd . app/admin/[id]", "fd . app/keys/[id]"] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}
