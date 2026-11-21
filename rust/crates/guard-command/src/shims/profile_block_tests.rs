use super::{guard_shim_profile_content, strip_managed_marker_blocks};
use crate::shims::{GUARD_PROFILE_MARKER, PACKAGE_PROFILE_MARKER};

#[test]
fn strip_preserves_marker_free_content() {
    let content = "a=1\nb=2\n";
    assert_eq!(
        strip_managed_marker_blocks(content, PACKAGE_PROFILE_MARKER),
        content
    );
    assert_eq!(
        strip_managed_marker_blocks("a=1", PACKAGE_PROFILE_MARKER),
        "a=1\n"
    );
}

#[test]
fn strip_keeps_empty_content_empty() {
    assert_eq!(strip_managed_marker_blocks("", PACKAGE_PROFILE_MARKER), "");
}

#[test]
fn strip_keeps_user_blank_runs() {
    let content = "a=1\n\n\n\nb=2\n";
    assert_eq!(
        strip_managed_marker_blocks(content, PACKAGE_PROFILE_MARKER),
        content
    );
}

#[test]
fn strip_drops_the_blank_lines_beside_a_block() {
    let content = format!("a=1\n\n{GUARD_PROFILE_MARKER}\nexport PATH=/x:$PATH\n\nb=2\n");
    assert_eq!(
        strip_managed_marker_blocks(&content, GUARD_PROFILE_MARKER),
        "a=1\nb=2\n"
    );
}

#[test]
fn guard_block_is_appended_once() {
    let shim = "/Users/me/.hol-guard/bin";
    let first = guard_shim_profile_content("# user profile content\n", shim, false);
    assert_eq!(
        first,
        format!("# user profile content\n{GUARD_PROFILE_MARKER}\nexport PATH={shim}:$PATH\n")
    );
    assert_eq!(guard_shim_profile_content(&first, shim, false), first);
}

#[test]
fn guard_block_alone_is_the_whole_profile() {
    let shim = "/Users/me/.hol-guard/bin";
    let block = format!("{GUARD_PROFILE_MARKER}\nexport PATH={shim}:$PATH\n");
    assert_eq!(guard_shim_profile_content("", shim, false), block);
    assert_eq!(guard_shim_profile_content(&block, shim, false), block);
}

#[test]
fn guard_block_uses_fish_syntax_for_fish() {
    let content = guard_shim_profile_content("set -x A 1", "/Users/me/.hol-guard/bin", true);
    assert_eq!(
        content,
        format!(
            "set -x A 1\n{GUARD_PROFILE_MARKER}\nfish_add_path --prepend -- /Users/me/.hol-guard/bin\n"
        )
    );
}

#[test]
fn guard_block_replaces_a_stale_shim_dir_and_quotes_the_new_one() {
    let stale = format!("export KEEP=1\n{GUARD_PROFILE_MARKER}\nexport PATH=/old/bin:$PATH\n");
    let content = guard_shim_profile_content(&stale, "/Users/me/Guard Home/bin", false);
    assert_eq!(
        content,
        format!(
            "export KEEP=1\n{GUARD_PROFILE_MARKER}\nexport PATH='/Users/me/Guard Home/bin':$PATH\n"
        )
    );
}

#[test]
fn guard_block_leaves_the_package_block_alone() {
    let existing = format!("{PACKAGE_PROFILE_MARKER}\nexport PATH=/p/bin:$PATH\n");
    let content = guard_shim_profile_content(&existing, "/g/bin", false);
    assert_eq!(
        content,
        format!("{existing}{GUARD_PROFILE_MARKER}\nexport PATH=/g/bin:$PATH\n")
    );
}
