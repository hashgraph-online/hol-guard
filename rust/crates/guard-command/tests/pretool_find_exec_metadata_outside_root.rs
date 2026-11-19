#![cfg(unix)]

//! `find` over a sibling repository with a metadata child.
//!
//! An agent working in one repository often checks file times or sizes in a
//! sibling checkout, as `find ~/Code/org/service-api/src -type f -exec stat
//! -f "%m %N" {} \;` does. `find` over the same root with no child was
//! already allowed, and so was the same `-exec stat` after `cd` into the
//! sibling, but naming the sibling from the current repository went to review
//! because the fan-out proof only accepted roots inside the working
//! directory. `ls` and `stat` print only what a listing shows about each
//! file, so they may now walk a root outside the working directory when that
//! root is a non-hidden directory below home that a plain read accepts.
//! Children that read file contents stay bound to the working directory.

use serde_json::json;

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{layout, write};

#[test]
fn a_metadata_child_may_walk_a_sibling_repository() {
    let layout = layout("find-exec-metadata-sibling");
    let home = &layout.home;
    let sibling = layout.org.join("service-api");
    let cwd = layout.org.join("app-portal");
    write(home.join(".toolcfg/settings.json"), "{}\n");
    std::os::unix::fs::symlink(home.join(".toolcfg"), layout.org.join("linked")).unwrap();
    let sib = fixture::shell_word(&sibling);
    let org = fixture::shell_word(&layout.org);
    let home_word = fixture::shell_word(home);
    let cases = [
        (
            format!(r#"find {sib}/src -type f -exec stat -f "%m %N" {{}} \;"#),
            true,
        ),
        (format!("find {sib}/src -type f -exec ls -l {{}} +"), true),
        (
            r"find ~/Code/org/service-api/src -type f -exec stat {} \;".to_owned(),
            true,
        ),
        (
            "find ../service-api -type f -exec ls -la {} +".to_owned(),
            true,
        ),
        (
            "find ../service-api -type f -print0 | xargs -0 stat".to_owned(),
            true,
        ),
        // Children that read contents stay bound to the working directory.
        (format!("find {sib}/src -type f -exec cat {{}} +"), false),
        (
            format!("find {sib}/src -type f -name '*.rs' -exec cat {{}} +"),
            false,
        ),
        (format!("find {sib}/src -type f -exec wc -l {{}} +"), false),
        // Home itself, a home dot-directory, a link into one and a root
        // outside home keep review whatever the child.
        (r"find ~ -type f -exec stat {} \;".to_owned(), false),
        (
            format!("find {home_word} -type f -exec ls -l {{}} +"),
            false,
        ),
        (
            r"find ~/.toolcfg -type f -exec stat {} \;".to_owned(),
            false,
        ),
        (
            format!(r"find {org}/linked -type f -exec stat {{}} \;"),
            false,
        ),
        (r"find /etc -type f -exec stat {} \;".to_owned(), false),
        // A quoted or escaped `~` never reaches the shell as the home
        // directory. The word stays the literal relative name `~/Code/...`,
        // which `find` looks for under the working directory, so the home
        // path this proof would resolve is not the path the command walks.
        (
            r"find '~/Code/org/service-api/src' -type f -exec stat {} \;".to_owned(),
            false,
        ),
        (
            r#"find "~/Code/org/service-api/src" -type f -exec ls -l {} +"#.to_owned(),
            false,
        ),
        (
            r"find \~/Code/org/service-api/src -type f -exec stat {} \;".to_owned(),
            false,
        ),
    ];
    for harness in ["zcode", "codex", "claude-code"] {
        for (command, allowed) in &cases {
            let result = fixture::evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
                None,
                None,
                home.to_str(),
                cwd.to_str(),
            );
            assert_eq!(
                result.decision == "allow",
                *allowed,
                "{harness}: {command} => {} / {}",
                result.decision,
                result.reason_code
            );
        }
    }
}
