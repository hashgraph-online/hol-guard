use super::skip_inert_options;

/// The words a manager reads before its verb are skipped, so the verb behind
/// them is the one the admission check reads.
#[test]
fn an_inert_option_does_not_hide_the_verb() {
    for (manager, arguments, verb) in [
        ("pnpm", vec!["--silent", "build"], "build"),
        ("pnpm", vec!["-r", "build"], "build"),
        ("pnpm", vec!["--reporter", "silent", "test"], "test"),
        ("pnpm", vec!["--reporter=silent", "test"], "test"),
        ("pnpm", vec!["--filter", "web", "build"], "build"),
        ("pnpm", vec!["-F", "@acme/web", "lint"], "lint"),
        ("npm", vec!["--silent", "run", "build"], "run"),
        ("npm", vec!["--loglevel=error", "test"], "test"),
        ("npm", vec!["--workspace", "web", "run", "build"], "run"),
        ("yarn", vec!["--silent", "build"], "build"),
        ("bun", vec!["--bun", "run", "build"], "run"),
    ] {
        let skipped = skip_inert_options(manager, &arguments);
        assert_eq!(arguments.get(skipped).copied(), Some(verb), "{arguments:?}");
    }
}

/// An option the lists do not hold stops the walk where it stands, so the
/// verb stays hidden and the command keeps the admission it has today.
#[test]
fn an_unknown_option_still_hides_the_verb() {
    for (manager, arguments) in [
        // A bare `yarn` installs, and so does one carrying only options.
        ("yarn", vec!["--frozen-lockfile"]),
        ("npm", vec!["--prefix", "web", "run", "build"]),
        ("pnpm", vec!["-C", "web", "build"]),
        ("bun", vec!["--cwd", "web", "run", "build"]),
        ("pnpm", vec!["--registry", "https://example.test", "build"]),
        // Each list is its own manager's; bun reads none of pnpm's.
        ("bun", vec!["-r", "build"]),
    ] {
        let skipped = skip_inert_options(manager, &arguments);
        assert!(
            arguments
                .get(skipped)
                .is_none_or(|argument| argument.starts_with('-')),
            "{arguments:?}"
        );
    }
}

/// A selector reaching out of the workspace is refused, so a filter cannot
/// reach a project the workspace does not hold.
#[test]
fn a_path_selector_leaving_the_workspace_is_not_an_inert_value() {
    for arguments in [
        vec!["--filter", "../sibling", "build"],
        vec!["--filter", "/opt/other", "build"],
        vec!["--filter", "~/other", "build"],
        vec!["--filter", "web/../../other", "build"],
        vec!["--filter", "..\\other", "build"],
        vec!["--filter", "web\\..\\..\\other", "build"],
        vec!["--filter=../sibling", "build"],
        // pnpm removes the `...` that adds dependents before it decides
        // whether what is left names a place, so these resolve to
        // `../other` against the directory the command ran in.
        vec!["--filter", "...../other", "build"],
        vec!["--filter", "...^../other", "build"],
        vec!["--filter", "!...../other", "build"],
        vec!["--filter=...../other", "build"],
        vec!["--filter", "...^..\\other", "build"],
        // The shell expands a brace alternative into one word per
        // alternative, so pnpm is handed `--filter=../sibling` of its own.
        vec!["--filter={web,../sibling}", "build"],
        vec!["--filter", "{web,../sibling}", "build"],
        vec!["--filter", "web,/opt/other", "build"],
        vec!["-F", "/opt/other", "build"],
        // A missing value leaves the option itself in front of the verb.
        vec!["--filter"],
        vec!["--filter", "--silent", "build"],
    ] {
        assert_eq!(skip_inert_options("pnpm", &arguments), 0, "{arguments:?}");
    }
}

/// A selector naming a directory below where the command runs selects one of
/// the workspace's own projects, exactly as the bare name does, so it carries
/// the verb past the walk rather than hiding it.
#[test]
fn a_selector_that_stays_in_the_workspace_is_an_inert_value() {
    for (arguments, skipped) in [
        (vec!["--filter", "./packages/web", "build"], 2),
        (vec!["--filter=./packages/web", "build"], 1),
        (vec!["-F", "./packages/web", "build"], 2),
        // pnpm's `...` suffix adds the project's dependents to the same
        // selection; it names no other place.
        (vec!["--filter", "./packages/web...", "build"], 2),
        (vec!["--filter", "packages/web", "build"], 2),
        (vec!["--filter", ".", "build"], 2),
        // The `{<dir>}` selector holds a directory, and this one is inside.
        (vec!["--filter", "{packages/web}", "build"], 2),
        (vec!["--filter", "@scope/*{components/**}", "build"], 2),
        // The same `...` prefix in front of a name is a name, not a place.
        (vec!["--filter", "...web", "build"], 2),
        (vec!["--filter", "...^web", "build"], 2),
        (vec!["--filter", "...packages/web", "build"], 2),
        (vec!["--filter", "!...web", "build"], 2),
    ] {
        assert_eq!(
            skip_inert_options("pnpm", &arguments),
            skipped,
            "{arguments:?}"
        );
    }
}

/// A scoped package name is a name, not a path.
#[test]
fn a_scoped_name_is_an_inert_value() {
    assert_eq!(
        skip_inert_options("pnpm", &["--filter", "@acme/web", "build"]),
        2
    );
}

/// pnpm's `{<dir>}` selector holds a directory wherever in the value it sits,
/// a drive letter opens one on Windows, and a `$` hides what the value names,
/// so a directory operand reaching out refuses the whole value whatever
/// precedes it.
#[test]
fn a_directory_selector_leaving_the_workspace_is_not_an_inert_value() {
    for arguments in [
        vec!["--filter", "{/opt/other}", "build"],
        vec!["--filter", "{../sibling}", "build"],
        vec!["--filter", "web{/opt/other}", "build"],
        vec!["--filter", "web{../../other}", "build"],
        vec!["--filter", "[origin/main]{/opt/other}", "build"],
        vec!["--filter", "!{/opt/other}", "build"],
        vec!["--filter=C:/other", "build"],
        vec!["--filter", "C:\\other", "build"],
        vec!["--filter", "$HOME/other", "build"],
        vec!["--filter", "{$HOME/other}", "build"],
    ] {
        assert_eq!(skip_inert_options("pnpm", &arguments), 0, "{arguments:?}");
    }
}

/// A changed-since selector names a git ref, not a place on disk.
#[test]
fn a_changed_since_selector_is_an_inert_value() {
    assert_eq!(
        skip_inert_options("pnpm", &["--filter", "[origin/main]", "build"]),
        2
    );
}
