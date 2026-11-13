//! A `--home` option that names the Guard home the command already uses.
//!
//! Guard's inspection commands read the store under their home. Without
//! `--home` that is the account's own `.hol-guard` directory. Another home
//! is one the command may create or that holds someone else's state, so root
//! overrides stay under review. A
//! `--home` that spells that same directory as an absolute path reads the
//! store the plain command reads, so it is set aside before the subcommand
//! is checked: `hol-guard approvals wait <id> --home /Users/me/.hol-guard` is
//! proven the way `hol-guard approvals wait <id>` is.

/// [`super::guard_diagnostics::safe_hol_guard_segment`] for `segment`, read
/// once as written and once more with a `--home` naming the account's own
/// Guard home set aside.
pub(super) fn safe_hol_guard_segment(
    basename: &str,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    let proven = |arguments: &[String]| {
        super::guard_diagnostics::safe_hol_guard_segment(
            basename,
            arguments,
            context.cwd,
            segment.pipeline_index,
        )
    };
    proven(&segment.arguments)
        || without_own_home(&segment.arguments, context.home_dir).is_some_and(|rest| proven(&rest))
}

/// `arguments` without their one `--home` option, when that option names the
/// Guard home the launcher uses without it. `None` when there is no such
/// option, when it names any other directory, or when it is given more than
/// once.
pub(super) fn without_own_home(
    arguments: &[String],
    home_dir: Option<&str>,
) -> Option<Vec<String>> {
    let home = home_dir?.trim_end_matches('/');
    if home.is_empty() || !home.starts_with('/') {
        return None;
    }
    let own = format!("{home}/.hol-guard");
    let mut rest = Vec::with_capacity(arguments.len());
    let mut found = false;
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        let value = if word == "--home" {
            words.next()?.as_str()
        } else if let Some(value) = word.strip_prefix("--home=") {
            value
        } else {
            rest.push(word.clone());
            continue;
        };
        if found || value.trim_end_matches('/') != own {
            return None;
        }
        found = true;
    }
    found.then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::without_own_home;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn only_the_own_home_is_set_aside() {
        let home = "/home/fixture";
        for (text, expected) in [
            (
                "approvals wait abc --json --home {home}/.hol-guard",
                Some("approvals wait abc --json"),
            ),
            (
                "approvals wait abc --home={home}/.hol-guard/",
                Some("approvals wait abc"),
            ),
            (
                "--home {home}/.hol-guard approvals list",
                Some("approvals list"),
            ),
            ("approvals wait abc", None),
            ("approvals wait abc --home {home}/other", None),
            ("approvals wait abc --home {home}/.hol-guard/../x", None),
            ("approvals wait abc --home ~/.hol-guard", None),
            (
                "approvals wait abc --home {home}/.hol-guard --home {home}/.hol-guard",
                None,
            ),
            ("approvals wait abc --home", None),
        ] {
            let text = text.replace("{home}", home);
            assert_eq!(
                without_own_home(&words(&text), Some(home)),
                expected.map(words),
                "{text}"
            );
        }
    }
}
