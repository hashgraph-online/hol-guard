//! A search told to look past ignore rules stays at review.
//!
//! `rg` skips hidden and ignored files unless a glob override (`--glob`,
//! `--iglob`), `--hidden`, `--no-ignore` or `-u` widens it. Those are the
//! files a repository keeps its local secrets in, and the read review stops
//! exactly these searches because it cannot prove what they reach. The
//! sandbox withholds only a fixed list of credential paths, so a contained
//! run would still read a secret kept under any other name and print it.

/// Whether a segment runs `rg` with a flag that reaches hidden or ignored files.
pub(super) fn widens_past_ignore_rules(model: &crate::CanonicalCommandV1) -> bool {
    model.segments.iter().any(|segment| {
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        executable.rsplit('/').next() == Some("rg")
            && segment
                .arguments
                .iter()
                .any(|argument| widening_flag(argument))
    })
}

fn widening_flag(argument: &str) -> bool {
    if let Some(long) = argument.strip_prefix("--") {
        let name = long.split_once('=').map_or(long, |(name, _)| name);
        return matches!(name, "glob" | "iglob" | "hidden" | "unrestricted")
            || name.starts_with("no-ignore");
    }
    // A short bundle such as `-nu` or `-g*.ts`; letters after `g` are its value.
    argument
        .strip_prefix('-')
        .filter(|letters| !letters.is_empty())
        .is_some_and(|letters| {
            let flags = letters.split_once('g').map_or(letters, |(flags, _)| flags);
            letters.contains('g') || flags.contains(['u', '.'])
        })
}
