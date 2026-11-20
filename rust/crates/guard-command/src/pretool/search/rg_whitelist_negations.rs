//! Reading one ignore file into the rules and negations it states.
//!
//! A plain rule prunes a directory from the walk. A `!` line re-includes
//! what an earlier rule pruned, and Git's anchoring decides how deep that
//! reach goes, so each negation is recorded with the directory its file
//! applies to and whether any component could name a hidden secret.

use super::{benign_hidden, ignore_lines, plain_name, Negations, Risk, Rule, Target};
use std::path::Path;

/// Records the negations in one ignore file and returns the plain rules
/// that prune directories, relative to `base`. A missing file has no rules;
/// an unreadable or oversized one fails.
pub(super) fn ignore_rules(
    path: &Path,
    base: &Path,
    git: bool,
    negations: &mut Negations,
) -> Option<Vec<Rule>> {
    let Some(lines) = ignore_lines(path)? else {
        return Some(Vec::new());
    };
    let mut rules = Vec::new();
    for line in &lines {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pattern) = line.strip_prefix('!') {
            record_negation(pattern, base, negations);
            continue;
        }
        let line = line.strip_suffix('/').unwrap_or(line);
        let line = line.strip_prefix("**/").unwrap_or(line);
        // A slash at the start or in the middle anchors the rule to the
        // ignore file's directory.
        let (relative, anchored) = match line.strip_prefix('/') {
            Some(relative) => (relative, true),
            None => (line, line.contains('/')),
        };
        if !relative.split('/').all(plain_name) {
            continue;
        }
        let target = if anchored {
            Target::Path(base.join(relative))
        } else {
            Target::Name(relative.to_owned())
        };
        rules.push(Rule { target, git });
    }
    Some(rules)
}

/// Records a negated pattern, with the directory its ignore file applies to
/// and whether each component could name a hidden secret. An escape or empty
/// component matches anything.
fn record_negation(pattern: &str, base: &Path, negations: &mut Negations) {
    let pattern = pattern.strip_suffix('/').unwrap_or(pattern);
    // Git anchors a pattern to its ignore file's directory as soon as it
    // carries a slash anywhere but the end, so only a bare name re-includes
    // entries deeper down. `**` is the exception: it stands for any run of
    // directories, so `!**/.env` and `!src/**/.env` re-include that name
    // however deep it sits, and the anchored reading would miss it.
    let anchored = (pattern.starts_with('/') || pattern.contains('/'))
        && !pattern.split('/').any(|component| component.contains("**"));
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    let mut components = Vec::new();
    let spelled: Vec<&str> = pattern.split('/').collect();
    for (index, component) in spelled.iter().copied().enumerate() {
        if component.is_empty() || component.contains('\\') {
            negations.all.push("*".to_owned());
            components.push(("*".to_owned(), true));
            continue;
        }
        // A `**` that a name follows stands for the run of directories above
        // that name, which is pushed here in its own turn, and names no entry
        // itself. Pushed as a pattern it would match every pruned directory,
        // so `dist/` beside `!**/notes.md` would read as a re-included
        // `dist`. A trailing `**` is the opposite: `!**` re-includes every
        // entry there is, pruned directories among them, so it keeps the
        // pattern that matches them.
        if component != "**" || index + 1 == spelled.len() {
            negations.all.push(component.to_owned());
        }
        let screened = !super::super::sensitive_path_argument(component)
            && !super::super::glob_can_select_sensitive_path(component);
        // A wildcard such as `.c[a]rgo` can re-include a whole hidden
        // directory, so it counts whenever it matches a hidden name.
        let harmless = plain_name(component)
            && (!component.starts_with('.') || (screened && benign_hidden(component)));
        components.push((component.to_owned(), !harmless));
    }
    // A `**` pattern is held by its last component at any depth, which
    // re-includes at least what Git does: `!src/**/.env` holds every `.env`
    // below the ignore file rather than only the ones below `src`.
    if !anchored && components.len() > 1 {
        let last = components.pop().expect("components is not empty");
        components = vec![last];
    }
    negations.risky.push(Risk {
        base: base.to_path_buf(),
        components,
        anywhere: !anchored,
    });
}
