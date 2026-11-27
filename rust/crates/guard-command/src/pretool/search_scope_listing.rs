//! What a directory listing tells the scope walk before it opens anything:
//! whether an ignore file or nested repository may be there, and which
//! ignore rules the directory's entries inherit.

use std::rc::Rc;

use super::search_scope_ignore::{IgnoreTiers, ScopeUnproven, MAX_IGNORE_RULES};

/// Whether a directory listing may hold an entry the file system would open
/// as `wanted`. A case-insensitive file system opens `.GITIGNORE` as
/// `.gitignore`, so the match ignores ASCII case, and a name that is not
/// plain ASCII could fold to it, so it answers yes.
pub(super) fn listing_may_hold(listing: &[std::fs::DirEntry], wanted: &str) -> bool {
    listing.iter().any(|entry| {
        let name = entry.file_name();
        name.to_str()
            .is_none_or(|name| !name.is_ascii() || name.eq_ignore_ascii_case(wanted))
    })
}

/// The tiers in force inside a directory: its parent's, cleared of git rules
/// in a nested repository, with the rules its own ignore files add after
/// them. A directory that changes nothing shares its parent's tiers. A tier
/// past [`MAX_IGNORE_RULES`] has no trustworthy rules for the proof.
pub(super) fn inherited_tiers(
    parent: &Rc<IgnoreTiers>,
    nested: bool,
    added: IgnoreTiers,
) -> Result<Rc<IgnoreTiers>, ScopeUnproven> {
    if !nested && added.git.is_empty() && added.ignore.is_empty() && added.rgignore.is_empty() {
        return Ok(Rc::clone(parent));
    }
    let mut tiers = (**parent).clone();
    if nested {
        tiers.git.clear();
    }
    tiers.git.extend(added.git);
    tiers.ignore.extend(added.ignore);
    tiers.rgignore.extend(added.rgignore);
    if [&tiers.git, &tiers.ignore, &tiers.rgignore]
        .iter()
        .any(|rules| rules.len() > MAX_IGNORE_RULES)
    {
        return Err(ScopeUnproven);
    }
    Ok(Rc::new(tiers))
}

#[cfg(test)]
#[path = "search_scope_listing_tests.rs"]
mod tests;
