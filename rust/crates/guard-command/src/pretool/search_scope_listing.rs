//! What a directory listing tells the scope walk before it opens anything:
//! whether an ignore file or nested repository may be there, and which
//! ignore rules the directory's entries inherit.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::FileType;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::search_scope_ignore::{IgnoreTiers, ScopeUnproven, MAX_IGNORE_RULES};

/// One entry of a directory listing: its name and its own kind, as the
/// listing reports it, so a link is never followed.
pub(super) struct Listed {
    pub(super) name: OsString,
    pub(super) file_type: FileType,
}

/// Listings read within one evaluation, with whether each holds the whole
/// directory or stopped at the limit it was read to.
type Listings = Option<HashMap<PathBuf, (Rc<[Listed]>, bool)>>;

thread_local! {
    static LISTINGS: RefCell<Listings> = const { RefCell::new(None) };
}

/// Runs `evaluate` with a listing memo of its own, dropped when it returns.
pub(super) fn with_listings<T>(evaluate: impl FnOnce() -> T) -> T {
    struct Restore(Listings);
    impl Drop for Restore {
        fn drop(&mut self) {
            LISTINGS.with(|listings| *listings.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(LISTINGS.with(|listings| listings.replace(Some(HashMap::new()))));
    evaluate()
}

/// At least the first `limit` entries of `directory`, or all of them when it
/// holds fewer; a caller reads no further than its own limit. One `rg` is proven by more than one walk of the same tree, and on
/// a large tree opening every directory again was a third of the decision;
/// within an evaluation each directory is read once, unless a later walk
/// needs more of it than an earlier one read. `None` when the directory or
/// an entry cannot be read.
pub(super) fn read_listing(directory: &Path, limit: usize) -> Option<Rc<[Listed]>> {
    let cached = LISTINGS.with(|listings| {
        listings
            .borrow()
            .as_ref()
            .and_then(|listings| listings.get(directory).cloned())
    });
    if let Some((listed, complete)) = cached {
        if complete || listed.len() >= limit {
            return Some(listed);
        }
    }
    #[cfg(test)]
    super::search::count_walk("dir-listing", directory);
    let listed: Rc<[Listed]> = std::fs::read_dir(directory)
        .ok()?
        .take(limit)
        .map(|entry| {
            let entry = entry?;
            Ok(Listed {
                name: entry.file_name(),
                file_type: entry.file_type()?,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()
        .ok()?
        .into();
    let complete = listed.len() < limit;
    LISTINGS.with(|listings| {
        if let Some(listings) = listings.borrow_mut().as_mut() {
            listings.insert(directory.to_path_buf(), (Rc::clone(&listed), complete));
        }
    });
    Some(listed)
}

/// Whether a directory listing may hold an entry the file system would open
/// as `wanted`. A case-insensitive file system opens `.GITIGNORE` as
/// `.gitignore`, so the match ignores ASCII case, and a name that is not
/// plain ASCII could fold to it, so it answers yes.
pub(super) fn listing_may_hold(listing: &[Listed], wanted: &str) -> bool {
    listing.iter().any(|entry| {
        entry
            .name
            .to_str()
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
