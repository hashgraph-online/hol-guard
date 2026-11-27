//! The listing decides which ignore files the walk reads, so a name it
//! misses would drop rules the host applies.

use super::super::search_scope_ignore::{
    load_ignore_file, IgnoreTiers, ScopeUnproven, MAX_IGNORE_RULES,
};
use super::{inherited_tiers, listing_may_hold, read_listing, with_listings, Listed};
use std::path::{Path, PathBuf};
use std::rc::Rc;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/search-scope-listing")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    Scratch(root)
}

fn listing(directory: &Path) -> Rc<[Listed]> {
    read_listing(directory, usize::MAX).unwrap()
}

fn rules(
    scratch: &Scratch,
    name: &str,
    text: &str,
) -> Vec<super::super::search_scope_ignore::IgnoreRule> {
    let path = scratch.0.join(name);
    std::fs::write(&path, text).unwrap();
    let mut rules = Vec::new();
    load_ignore_file(&path, "", &mut rules).unwrap();
    rules
}

#[test]
fn a_listing_names_the_ignore_files_it_holds_in_any_ascii_case() {
    let scratch = scratch("names");
    std::fs::write(scratch.0.join("index.ts"), "").unwrap();
    std::fs::write(scratch.0.join(".GitIgnore"), "").unwrap();
    std::fs::create_dir(scratch.0.join(".git")).unwrap();
    let entries = listing(&scratch.0);
    assert!(listing_may_hold(&entries, ".gitignore"));
    assert!(listing_may_hold(&entries, ".git"));
    assert!(!listing_may_hold(&entries, ".ignore"));
    assert!(!listing_may_hold(&entries, ".rgignore"));
}

#[test]
fn a_name_outside_ascii_may_fold_to_an_ignore_file() {
    let scratch = scratch("folding");
    // The Kelvin sign folds to `k` on some case-insensitive file systems, so
    // the listing cannot rule out that this entry opens as another name.
    std::fs::write(scratch.0.join("\u{212a}eep"), "").unwrap();
    assert!(listing_may_hold(&listing(&scratch.0), ".rgignore"));
}

#[test]
fn a_directory_that_adds_nothing_shares_its_parents_rules() {
    let scratch = scratch("shared");
    let parent = Rc::new(IgnoreTiers {
        git: rules(&scratch, "outer", "dist/\n"),
        ..IgnoreTiers::default()
    });
    let inherited = inherited_tiers(&parent, false, IgnoreTiers::default()).unwrap();
    assert!(Rc::ptr_eq(&parent, &inherited));
}

#[test]
fn a_directory_adds_its_rules_after_its_parents() {
    let scratch = scratch("added");
    let parent = Rc::new(IgnoreTiers {
        git: rules(&scratch, "outer", "dist/\n"),
        ..IgnoreTiers::default()
    });
    let added = IgnoreTiers {
        git: rules(&scratch, "inner", "!dist/\n"),
        ignore: rules(&scratch, "custom", "build/\n"),
        rgignore: Vec::new(),
    };
    let inherited = inherited_tiers(&parent, false, added).unwrap();
    assert_eq!(parent.git.len(), 1, "the parent's rules changed");
    assert_eq!(inherited.git.len(), 2);
    assert!(!inherited.git[0].negated() && inherited.git[1].negated());
    assert_eq!(inherited.ignore.len(), 1);
}

#[test]
fn a_nested_repository_drops_only_the_outer_git_rules() {
    let scratch = scratch("nested");
    let parent = Rc::new(IgnoreTiers {
        git: rules(&scratch, "outer", "dist/\n"),
        ignore: rules(&scratch, "custom", "build/\n"),
        rgignore: Vec::new(),
    });
    let inherited = inherited_tiers(&parent, true, IgnoreTiers::default()).unwrap();
    assert!(!Rc::ptr_eq(&parent, &inherited));
    assert!(inherited.git.is_empty());
    assert_eq!(inherited.ignore.len(), 1);
    assert_eq!(parent.git.len(), 1, "the parent's rules changed");
}

#[test]
fn inherited_rules_past_the_cap_leave_the_scope_unproven() {
    let scratch = scratch("cap");
    let half = "dist/\n".repeat(MAX_IGNORE_RULES / 2 + 1);
    let parent = Rc::new(IgnoreTiers {
        rgignore: rules(&scratch, "outer", &half),
        ..IgnoreTiers::default()
    });
    let added = IgnoreTiers {
        rgignore: rules(&scratch, "inner", &half),
        ..IgnoreTiers::default()
    };
    assert!(matches!(
        inherited_tiers(&parent, false, added),
        Err(ScopeUnproven)
    ));
}

#[test]
fn an_evaluation_reads_each_listing_once() {
    // Two walks prove one `rg` over the same tree. Each listed every
    // directory again, and on a large tree the second listing pushed the
    // decision toward the hook's deadline.
    let scratch = scratch("shared");
    std::fs::write(scratch.0.join("index.ts"), "").unwrap();
    with_listings(|| {
        assert_eq!(listing(&scratch.0).len(), 1);
        std::fs::write(scratch.0.join("page.ts"), "").unwrap();
        // The evaluation keeps the listing it read first.
        assert_eq!(listing(&scratch.0).len(), 1);
    });
    // The next evaluation reads the directory again.
    with_listings(|| assert_eq!(listing(&scratch.0).len(), 2));
    // Outside an evaluation nothing is kept.
    std::fs::write(scratch.0.join("view.ts"), "").unwrap();
    assert_eq!(listing(&scratch.0).len(), 3);
}

#[test]
fn a_read_past_an_earlier_limit_lists_the_directory_again() {
    let scratch = scratch("limits");
    for name in ["a.ts", "b.ts", "c.ts"] {
        std::fs::write(scratch.0.join(name), "").unwrap();
    }
    with_listings(|| {
        // A walk with one entry of budget left reads no further than that.
        assert_eq!(read_listing(&scratch.0, 1).unwrap().len(), 1);
        // A later walk with room for every entry must see all of them, not
        // the shorter listing the first walk stopped at.
        assert_eq!(read_listing(&scratch.0, 10).unwrap().len(), 3);
        // A whole listing serves any limit after it.
        assert_eq!(read_listing(&scratch.0, 2).unwrap().len(), 3);
    });
}
