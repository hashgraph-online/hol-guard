//! The `<dir>/None` sentinel as `ntpath` splits it. The daemon drops the
//! component with `os.path.dirname`, which treats a backslash as a separator
//! on Windows, so the lane has to drop the same one or it settles a directory
//! the daemon never would.

use super::normalized_workspace;

const HOME: &str = r"C:\Users\guard";

fn normalized(value: &str) -> Option<String> {
    normalized_workspace(Some(value), HOME).unwrap()
}

#[test]
fn the_no_workspace_sentinel_is_dropped_after_either_separator() {
    assert_eq!(normalized(r"C:\proj\None"), Some(r"C:\proj".to_owned()));
    assert_eq!(normalized("C:/proj/None"), Some(r"C:\proj".to_owned()));
    assert_eq!(
        normalized(r"C:\proj\sub\None"),
        Some(r"C:\proj\sub".to_owned())
    );
}

#[test]
fn a_directory_merely_ending_in_none_is_not_the_sentinel() {
    assert_eq!(
        normalized(r"C:\proj\NoneSuch"),
        Some(r"C:\proj\NoneSuch".to_owned())
    );
    assert_eq!(
        normalized(r"C:\None\work"),
        Some(r"C:\None\work".to_owned())
    );
}

#[test]
fn the_bare_sentinel_names_no_workspace() {
    assert_eq!(normalized("None"), None);
    assert_eq!(normalized("null"), None);
}

#[test]
fn the_sentinel_is_dropped_after_the_home_is_expanded() {
    assert_eq!(normalized(r"~\None"), Some(HOME.to_owned()));
    assert_eq!(normalized("~/None"), Some(HOME.to_owned()));
}
