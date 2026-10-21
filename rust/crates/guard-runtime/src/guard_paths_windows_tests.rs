//! What a Windows path keeps on its way through these resolvers. A drive or
//! UNC prefix is the part of a path that says which volume it names, so a
//! resolver that dropped it would hand the daemon a path read against
//! whichever volume the process happened to be on.

use std::path::{Path, PathBuf};

use super::{expanduser, normpath, python_realpath_lax, PathError};

#[test]
fn a_normalized_path_keeps_the_drive_it_was_written_with() {
    assert_eq!(
        normpath(r"C:\Users\me\project\..\project"),
        Ok(r"C:\Users\me\project".to_owned())
    );
    assert_eq!(normpath(r"C:/Users/me"), Ok(r"C:\Users\me".to_owned()));
}

#[test]
fn a_share_is_a_root_of_its_own() {
    assert_eq!(
        normpath(r"\\server\share\work\.\sub"),
        Ok(r"\\server\share\work\sub".to_owned())
    );
}

#[test]
fn a_path_naming_no_volume_is_not_one_this_resolver_settles() {
    assert_eq!(normpath(r"\Users\me"), Err(PathError::Relative));
    assert_eq!(normpath(r"Users\me"), Err(PathError::Relative));
    assert_eq!(
        python_realpath_lax(Path::new(r"\Users\me")),
        Err(PathError::Relative)
    );
}

#[test]
fn a_home_expands_after_either_separator() {
    assert_eq!(
        expanduser(r"~\project", r"C:\Users\me"),
        Ok(r"C:\Users\me\project".to_owned())
    );
    assert_eq!(
        expanduser("~/project", r"C:\Users\me"),
        Ok(r"C:\Users\me/project".to_owned())
    );
}

#[test]
fn resolving_a_path_that_does_not_exist_keeps_its_drive() {
    let absent = PathBuf::from(r"C:\hol-guard-absent\workspace");
    assert_eq!(python_realpath_lax(&absent), Ok(absent));
}
