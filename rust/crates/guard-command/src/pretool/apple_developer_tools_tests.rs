use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

const XCODE_EXEC: &str = "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core";
const CLT_EXEC: &str = "/Library/Developer/CommandLineTools/usr/libexec/git-core";

fn directory(uid: u32, gid: u32, mode: u32) -> Entry {
    Entry {
        uid,
        gid,
        mode,
        directory: true,
        file: false,
    }
}

/// Root-owned, non-writable entries for `exec_path`, its helper and every
/// ancestor; `/Applications` gets the stock `root:admin 0775`.
fn layout(exec_path: &str) -> BTreeMap<PathBuf, (u32, u32, u32, bool)> {
    let mut entries = BTreeMap::new();
    for ancestor in Path::new(exec_path).ancestors() {
        let stock = if ancestor == Path::new("/Applications") {
            (0, ADMIN_GID, 0o40775, true)
        } else {
            (0, 0, 0o40755, true)
        };
        entries.insert(ancestor.to_path_buf(), stock);
    }
    entries.insert(
        Path::new(exec_path).join("git-credential-osxkeychain"),
        (0, 0, 0o100755, false),
    );
    entries
}

fn judge(exec_path: &str, entries: &BTreeMap<PathBuf, (u32, u32, u32, bool)>) -> bool {
    let helper = Path::new(exec_path).join("git-credential-osxkeychain");
    sealed(&helper, Path::new(exec_path), |path| {
        entries.get(path).map(|(uid, gid, mode, is_directory)| {
            if *is_directory {
                directory(*uid, *gid, *mode)
            } else {
                Entry {
                    uid: *uid,
                    gid: *gid,
                    mode: *mode,
                    directory: false,
                    file: true,
                }
            }
        })
    })
}

#[test]
fn root_owned_xcode_and_command_line_tools_helpers_are_trusted() {
    assert!(judge(XCODE_EXEC, &layout(XCODE_EXEC)));
    assert!(judge(CLT_EXEC, &layout(CLT_EXEC)));
    let beta = "/Applications/Xcode-beta.app/Contents/Developer/usr/libexec/git-core";
    assert!(judge(beta, &layout(beta)));
}

#[test]
fn user_owned_or_writable_developer_directories_are_not_trusted() {
    // An Xcode bundle copied in by the user, rather than installed as root.
    let mut entries = layout(XCODE_EXEC);
    entries.insert(
        PathBuf::from("/Applications/Xcode.app"),
        (501, 20, 0o40755, true),
    );
    assert!(!judge(XCODE_EXEC, &entries));
    // A group-writable directory inside the bundle.
    let mut entries = layout(XCODE_EXEC);
    entries.insert(PathBuf::from(XCODE_EXEC), (0, ADMIN_GID, 0o40775, true));
    assert!(!judge(XCODE_EXEC, &entries));
    // A world-writable /Applications.
    let mut entries = layout(XCODE_EXEC);
    entries.insert(
        PathBuf::from("/Applications"),
        (0, ADMIN_GID, 0o40777, true),
    );
    assert!(!judge(XCODE_EXEC, &entries));
    // A helper the user owns.
    let mut entries = layout(CLT_EXEC);
    entries.insert(
        Path::new(CLT_EXEC).join("git-credential-osxkeychain"),
        (501, 20, 0o100755, false),
    );
    assert!(!judge(CLT_EXEC, &entries));
}

#[test]
fn helpers_outside_an_apple_developer_directory_are_not_trusted() {
    for exec_path in [
        "/opt/homebrew/opt/git/libexec/git-core",
        "/Applications/Tools/Contents/Developer/usr/libexec/git-core",
        "/Users/dev/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core",
        "/Library/Developer/Toolchains/swift.xctoolchain/usr/libexec/git-core",
    ] {
        assert!(!judge(exec_path, &layout(exec_path)), "{exec_path}");
    }
    // A helper that is not directly in the exec path.
    let helper = Path::new(XCODE_EXEC).join("nested/git-credential-osxkeychain");
    let entries = layout(XCODE_EXEC);
    assert!(!sealed(&helper, Path::new(XCODE_EXEC), |path| {
        entries
            .get(path)
            .map(|(uid, gid, mode, _)| directory(*uid, *gid, *mode))
    }));
}

#[test]
fn shim_selectors_are_recognized_by_name() {
    let names = |values: &[&str]| -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    };
    assert!(names_select_shim(names(&["PATH", "DEVELOPER_DIR"]).iter()));
    assert!(names_select_shim(names(&["TOOLCHAINS"]).iter()));
    assert!(!names_select_shim(
        names(&["PATH", "HOME", "SDKROOT"]).iter()
    ));
    assert!(!selection_overridden(
        Path::new("/opt/homebrew/bin/git"),
        None
    ));
}
