//! Launcher resolution against a caller-supplied `PATH`.

use super::*;

#[test]
fn windows_pathext_is_applied_like_shutil_which() {
    let pathext = ".COM;.EXE;.BAT;.CMD";
    assert_eq!(
        windows_launcher_file_names("npx", pathext),
        vec!["npx.COM", "npx.EXE", "npx.BAT", "npx.CMD"]
    );
    assert_eq!(
        windows_launcher_file_names("npx.cmd", pathext),
        vec!["npx.cmd"]
    );
    assert_eq!(
        windows_launcher_file_names("NPX.CMD", pathext),
        vec!["NPX.CMD"]
    );
}

#[test]
fn shim_directories_are_recognised() {
    assert!(is_guard_package_shim_dir(
        Path::new("/home/a/.hol-guard/package-shims/bin/"),
        None
    ));
    assert!(!is_guard_package_shim_dir(
        Path::new("/usr/local/bin"),
        None
    ));
}

#[cfg(windows)]
#[test]
fn windows_shim_directories_compare_with_posix_separators() {
    assert!(is_guard_package_shim_dir(
        Path::new("C:\\Users\\a\\.hol-guard\\package-shims\\bin"),
        None
    ));
}

#[cfg(windows)]
#[test]
fn windows_semicolon_path_resolves_a_cmd_launcher() {
    let root = std::env::temp_dir().join(format!("hol-guard-launcher-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("npx.cmd"), "@echo off\r\n").unwrap();
    let path_value = format!("C:\\missing;{}", root.display());
    let resolved = resolved_package_launcher_executable_in("npx", &path_value, None);
    assert_eq!(resolved, Some(root.join("npx.cmd").canonicalize().unwrap()));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn caller_path_uses_the_platform_separator_and_skips_shims() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("hol-guard-launcher-{}", std::process::id()));
    let shims = root.join(".hol-guard").join("package-shims").join("bin");
    let real = root.join("real");
    std::fs::create_dir_all(&shims).unwrap();
    std::fs::create_dir_all(&real).unwrap();
    for dir in [&shims, &real] {
        let launcher = dir.join("npx");
        std::fs::write(&launcher, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path_value = std::env::join_paths([shims.as_path(), real.as_path()]).unwrap();
    let resolved = resolved_package_launcher_executable_in(
        "npx",
        &path_value.to_string_lossy(),
        Some(root.as_path()),
    );
    assert_eq!(resolved, Some(real.join("npx").canonicalize().unwrap()));
    let _ = std::fs::remove_dir_all(root);
}
