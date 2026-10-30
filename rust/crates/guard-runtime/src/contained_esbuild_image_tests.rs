use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;

const MACH_O: &[u8] = b"\xcf\xfa\xed\xfe image";

/// A project whose `node_modules` holds esbuild `version` and this host's
/// binary with `image` bytes and `mode`.
fn project(version: &str, image: &[u8], mode: u32) -> tempfile::TempDir {
    let project = tempfile::tempdir().expect("project");
    let modules = project.path().join("node_modules");
    let manifest = modules.join("esbuild/package.json");
    fs::create_dir_all(manifest.parent().expect("parent")).expect("esbuild");
    let package = serde_json::json!({ "name": "esbuild", "version": version });
    fs::write(&manifest, package.to_string()).expect("manifest");
    let binary = modules
        .join("@esbuild")
        .join(format!("{}-{}", system().expect("os"), cpu().expect("cpu")))
        .join("bin/esbuild");
    fs::create_dir_all(binary.parent().expect("parent")).expect("bin");
    fs::write(&binary, image).expect("binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(mode)).expect("mode");
    project
}

#[test]
fn a_project_without_esbuild_needs_no_image() {
    let project = tempfile::tempdir().expect("project");
    let images = tempfile::tempdir().expect("images");
    assert!(snapshot(project.path(), images.path())
        .expect("no image")
        .is_none());
}

#[test]
fn the_image_is_a_private_copy_of_the_projects_binary() {
    let project = project("0.25.10", MACH_O, 0o755);
    let images = tempfile::tempdir().expect("images");
    let image = snapshot(project.path(), images.path())
        .expect("snapshot")
        .expect("image");
    assert_eq!(image.version, "0.25.10");
    assert_eq!(image.image, images.path().join("esbuild"));
    assert!(image.source.ends_with("bin/esbuild"));
    assert_eq!(fs::read(&image.image).expect("copy"), MACH_O);
    let mode = fs::metadata(&image.image).expect("copy").mode();
    assert_eq!(mode & 0o777, 0o500);
}

#[test]
fn a_shared_write_bit_under_a_private_directory_grants_nothing() {
    // A 0700 project directory keeps every other account from reaching the
    // 0777 image Bun-style unpacking leaves behind. The mode is set here:
    // a temporary directory under Linux's shared `/tmp` is created 0755.
    let project = project("0.25.10", MACH_O, 0o777);
    fs::set_permissions(project.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let images = tempfile::tempdir().expect("images");
    assert!(snapshot(project.path(), images.path())
        .expect("snapshot")
        .is_some());
}

#[test]
fn an_image_that_is_not_an_executable_release_is_refused() {
    for (version, image, mode) in [
        ("0.25.10", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ("0.25.10", MACH_O, 0o644),
        ("0.25.10", b"\xcf\xfa".as_slice(), 0o755),
        ("latest", MACH_O, 0o755),
        ("0.25", MACH_O, 0o755),
    ] {
        let project = project(version, image, mode);
        let images = tempfile::tempdir().expect("images");
        let failure = snapshot(project.path(), images.path()).err();
        assert_eq!(
            failure.map(|failure| failure.reason),
            Some(UNAVAILABLE.to_owned()),
            "{version} {mode:o}"
        );
        assert!(!images.path().join("esbuild").exists());
    }
}

#[test]
fn a_binary_outside_the_projects_modules_is_refused() {
    let project = project("0.25.10", MACH_O, 0o755);
    let outside = tempfile::tempdir().expect("outside");
    let elsewhere = outside.path().join("esbuild");
    fs::write(&elsewhere, MACH_O).expect("elsewhere");
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).expect("mode");
    let binary = project
        .path()
        .join("node_modules/@esbuild")
        .join(format!("{}-{}", system().expect("os"), cpu().expect("cpu")))
        .join("bin/esbuild");
    fs::remove_file(&binary).expect("binary");
    std::os::unix::fs::symlink(&elsewhere, &binary).expect("link");
    let images = tempfile::tempdir().expect("images");
    assert!(snapshot(project.path(), images.path()).is_err());
}

#[test]
fn a_release_version_is_three_short_numbers() {
    for version in ["0.25.10", "1.0.0", "12345678.0.1"] {
        assert!(release_version(version), "{version}");
    }
    for version in [
        "",
        "1.0",
        "1.0.0.0",
        "1.0.0-beta",
        "123456789.0.0",
        "a.b.c",
        "1..0",
    ] {
        assert!(!release_version(version), "{version}");
    }
}
