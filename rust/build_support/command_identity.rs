//! Shared implementation identity for the host compiler and target program.
//!
//! The checked-in input manifest keeps unrelated workspace crates outside
//! the fingerprint so edits in runtime-only domains stop invalidating the
//! command compiler, the packaged catalog and both producer executables.
//! The manifest is bound by contract tests to the real path-dependency
//! closure; a newly reachable input fails CI until it is classified.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", directory.display());
    let mut entries: Vec<_> = fs::read_dir(directory)
        .expect("native source directory")
        .map(|entry| entry.expect("native source entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let metadata = fs::symlink_metadata(&path).expect("native source metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "native source fingerprint rejects symlinks"
        );
        if metadata.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|v| v == "rs" || v == "json") {
            files.push(path);
        }
    }
}

fn manifest(root: &Path) -> Value {
    let path = root.join("build_support/command_source_inputs.v2.json");
    println!("cargo:rerun-if-changed={}", path.display());
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&path).expect("command source inputs manifest UTF-8"),
    )
    .expect("command source inputs manifest JSON");
    assert_eq!(
        manifest["schema"].as_str(),
        Some("guard.command-source-inputs.v2"),
        "command source inputs manifest schema"
    );
    manifest
}

fn relative_file(root: &Path, entry: &Value, files: &mut Vec<PathBuf>) {
    let relative = entry.as_str().expect("command source inputs file path");
    assert!(
        !relative.is_empty()
            && !relative.starts_with('/')
            && !relative.starts_with('\\')
            && !relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "command source inputs file must stay inside the workspace"
    );
    let path = root.join(relative);
    assert!(path.is_file(), "command source inputs file must exist");
    files.push(path);
}

fn crate_inputs(root: &Path, entry: &Value, files: &mut Vec<PathBuf>) {
    let name = entry.as_str().expect("command source inputs crate name");
    assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "command source inputs crate name"
    );
    let directory = root.join("crates").join(name);
    // Cargo manifests and each production src directory below are watched.
    // Watching the entire crates directory would also invalidate this build
    // for portable test fixtures, recreating the fixture/recompile cycle.
    let manifest = directory.join("Cargo.toml");
    assert!(manifest.is_file(), "command source inputs crate manifest");
    files.push(manifest);
    let build = directory.join("build.rs");
    if build.is_file() {
        files.push(build);
    }
    if directory.join("src").is_dir() {
        collect(&directory.join("src"), files);
    }
}

fn crate_file_inputs(root: &Path, name: &str, entries: &Value, files: &mut Vec<PathBuf>) {
    assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "command source inputs crate_files name"
    );
    let directory = root.join("crates").join(name);
    // A crate named here contributes only the sources listed, but the compiler
    // built from it still reads its own manifest and build script. Leaving
    // those out lets a dependency feature or an entrypoint change alter the
    // producer while the identity stays put, and a stale pack is then reused.
    let manifest = directory.join("Cargo.toml");
    assert!(
        manifest.is_file(),
        "command source inputs crate_files crate manifest"
    );
    files.push(manifest);
    let build = directory.join("build.rs");
    if build.is_file() {
        files.push(build);
    }
    for entry in entries
        .as_array()
        .expect("command source inputs crate_files")
    {
        let relative = entry
            .as_str()
            .expect("command source inputs crate_files path");
        assert!(
            !relative.is_empty()
                && !relative.starts_with('/')
                && !relative.starts_with('\\')
                && !relative
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == ".."),
            "command source inputs crate_files must stay inside the crate"
        );
        let path = directory.join(relative);
        assert!(
            path.is_file(),
            "command source inputs crate file must exist"
        );
        files.push(path);
    }
}

pub fn emit(root: &Path) -> String {
    println!("cargo:rustc-check-cfg=cfg(guard_source_bootstrap)");
    let manifest = manifest(root);
    let domain = manifest["identity_domain"]
        .as_str()
        .expect("command source inputs identity domain");
    let mut files = vec![root.join("Cargo.lock"), root.join("Cargo.toml")];
    for entry in manifest["files"]
        .as_array()
        .expect("command source inputs files")
    {
        relative_file(root, entry, &mut files);
    }
    for entry in manifest["crates"]
        .as_array()
        .expect("command source inputs crates")
    {
        crate_inputs(root, entry, &mut files);
    }
    if let Some(partial) = manifest["crate_files"].as_object() {
        for (name, entries) in partial {
            crate_file_inputs(root, name, entries, &mut files);
        }
    }
    files.sort_by_cached_key(|path| {
        path.strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/")
    });
    files.dedup();
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        assert!(
            !fs::symlink_metadata(&path)
                .expect("source metadata")
                .file_type()
                .is_symlink(),
            "native source fingerprint rejects symlinks"
        );
        let name = path
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let content = fs::read_to_string(&path)
            .expect("native source UTF-8")
            .replace("\r\n", "\n");
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((content.len() as u64).to_be_bytes());
        hasher.update(content.as_bytes());
    }
    let identity = format!("{:x}", hasher.finalize());
    println!("cargo:rustc-env=GUARD_COMMAND_SOURCE_IMPLEMENTATION={identity}");
    identity
}
