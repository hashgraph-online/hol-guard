//! Shared implementation identity for the host compiler and target program.
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

pub fn emit(root: &Path) -> String {
    println!("cargo:rustc-check-cfg=cfg(guard_source_bootstrap)");
    let mut files = vec![root.join("Cargo.lock"), root.join("Cargo.toml")];
    let mut crates: Vec<_> = fs::read_dir(root.join("crates"))
        .expect("native crates")
        .map(|entry| entry.expect("native crate").path())
        .collect();
    crates.sort();
    println!("cargo:rerun-if-changed={}", root.join("crates").display());
    for directory in crates {
        if directory.join("Cargo.toml").is_file() {
            files.push(directory.join("Cargo.toml"));
        }
        if directory.join("build.rs").is_file() {
            files.push(directory.join("build.rs"));
        }
        if directory.join("src").is_dir() {
            collect(&directory.join("src"), &mut files);
        }
    }
    collect(&root.join("build_support"), &mut files);
    files.sort_by_cached_key(|path| {
        path.strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/")
    });
    files.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard.native-source-implementation.v1\0");
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
