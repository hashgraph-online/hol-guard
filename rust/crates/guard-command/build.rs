//! Bind source compilation to native implementation and locked dependencies.
use sha2::{Digest, Sha256};
use std::{
    env, fs,
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
        } else if path
            .extension()
            .is_some_and(|value| value == "rs" || value == "json")
        {
            files.push(path);
        }
    }
}

fn main() {
    let package = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = package.parent().unwrap().parent().unwrap();
    // The embedded program lives outside the Cargo workspace. Track it for
    // rebuilds, but exclude generated output from its own implementation hash.
    println!(
        "cargo:rerun-if-changed={}",
        root.parent()
            .unwrap()
            .join("contracts/extensions/native-command-program.v1.json")
            .display()
    );
    let mut files = vec![
        root.join("Cargo.lock"),
        root.join("Cargo.toml"),
        package.join("build.rs"),
    ];
    let mut crates: Vec<_> = fs::read_dir(root.join("crates"))
        .expect("native crates")
        .map(|entry| entry.expect("native crate").path())
        .collect();
    crates.sort();
    println!("cargo:rerun-if-changed={}", root.join("crates").display());
    for directory in crates {
        if directory.join("src").is_dir() {
            files.push(directory.join("Cargo.toml"));
            if directory.join("build.rs").is_file() {
                files.push(directory.join("build.rs"));
            }
            collect(&directory.join("src"), &mut files);
        }
    }
    files.sort();
    files.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard.native-source-implementation.v1\0");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
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
    println!(
        "cargo:rustc-env=GUARD_COMMAND_SOURCE_IMPLEMENTATION={:x}",
        hasher.finalize()
    );
}
