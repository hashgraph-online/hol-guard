//! Compute the rule-contract component digests at build time so the packaged
//! runtime embeds hashes instead of the component source bytes.
use sha2::{Digest, Sha256};
use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const PROGRAM_COMPONENT: &str = "native-command-program-artifact";

const COMPONENTS: &str = include_str!("component-inputs.tsv");

fn component_bytes(root: &Path, path: &Path) -> Vec<u8> {
    let relative = path
        .strip_prefix(root)
        .expect("component inside source tree");
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part);
        assert!(
            !fs::symlink_metadata(&current)
                .expect("component metadata")
                .file_type()
                .is_symlink(),
            "component must not traverse symlinks"
        );
    }
    let metadata = fs::metadata(path).expect("component metadata");
    assert!(
        metadata.is_file() && metadata.len() <= MAX_INPUT_BYTES,
        "component size/type invalid"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read(path).expect("component bytes")
}

fn main() {
    let package = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = package
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .expect("repository root");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let mut digests = String::from("const COMPONENT_DIGESTS: &[(&str, &str)] = &[");
    let mut sources = String::from("const COMPONENT_SOURCES: &[(&str, &[u8])] = &[");
    println!("cargo:rerun-if-changed=component-inputs.tsv");
    for line in COMPONENTS.lines() {
        let (name, relative) = line.split_once('\t').expect("component name/path pair");
        if name == PROGRAM_COMPONENT {
            write!(digests, "({name:?},{:?}),", "").unwrap();
            write!(sources, "({name:?},&[]),").unwrap();
            continue;
        }
        let path = package.join(relative);
        let bytes = component_bytes(root, &path);
        write!(
            digests,
            "({name:?},{:?}),",
            hex::encode(Sha256::digest(&bytes))
        )
        .unwrap();
        write!(
            sources,
            "({name:?},include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"),\"/{relative}\"))),"
        )
        .unwrap();
    }
    digests.push_str("];\n");
    sources.push_str("];\n");
    fs::write(out.join("rule_components.rs"), digests).expect("write rule components");
    fs::write(out.join("rule_component_sources.rs"), sources)
        .expect("write rule component sources");
}
