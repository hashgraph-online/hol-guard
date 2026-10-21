//! Dependency-closure evidence fails closed on malformed or oversized images.
use super::evaluate_with_deadline;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Image<'a> {
    library: bool,
    needed: &'a [&'a str],
    soname: Option<&'a str>,
    entry: u64,
    pie: bool,
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    (directory, root)
}

fn program(bytes: &mut Vec<u8>, kind: u32, flags: u32, offset: u64, size: u64, align: u64) {
    bytes.extend(kind.to_le_bytes());
    bytes.extend(flags.to_le_bytes());
    for value in [offset, offset, 0, size, size, align] {
        bytes.extend(value.to_le_bytes());
    }
}

fn image(path: &Path, spec: Image) -> PathBuf {
    let mut strings = vec![0u8];
    let mut dynamic = vec![];
    let names = spec.needed.iter().map(|name| (1u64, *name));
    for (tag, name) in names.chain(spec.soname.map(|name| (14u64, name))) {
        dynamic.push((tag, strings.len() as u64));
        strings.extend(name.as_bytes());
        strings.push(0);
    }
    if spec.pie {
        dynamic.push((0x6fff_fffb, 0x0800_0000));
    }
    let table = 176 + (dynamic.len() as u64 + 3) * 16;
    dynamic.extend([(5, table), (10, strings.len() as u64), (0, 0)]);
    let mut tail = vec![];
    for (tag, value) in &dynamic {
        tail.extend(tag.to_le_bytes());
        tail.extend(value.to_le_bytes());
    }
    tail.extend(strings);
    let mut bytes = b"\x7fELF\x02\x01\x01".to_vec();
    bytes.extend([0u8; 9]);
    bytes.extend((if spec.library { 3u16 } else { 2u16 }).to_le_bytes());
    bytes.extend(62u16.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(spec.entry.to_le_bytes());
    bytes.extend(64u64.to_le_bytes());
    bytes.extend(0u64.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(64u16.to_le_bytes());
    bytes.extend(56u16.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend([0u8; 6]);
    // The load segment maps the whole file at address zero, so the string
    // table address doubles as its file offset.
    program(&mut bytes, 1, 5, 0, 176 + tail.len() as u64, 4096);
    program(&mut bytes, 2, 4, 176, dynamic.len() as u64 * 16, 8);
    bytes.extend(tail);
    fs::write(path, bytes).unwrap();
    path.to_path_buf()
}

fn evidence(root: &Path, images: &[&Path], files: &[&Path], limits: Value) -> Value {
    let mut input = json!({
        "images": images,
        "read_files": files,
        "runtime_roots": [],
        "workspace": root,
    });
    for (name, value) in limits.as_object().unwrap() {
        input[name] = value.clone();
    }
    evaluate_with_deadline(
        "mapping_evidence",
        &input,
        Instant::now() + Duration::from_secs(10),
    )
}

fn mapped(result: &Value) -> Vec<&str> {
    result["value"]
        .as_array()
        .unwrap_or_else(|| panic!("mapping refused: {result}"))
        .iter()
        .map(|record| record["path"].as_str().unwrap())
        .collect()
}

fn refused(result: &Value) {
    assert_eq!(
        result,
        &json!({
            "reason_code": "linux_mapping_unavailable",
            "message": "Linux executable mapping evidence could not be verified."
        })
    );
}

#[test]
fn a_large_string_table_reads_only_bounded_dependency_names() {
    let (_directory, root) = root();
    let library = image(
        &root.join("ordinary.so"),
        Image {
            library: true,
            ..Image::default()
        },
    );
    let runner = image(
        &root.join("runner"),
        Image {
            needed: &["ordinary.so"],
            ..Image::default()
        },
    );
    let mut raw = fs::read(&runner).unwrap();
    let padding = 2 * 1024 * 1024;
    raw.resize(raw.len() + padding, 0);
    let length = (raw.len() as u64).to_le_bytes();
    // PT_LOAD file and memory sizes, then the DT_STRSZ value.
    raw[96..104].copy_from_slice(&length);
    raw[104..112].copy_from_slice(&length);
    let size = u64::from_le_bytes(raw[216..224].try_into().unwrap()) + padding as u64;
    raw[216..224].copy_from_slice(&size.to_le_bytes());
    fs::write(&runner, raw).unwrap();
    let result = evidence(&root, &[&runner], &[&library], json!({}));
    assert_eq!(
        mapped(&result),
        [library.to_str().unwrap(), runner.to_str().unwrap()]
    );
}

#[test]
fn a_program_shaped_library_cannot_claim_the_system_libc_exception() {
    let (_directory, root) = root();
    let fake = image(
        &root.join("libc.so.6"),
        Image {
            library: true,
            soname: Some("libc.so.6"),
            entry: 4096,
            pie: true,
            ..Image::default()
        },
    );
    for system_library in [false, true] {
        let result = evaluate_with_deadline(
            "mapping_elf",
            &json!({"path": fake, "library": true, "system_library": system_library}),
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(
            result["message"], "Program image is not a shared-library mapping exception.",
            "system_library={system_library}"
        );
    }
    let real = image(
        &root.join("binding.node"),
        Image {
            library: true,
            entry: 4096,
            ..Image::default()
        },
    );
    let result = evidence(&root, &[], &[&real], json!({}));
    assert_eq!(mapped(&result), [real.to_str().unwrap()]);
}

#[test]
fn an_invalid_optional_module_stays_unmapped_without_blocking_the_runner() {
    for content in [&b"library placeholder"[..], b"\x7fELFtruncated"] {
        let (_directory, root) = root();
        let runner = image(&root.join("runner"), Image::default());
        let optional = root.join("unused.node");
        fs::write(&optional, content).unwrap();
        let result = evidence(&root, &[&runner], &[&optional], json!({}));
        assert_eq!(mapped(&result), [runner.to_str().unwrap()]);
    }
}

#[test]
fn an_oversized_optional_library_stays_unmapped_without_blocking_the_runner() {
    let (_directory, root) = root();
    let runner = image(&root.join("runner"), Image::default());
    let optional = image(
        &root.join("unused.so"),
        Image {
            library: true,
            ..Image::default()
        },
    );
    let mut raw = fs::read(&optional).unwrap();
    raw.extend([0u8; 1024]);
    fs::write(&optional, raw).unwrap();
    let limit = fs::metadata(&runner).unwrap().len() + 1;
    let result = evidence(
        &root,
        &[&runner],
        &[&optional],
        json!({"max_file_bytes": limit}),
    );
    assert_eq!(mapped(&result), [runner.to_str().unwrap()]);
    let result = evidence(&root, &[&runner], &[&optional], json!({}));
    assert_eq!(
        mapped(&result),
        [runner.to_str().unwrap(), optional.to_str().unwrap()]
    );
}

#[test]
fn an_invalid_required_module_blocks_execution() {
    let (_directory, root) = root();
    let runner = image(
        &root.join("runner"),
        Image {
            needed: &["required.so"],
            ..Image::default()
        },
    );
    let required = root.join("required.so");
    fs::write(&required, "library placeholder").unwrap();
    refused(&evidence(&root, &[&runner], &[&required], json!({})));
}

#[test]
fn the_mapping_budget_fails_closed() {
    let (_directory, root) = root();
    let runner = image(&root.join("runner"), Image::default());
    let size = fs::metadata(&runner).unwrap().len();
    let result = evidence(&root, &[&runner], &[], json!({"max_mapping_bytes": size}));
    assert_eq!(mapped(&result), [runner.to_str().unwrap()]);
    refused(&evidence(
        &root,
        &[&runner],
        &[],
        json!({"max_mapping_bytes": size - 1}),
    ));
}

#[test]
fn an_unresolved_symlink_cannot_be_admitted_as_a_program() {
    let (_directory, root) = root();
    let runner = image(&root.join("runner"), Image::default());
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&runner, &alias).unwrap();
    refused(&evidence(&root, &[&alias], &[], json!({})));
}

#[test]
fn a_dependency_on_an_already_approved_loader_is_not_reclassified_as_library() {
    let (_directory, root) = root();
    let loader = image(
        &root.join("aaa-loader.so"),
        Image {
            entry: 4096,
            ..Image::default()
        },
    );
    let runner = image(
        &root.join("zzz-runner"),
        Image {
            needed: &["aaa-loader.so"],
            ..Image::default()
        },
    );
    let result = evidence(&root, &[&loader, &runner], &[&loader], json!({}));
    assert_eq!(
        mapped(&result),
        [loader.to_str().unwrap(), runner.to_str().unwrap()]
    );
}
