use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{observe, run_command, Hashing, Outcome};
use crate::runtime_identity_probe_layout::{hint_for, strict_version};

fn probe(paths: &[&str]) -> Value {
    let reply = run_command(json!({"paths": paths}).to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], true, "{reply}");
    reply["result"].clone()
}

fn probe_error(request: Value) -> String {
    let reply = run_command(request.to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], false, "{reply}");
    reply["error"].as_str().unwrap().to_owned()
}

fn write(root: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn artifact_of(result: &Value, index: usize) -> &Value {
    let id = result["observations"][index]["artifact_id"]
        .as_str()
        .expect("artifact");
    result["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["artifact_id"] == id)
        .expect("artifact listed")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn layouts_name_family_and_version() {
    let node = |path: &str| {
        let hint = hint_for(path);
        (hint.family, hint.version)
    };
    let cases = [
        (
            "/home/u/.nvm/versions/node/v20.11.1/bin/node",
            Some("20.11.1"),
        ),
        ("/opt/homebrew/Cellar/node/22.3.0/bin/node", Some("22.3.0")),
        (
            "/opt/homebrew/Cellar/node@20/20.15.0_1/bin/node",
            Some("20.15.0"),
        ),
        (
            "/home/u/.fnm/node-versions/v18.19.0/installation/bin/node",
            Some("18.19.0"),
        ),
        (
            "/home/u/.asdf/installs/nodejs/20.11.1/bin/node",
            Some("20.11.1"),
        ),
        (
            "/home/u/.volta/tools/image/node/20.11.1/bin/node",
            Some("20.11.1"),
        ),
        ("/opt/node-v22.4.1-linux-x64/bin/node", Some("22.4.1")),
        ("C:\\Program Files\\nodejs\\node.exe", None),
        ("/usr/local/bin/node", None),
    ];
    for (path, version) in cases {
        assert_eq!(
            node(path),
            (Some("node"), version.map(str::to_owned)),
            "{path}"
        );
        // A bare system path may hold a distribution build with backports.
        assert_eq!(hint_for(path).vendor, version.and(Some("nodejs.org")));
    }
    assert_eq!(hint_for("/usr/bin/python3.12").vendor, None);
    assert_eq!(hint_for("/x/node/v20.11/bin/node").vendor, None);
}

#[test]
fn python_names_and_layouts() {
    let hint = hint_for("/usr/bin/python3.12");
    assert_eq!(
        (hint.family, hint.version.as_deref()),
        (Some("python"), Some("3.12"))
    );
    let hint = hint_for("/usr/bin/python3");
    assert_eq!((hint.family, hint.version), (Some("python"), None));
    let hint = hint_for("/opt/homebrew/Cellar/python@3.12/3.12.4/bin/python3.12");
    assert_eq!(hint.version.as_deref(), Some("3.12.4"));
    let hint = hint_for("/home/u/.pyenv/versions/3.11.9/bin/python");
    assert_eq!(hint.version.as_deref(), Some("3.11.9"));
    let hint =
        hint_for("/home/u/.local/share/uv/python/cpython-3.12.4-macos-aarch64-none/bin/python3");
    assert_eq!(hint.version.as_deref(), Some("3.12.4"));
    // The name says 3.12 and the directory says 3.11: neither is believed.
    let hint = hint_for("/home/u/.pyenv/versions/3.11.9/bin/python3.12");
    assert_eq!((hint.family, hint.version), (Some("python"), None));
}

#[test]
fn unknown_names_and_malformed_versions_stay_unknown() {
    assert_eq!(hint_for("/usr/bin/ruby").family, None);
    assert_eq!(hint_for("/x/node/v20.11/bin/tool").family, None);
    assert_eq!(hint_for("/x/node/v20.11/bin/node").version, None);
    assert_eq!(hint_for("/x/node/v020.11.1/bin/node").version, None);
    assert_eq!(strict_version("1.2.3_x"), None);
    assert_eq!(strict_version("1.2.3.4"), None);
    assert_eq!(strict_version("v1.2.3_2").as_deref(), Some("1.2.3"));
}

#[test]
fn layout_inferred_runtime_is_self_reported_with_hash() {
    let dir = tempfile::tempdir().unwrap();
    let body = b"not really node";
    let path = write(dir.path(), ".nvm/versions/node/v20.11.1/bin/node", body);
    let path_text = path.to_str().unwrap();
    let result = probe(&[path_text]);

    let artifact = artifact_of(&result, 0);
    assert_eq!(artifact["family"], "node");
    assert_eq!(artifact["version"], "20.11.1");
    assert_eq!(artifact["identity_assurance"], "self_reported");
    assert_eq!(artifact["executable_sha256"], sha256_hex(body));
    assert_eq!(artifact["vendor"], "nodejs.org");
    assert_eq!(result["locations"][0]["state"], "present");
    assert_eq!(
        result["observations"][0]["resolved_path"],
        fs::canonicalize(&path).unwrap().to_str().unwrap()
    );

    // Same input, same identifiers, and no raw path inside them.
    assert_eq!(probe(&[path_text]), result);
    let ids = format!(
        "{}{}",
        result["locations"][0]["location_id"], artifact["artifact_id"]
    );
    assert!(!ids.contains(dir.path().to_str().unwrap()));
}

#[test]
fn nothing_inferable_is_unknown_assurance() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "bin/mystery-tool", b"#!/bin/sh\n");
    let result = probe(&[path.to_str().unwrap()]);
    let artifact = artifact_of(&result, 0);
    assert_eq!(artifact["family"], "unknown");
    assert_eq!(artifact["version"], Value::Null);
    assert_eq!(artifact["identity_assurance"], "unknown");
    assert_eq!(artifact["arch"], "unknown");
}

#[test]
fn spoofed_version_never_exceeds_self_reported() {
    let dir = tempfile::tempdir().unwrap();
    // Path, file name and contents all claim a fixed vendor release.
    let path = write(
        dir.path(),
        "versions/node/v22.4.1/bin/node",
        b"node v22.4.1 vendor_verified locally_trusted",
    );
    let result = probe(&[path.to_str().unwrap()]);
    let artifact = artifact_of(&result, 0);
    assert_eq!(artifact["version"], "22.4.1");
    assert_eq!(artifact["identity_assurance"], "self_reported");

    // The assessment cannot use it to clear the runtime either.
    let request = json!({
        "artifacts": result["artifacts"], "locations": result["locations"],
        "advisories": [{
            "advisory_id": "ADV-1", "family": "node", "vendor": "nodejs",
            "version_scheme": "semver",
            "ranges": [{"introduced": "22.0.0", "fixed": "22.4.1"}],
        }],
    });
    let reply = crate::runtime_identity::run_command(request.to_string().as_bytes()).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    // Another vendor's rule yields no match row; either way, never cleared.
    let status = reply["result"]["artifacts"][0]["matches"][0]["status"].as_str();
    assert_ne!(status, Some("not_affected"));
    assert_ne!(
        reply["result"]["advisories"][0]["verdict"],
        "fixed_verified"
    );

    // Its layout vendor flags an in-range build of the upstream release, but
    // a self-reported vendor still cannot clear an out-of-range one.
    for (fixed, expected) in [("22.5.0", "affected"), ("22.4.1", "unknown")] {
        let rule = json!({"advisory_id": "ADV-2", "family": "node", "vendor": "nodejs.org",
            "version_scheme": "semver", "ranges": [{"introduced": "22.0.0", "fixed": fixed}]});
        let request = json!({"artifacts": result["artifacts"],
            "locations": result["locations"], "advisories": [rule]});
        let reply = crate::runtime_identity::run_command(request.to_string().as_bytes()).unwrap();
        let row = &reply["result"]["artifacts"][0]["matches"][0];
        assert_eq!(row["status"], expected);
    }
}

#[test]
fn identical_binaries_in_different_layouts_keep_separate_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let a = write(dir.path(), "a/node/v20.11.1/bin/node", b"same");
    let b = write(dir.path(), "b/node/v22.3.0/bin/node", b"same");
    let result = probe(&[
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        a.to_str().unwrap(),
    ]);
    assert_eq!(result["artifacts"].as_array().unwrap().len(), 2);
    assert_eq!(result["locations"].as_array().unwrap().len(), 2);
}

#[test]
fn missing_path_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nope/node");
    let result = probe(&[path.to_str().unwrap()]);
    assert_eq!(result["locations"][0]["state"], "missing");
    assert_eq!(result["locations"][0]["artifact_id"], Value::Null);
    assert_eq!(result["artifacts"].as_array().unwrap().len(), 0);
}

#[test]
fn directories_and_oversized_files_are_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big/node");
    fs::create_dir_all(big.parent().unwrap()).unwrap();
    let file = fs::File::create(&big).unwrap();
    file.set_len(super::MAX_HASH_BYTES + 1).unwrap();
    let result = probe(&[dir.path().to_str().unwrap(), big.to_str().unwrap()]);
    assert_eq!(result["observations"][0]["state"], "unknown");
    assert_eq!(result["observations"][0]["reason"], "not_regular_file");
    assert_eq!(result["observations"][1]["state"], "unknown");
    assert_eq!(result["observations"][1]["reason"], "too_large");
    assert_eq!(result["artifacts"].as_array().unwrap().len(), 0);
}

#[cfg(unix)]
#[test]
fn symlinks_resolve_to_the_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = write(dir.path(), "Cellar/node/22.3.0/bin/node", b"payload");
    let bin = dir.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let link = bin.join("node");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let result = probe(&[link.to_str().unwrap()]);
    assert_eq!(
        result["observations"][0]["resolved_path"],
        fs::canonicalize(&real).unwrap().to_str().unwrap()
    );
    let artifact = artifact_of(&result, 0);
    assert_eq!(artifact["version"], "22.3.0");
    assert_eq!(artifact["executable_sha256"], sha256_hex(b"payload"));
}

#[cfg(unix)]
#[test]
fn fifo_is_unknown_and_not_opened() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("node");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let result = probe(&[fifo.to_str().unwrap()]);
    assert_eq!(result["observations"][0]["state"], "unknown");
    assert_eq!(result["observations"][0]["reason"], "not_regular_file");
}

#[cfg(unix)]
#[test]
fn probing_never_executes_the_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("ran");
    let script = format!("#!/bin/sh\ntouch '{}'\necho v20.11.1\n", sentinel.display());
    let path = write(
        dir.path(),
        "versions/node/v20.11.1/bin/node",
        script.as_bytes(),
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let result = probe(&[path.to_str().unwrap()]);
    assert_eq!(result["observations"][0]["state"], "present");
    assert!(!sentinel.exists(), "probe launched the file");
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_unknown() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "node", b"x");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&path).is_ok() {
        return; // running as a user that ignores file modes
    }
    let result = probe(&[path.to_str().unwrap()]);
    assert_eq!(result["observations"][0]["state"], "unknown");
    assert_eq!(result["observations"][0]["reason"], "unreadable");
}

#[test]
fn headers_set_os_and_arch() {
    let dir = tempfile::tempdir().unwrap();
    let mut elf = vec![0_u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
    let mut macho = vec![0_u8; 32];
    macho[..4].copy_from_slice(&0xcffa_edfe_u32.to_be_bytes());
    macho[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
    let mut java = vec![0_u8; 32];
    java[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
    java[4..8].copy_from_slice(&0x0000_0034_u32.to_be_bytes());
    let paths: Vec<String> = [("elf", elf), ("macho", macho), ("class", java)]
        .into_iter()
        .map(|(name, bytes)| write(dir.path(), &format!("{name}/node"), &bytes))
        .map(|p| p.to_str().unwrap().to_owned())
        .collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let result = probe(&refs);
    let elf = artifact_of(&result, 0);
    assert_eq!(
        (elf["os"].as_str(), elf["arch"].as_str()),
        (Some("linux"), Some("arm64"))
    );
    let macho = artifact_of(&result, 1);
    assert_eq!(
        (macho["os"].as_str(), macho["arch"].as_str()),
        (Some("macos"), Some("arm64"))
    );
    assert_eq!(artifact_of(&result, 2)["arch"], "unknown");
}

/// A fat header: magic, entry count, then `count` entries of `entry` bytes
/// whose first holds a cpu type, an offset past the table and an alignment.
fn universal(magic: u32, count: u32, wide: bool) -> Vec<u8> {
    let entry = if wide { 32 } else { 20 };
    let table_end = 8 + count as usize * entry;
    let mut bytes = vec![0_u8; table_end.max(64)];
    bytes[..4].copy_from_slice(&magic.to_be_bytes());
    bytes[4..8].copy_from_slice(&count.to_be_bytes());
    bytes[8..12].copy_from_slice(&0x0100_000c_u32.to_be_bytes());
    let offset = (table_end as u64).next_multiple_of(0x4000);
    if wide {
        bytes[16..24].copy_from_slice(&offset.to_be_bytes());
        bytes[32..36].copy_from_slice(&14_u32.to_be_bytes());
    } else {
        bytes[16..20].copy_from_slice(&(offset as u32).to_be_bytes());
        bytes[24..28].copy_from_slice(&14_u32.to_be_bytes());
    }
    bytes
}

#[test]
fn universal_binaries_are_recognised_in_both_widths_and_any_count() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        ("fat", universal(0xcafe_babe, 2, false)),
        ("fat-many", universal(0xcafe_babe, 12, false)),
        ("fat64", universal(0xcafe_babf, 2, true)),
        ("fat64-many", universal(0xcafe_babf, 30, true)),
    ];
    for (name, bytes) in cases {
        let path = write(dir.path(), &format!("{name}/node"), &bytes);
        let result = probe(&[path.to_str().unwrap()]);
        let artifact = artifact_of(&result, 0);
        assert_eq!(
            (artifact["os"].as_str(), artifact["arch"].as_str()),
            (Some("macos"), Some("universal")),
            "{name}"
        );
    }
}

#[test]
fn java_class_with_a_plausible_version_is_not_universal() {
    let dir = tempfile::tempdir().unwrap();
    // Major version 65 reads as an entry count in range; the entry table is not.
    let mut java = vec![0xa5_u8; 512];
    java[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
    java[4..8].copy_from_slice(&65_u32.to_be_bytes());
    let path = write(dir.path(), "class/node", &java);
    let result = probe(&[path.to_str().unwrap()]);
    assert_eq!(artifact_of(&result, 0)["arch"], "unknown");
}

#[cfg(unix)]
#[test]
fn aliases_of_one_file_are_hashed_once() {
    let dir = tempfile::tempdir().unwrap();
    let real = write(dir.path(), "real/node", b"payload");
    let mut hashing = Hashing::default();
    let mut ids = Vec::new();
    for alias in ["a", "b", "c"] {
        let link = dir.path().join(alias);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        match observe(link.to_str().unwrap(), &mut hashing) {
            Outcome::Present { artifact, .. } => ids.push(artifact["artifact_id"].clone()),
            _ => panic!("alias not present"),
        }
    }
    assert_eq!(hashing.done.len(), 1);
    assert_eq!(hashing.remaining, super::MAX_TOTAL_HASH_BYTES - 7);
    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn hashing_stops_when_the_request_budget_is_spent() {
    let dir = tempfile::tempdir().unwrap();
    let first = write(dir.path(), "one/node", b"12345678");
    let second = write(dir.path(), "two/node", b"87654321");
    let mut hashing = Hashing {
        remaining: 10,
        ..Hashing::default()
    };
    assert!(matches!(
        observe(first.to_str().unwrap(), &mut hashing),
        Outcome::Present { .. }
    ));
    match observe(second.to_str().unwrap(), &mut hashing) {
        Outcome::Unknown { reason, .. } => assert_eq!(reason, "hash_budget_exhausted"),
        _ => panic!("budget not enforced"),
    }
}

#[test]
fn hashing_charges_bytes_read_and_needs_room_to_prove_eof() {
    let dir = tempfile::tempdir().unwrap();
    let empty = write(dir.path(), "empty/node", b"");
    let mut hashing = Hashing {
        remaining: 0,
        ..Hashing::default()
    };
    match observe(empty.to_str().unwrap(), &mut hashing) {
        Outcome::Unknown { reason, .. } => assert_eq!(reason, "hash_budget_exhausted"),
        _ => panic!("an empty file was hashed without an EOF read"),
    }
    hashing.remaining = 1;
    assert!(matches!(
        observe(empty.to_str().unwrap(), &mut hashing),
        Outcome::Present { .. }
    ));
    assert_eq!(hashing.remaining, 1);
    let full = write(dir.path(), "full/node", b"1234");
    hashing.remaining = 4;
    match observe(full.to_str().unwrap(), &mut hashing) {
        Outcome::Unknown { reason, .. } => assert_eq!(reason, "hash_budget_exhausted"),
        _ => panic!("a file was hashed without room for the EOF read"),
    }
    hashing.remaining = 5;
    assert!(matches!(
        observe(full.to_str().unwrap(), &mut hashing),
        Outcome::Present { .. }
    ));
    assert_eq!(hashing.remaining, 1);
}

#[test]
fn requests_are_validated_and_bounded() {
    let malformed = json!({"paths": ["a"], "extra": 1}).to_string();
    assert_eq!(
        run_command(malformed.as_bytes()).unwrap_err(),
        "runtime_identity_probe_request_invalid"
    );
    assert_eq!(
        probe_error(json!({"paths": [""]})),
        "runtime_identity_probe_path_invalid"
    );
    assert_eq!(
        probe_error(json!({"paths": ["a\u{0}b"]})),
        "runtime_identity_probe_path_invalid"
    );
    assert_eq!(
        probe_error(json!({"paths": ["node_modules/.bin/node"]})),
        "runtime_identity_probe_path_invalid"
    );
    let many: Vec<String> = (0..=super::MAX_PATHS).map(|i| format!("/x/{i}")).collect();
    assert_eq!(
        probe_error(json!({"paths": many})),
        "runtime_identity_probe_too_many_paths"
    );
}
