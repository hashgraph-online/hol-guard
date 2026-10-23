use super::ProviderQuotaWriter;
use crate::read_provider_quota_snapshot;
use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/python_provider_quota_v1.json"
    ))
    .unwrap()
}

fn case<'a>(frozen: &'a Value, name: &str) -> &'a Value {
    frozen["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap()
}

fn install_empty() -> (tempfile::TempDir, PathBuf, String) {
    let frozen = fixture();
    let empty = case(&frozen, "empty");
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.join("quota");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, content) in [
        ("config.json", empty["config"].as_str().unwrap()),
        ("events.jsonl", ""),
        ("quota.lock", ""),
    ] {
        let path = root.join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (
        temporary,
        root,
        empty["config_digest"].as_str().unwrap().to_owned(),
    )
}

fn snapshot(root: &std::path::Path, digest: &str, allowance: Option<&str>) -> Value {
    read_provider_quota_snapshot(root, digest, allowance).unwrap()
}

fn repository_with_python() -> Option<&'static std::path::Path> {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    let source = repository.join("ci/gauntlet/benchmark/provider_quota.py");
    if !source.is_file() {
        return None;
    }
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(source).unwrap())),
        "f9dae71c6caee2a5e2e5727010d247cb5424dbe1b55c7f472a5093e10a72815e"
    );
    Some(repository)
}

fn python_snapshot(root: &std::path::Path, digest: &str, allowance: Option<&str>) -> Option<Value> {
    let repository = repository_with_python()?; // Cross-compiled VM binary has no checkout.
    let output = Command::new("python3")
        .arg("-B")
        .arg("-c")
        .arg("from pathlib import Path\nimport json,sys\nfrom ci.gauntlet.benchmark.provider_quota import ProviderQuota\nq=ProviderQuota(Path(sys.argv[1]),expected_config_digest=sys.argv[2],expected_allowance_digest=None if sys.argv[3]=='-' else sys.argv[3])\nprint(json.dumps(q.snapshot(),sort_keys=True))")
        .arg(root)
        .arg(digest)
        .arg(allowance.unwrap_or("-"))
        .env("PYTHONPATH", repository)
        .current_dir(repository)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Python quota reader failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(serde_json::from_slice(&output.stdout).unwrap())
}

fn assert_python_reads(root: &std::path::Path, digest: &str, allowance: Option<&str>) {
    if let Some(python) = python_snapshot(root, digest, allowance) {
        assert_eq!(snapshot(root, digest, allowance), python);
    }
}

fn python_mutate(root: &std::path::Path, digest: &str, action: &str, id: &str) {
    let repository = repository_with_python().unwrap();
    let output = Command::new("python3")
        .arg("-B")
        .arg("-c")
        .arg("from pathlib import Path\nimport sys\nfrom ci.gauntlet.benchmark.provider_quota import ProviderQuota\nq=ProviderQuota(Path(sys.argv[1]),expected_config_digest=sys.argv[2])\nif sys.argv[3]=='settle': q.settle(sys.argv[4],prompt_tokens=4,output_tokens=2)\nelse: q.uncertain(sys.argv[4],reason='synthetic lost response')")
        .arg(root)
        .arg(digest)
        .arg(action)
        .arg(id)
        .env("PYTHONPATH", repository)
        .current_dir(repository)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Python quota writer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn compare_python_state(actual: &Value, expected: &Value) {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.as_object_mut().unwrap().remove("journal_hash");
    expected.as_object_mut().unwrap().remove("journal_hash");
    assert_eq!(actual, expected);
}

#[test]
fn rust_writer_matches_python_v1_lifetime_states() {
    let frozen = fixture();
    let (_temporary, root, config) = install_empty();
    let writer = ProviderQuotaWriter::open_existing(&root, &config, None).unwrap();
    assert_python_reads(&root, &config, None);
    assert_eq!(
        snapshot(&root, &config, None),
        case(&frozen, "empty")["snapshot"]
    );
    let first = writer.reserve(60, 20, &"b".repeat(64), None).unwrap();
    assert_python_reads(&root, &config, None);
    assert_eq!(first.len(), 32);
    compare_python_state(
        &snapshot(&root, &config, None),
        &case(&frozen, "reserved")["snapshot"],
    );
    assert!(writer.reserve(1, 1, &"b".repeat(64), None).is_err());
    assert!(writer.settle(&first, 59, 0).is_err());
    assert!(writer.settle(&first, 60, 21).is_err());
    writer.settle(&first, 60, 10).unwrap();
    assert_python_reads(&root, &config, None);
    compare_python_state(
        &snapshot(&root, &config, None),
        &case(&frozen, "settled")["snapshot"],
    );
    let settled_hash = snapshot(&root, &config, None)["journal_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(writer
        .extend_allowance(150, &"d".repeat(64), &"f".repeat(64))
        .is_err());
    let extended = writer
        .extend_allowance(150, &"d".repeat(64), &settled_hash)
        .unwrap();
    assert_eq!(extended.allowance_digest(), Some("d".repeat(64).as_str()));
    assert_python_reads(&root, &config, Some(&"d".repeat(64)));
    assert!(writer.reserve(1, 1, &"b".repeat(64), None).is_err());
    compare_python_state(
        &snapshot(&root, &config, Some(&"d".repeat(64))),
        &case(&frozen, "extended")["snapshot"],
    );
    assert!(extended
        .reserve(40, 20, &"b".repeat(64), Some(120))
        .is_err());
    let second = extended.reserve(40, 20, &"b".repeat(64), None).unwrap();
    assert_python_reads(&root, &config, Some(&"d".repeat(64)));
    compare_python_state(
        &snapshot(&root, &config, Some(&"d".repeat(64))),
        &case(&frozen, "extended-reserved")["snapshot"],
    );
    extended
        .uncertain(&second, "synthetic transport loss")
        .unwrap();
    assert_python_reads(&root, &config, Some(&"d".repeat(64)));
    compare_python_state(
        &snapshot(&root, &config, Some(&"d".repeat(64))),
        &case(&frozen, "uncertain")["snapshot"],
    );
    assert!(extended.reserve(1, 1, &"b".repeat(64), None).is_err());
    assert!(extended.settle(&second, 40, 0).is_err());
    assert!(extended
        .extend_allowance(200, &"e".repeat(64), &"f".repeat(64))
        .is_err());
    let rows = std::fs::read_to_string(root.join("events.jsonl")).unwrap();
    assert_eq!(rows.lines().count(), 5);
    assert!(rows.ends_with('\n'));
}

#[test]
fn writer_refuses_busy_or_unsafe_storage_and_interrupted_append() {
    let (_temporary, root, config) = install_empty();
    let lock = open(root.join("quota.lock"), OFlags::RDWR, Mode::empty()).unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(ProviderQuotaWriter::open_existing(&root, &config, None)
        .unwrap_err()
        .to_string()
        .contains("busy"));
    flock(&lock, FlockOperation::Unlock).unwrap();
    drop(lock);
    let writer = ProviderQuotaWriter::open_existing(&root, &config, None).unwrap();
    let id = writer.reserve(1, 1, &"b".repeat(64), None).unwrap();
    let events = root.join("events.jsonl");
    let mut raw = std::fs::read(&events).unwrap();
    raw.pop();
    std::fs::write(&events, raw).unwrap();
    assert!(writer.settle(&id, 1, 0).is_err());
    assert!(ProviderQuotaWriter::open_existing(&root, &config, None).is_err());

    let (_temporary, root, config) = install_empty();
    std::fs::set_permissions(
        root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert!(ProviderQuotaWriter::open_existing(&root, &config, None).is_err());
    std::fs::set_permissions(
        root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::remove_file(root.join("events.jsonl")).unwrap();
    symlink(root.join("config.json"), root.join("events.jsonl")).unwrap();
    assert!(ProviderQuotaWriter::open_existing(&root, &config, None).is_err());
}

#[test]
fn python_and_rust_writers_handoff_serially_under_one_lifetime() {
    if repository_with_python().is_none() {
        return;
    }
    let (_temporary, root, config) = install_empty();
    let writer = ProviderQuotaWriter::open_existing(&root, &config, None).unwrap();
    let first = writer.reserve(4, 3, &"b".repeat(64), None).unwrap();
    python_mutate(&root, &config, "settle", &first);
    let settled = snapshot(&root, &config, None);
    assert_eq!(settled["known_tokens"], 6);
    assert_eq!(settled["pending_requests"], 0);
    let second = writer.reserve(4, 3, &"c".repeat(64), None).unwrap();
    python_mutate(&root, &config, "uncertain", &second);
    let halted = snapshot(&root, &config, None);
    assert_eq!(halted["halted"], true);
    assert_eq!(halted["reserved_tokens"], 7);
    assert!(writer.reserve(1, 1, &"b".repeat(64), None).is_err());
}

#[test]
fn python_reader_accepts_rust_created_private_lifetime() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.join("new-quota");
    ProviderQuotaWriter::create_new(&root, "external-authorization", 100, 3, &"a".repeat(64))
        .unwrap();
    let config: Value =
        serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
    let digest = crate::provider_quota::digest(&config).unwrap();
    assert_python_reads(&root, &digest, None);
}
