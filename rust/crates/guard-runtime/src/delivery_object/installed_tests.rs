use super::*;
use crate::delivery_object::stored_zip::tests::build;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

fn source() -> String {
    "c".repeat(40)
}

fn tag() -> String {
    format!("extension-data-{}-0.0-000007", source())
}

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

struct Bundle {
    dir: tempfile::TempDir,
    name: String,
    data: &'static [u8],
}

fn bundle() -> Bundle {
    let data: &'static [u8] = br#"{"n":1}"#;
    let name = format!("object-{}.json", digest(data));
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(tag())).unwrap();
    std::fs::write(
        dir.path().join(tag()).join("objects-000001.zip"),
        build(&[(&name, data)]),
    )
    .unwrap();
    Bundle { dir, name, data }
}

fn ask(bundle: &Bundle, target: Value, length: u64) -> Outcome {
    fetch(&json!({
        "root": bundle.dir.path().to_str().unwrap(),
        "target": target,
        "source": source(),
        "length": length,
    }))
}

fn member(bundle: &Bundle) -> Value {
    json!({"tag": tag(), "asset": "objects-000001.zip", "member": bundle.name})
}

#[test]
fn a_member_is_read_from_the_installed_container() {
    let bundle = bundle();
    let reply = ask(&bundle, member(&bundle), bundle.data.len() as u64).unwrap();
    assert_eq!(reply["data"], STANDARD.encode(bundle.data));
}

#[test]
fn a_whole_asset_is_resolved_and_left_to_the_caller() {
    let bundle = bundle();
    let target = json!({"tag": tag(), "asset": bundle.name});
    let reply = ask(&bundle, target, 7).unwrap();
    assert_eq!(reply["kind"], "object");
    assert_eq!(reply["asset"], bundle.name);
    assert!(reply.get("data").is_none());
}

#[test]
fn the_requested_length_is_bounded_by_the_kind() {
    let bundle = bundle();
    let refused = "installed bundle fetch bounds invalid";
    for length in [0, OBJECT_BYTES + 1] {
        assert_eq!(ask(&bundle, member(&bundle), length).unwrap_err(), refused);
    }
    let pack = json!({
        "tag": tag(),
        "asset": "packs-000001.zip",
        "member": format!("pack-{}.zip", "ab".repeat(32)),
    });
    assert_eq!(ask(&bundle, pack, PACK_BYTES + 1).unwrap_err(), refused);
    let outcome = fetch(&json!({
        "root": bundle.dir.path().to_str().unwrap(),
        "target": member(&bundle),
        "source": source(),
        "length": "7",
    }));
    assert_eq!(outcome.unwrap_err(), refused);
}

#[test]
fn a_location_from_another_source_is_refused() {
    let bundle = bundle();
    let other = json!({
        "tag": format!("extension-data-{}-0.0-000007", "d".repeat(40)),
        "asset": "objects-000001.zip",
        "member": bundle.name,
    });
    assert_eq!(
        ask(&bundle, other, 7).unwrap_err(),
        "installed bundle asset source differs"
    );
}

#[test]
fn a_member_of_the_wrong_length_or_a_missing_container_is_refused() {
    let bundle = bundle();
    assert_eq!(
        ask(&bundle, member(&bundle), 8).unwrap_err(),
        "delivery container member length differs"
    );
    let absent = json!({"tag": tag(), "asset": "objects-000002.zip", "member": bundle.name});
    assert_eq!(
        ask(&bundle, absent, 7).unwrap_err(),
        "delivery container unreadable"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_tag_directory_is_not_followed() {
    let bundle = bundle();
    let real = bundle.dir.path().join(tag());
    let moved = bundle.dir.path().join("moved");
    std::fs::rename(&real, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &real).unwrap();
    assert_eq!(
        ask(&bundle, member(&bundle), 7).unwrap_err(),
        "delivery container unreadable"
    );
}

#[test]
fn a_member_request_needs_a_root() {
    let bundle = bundle();
    let outcome = fetch(&json!({
        "target": member(&bundle),
        "source": source(),
        "length": 7,
    }));
    assert_eq!(outcome.unwrap_err(), "delivery object request invalid");
}
