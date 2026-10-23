use super::*;
use crate::delivery_object::stored_zip::tests::build;
use std::fs;

const OBJECTS: &str = "objects-000001.zip";

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn object(data: &[u8]) -> String {
    format!("object-{}.json", digest(data))
}

fn call(bytes: &[u8], asset: &str, name: &str, length: usize) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(asset);
    fs::write(&path, bytes).unwrap();
    member(&json!({
        "path": path.to_str().unwrap(),
        "asset": asset,
        "name": name,
        "length": length,
    }))
}

fn rejected(outcome: Outcome) -> String {
    outcome.unwrap_err()
}

fn pair() -> (Vec<u8>, String, String) {
    let (first, second) = (br#"{"n":1}"#.as_slice(), br#"{"n":22}"#.as_slice());
    let bytes = build(&[(&object(first), first), (&object(second), second)]);
    (bytes, object(first), object(second))
}

fn central(bytes: &[u8]) -> usize {
    zip::end(bytes).unwrap().start
}

#[test]
fn returns_the_selected_member_only() {
    let (bytes, first, second) = pair();
    let chosen = call(&bytes, OBJECTS, &second, 8).unwrap();
    assert_eq!(
        STANDARD.decode(chosen["data"].as_str().unwrap()).unwrap(),
        br#"{"n":22}"#
    );
    let other = call(&bytes, OBJECTS, &first, 7).unwrap();
    assert_eq!(
        STANDARD.decode(other["data"].as_str().unwrap()).unwrap(),
        br#"{"n":1}"#
    );
}

#[test]
fn a_missing_or_resized_member_is_refused() {
    let (bytes, first, _) = pair();
    let absent = object(b"absent");
    assert_eq!(
        rejected(call(&bytes, OBJECTS, &absent, 6)),
        "delivery container member missing"
    );
    assert_eq!(
        rejected(call(&bytes, OBJECTS, &first, 8)),
        "delivery container member length differs"
    );
}

#[test]
fn a_member_that_is_not_its_name_is_refused() {
    let name = object(b"declared");
    let bytes = build(&[(&name, b"different")]);
    assert_eq!(
        rejected(call(&bytes, OBJECTS, &name, 9)),
        "delivery container member integrity invalid"
    );
}

#[test]
fn a_container_must_have_a_known_name_and_terminator() {
    let (bytes, first, _) = pair();
    assert_eq!(
        rejected(call(&bytes, "container.zip", &first, 7)),
        "delivery container name invalid"
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        rejected(call(&trailing, OBJECTS, &first, 7)),
        "delivery container size or terminator invalid"
    );
    assert_eq!(
        rejected(call(&bytes[..10], OBJECTS, &first, 7)),
        "delivery container size or terminator invalid"
    );
}

#[test]
fn a_container_with_an_unusual_directory_is_refused() {
    let (bytes, first, _) = pair();
    let tail = bytes.len() - 22;
    let mut many = bytes.clone();
    many[tail + 8..tail + 10].copy_from_slice(&257u16.to_le_bytes());
    many[tail + 10..tail + 12].copy_from_slice(&257u16.to_le_bytes());
    assert_eq!(
        rejected(call(&many, OBJECTS, &first, 7)),
        "delivery container central directory exceeds bounds"
    );
    let mut counted = bytes.clone();
    counted[tail + 8..tail + 10].copy_from_slice(&3u16.to_le_bytes());
    counted[tail + 10..tail + 12].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        rejected(call(&counted, OBJECTS, &first, 7)),
        "delivery container member count differs"
    );
    let mut unmarked = bytes.clone();
    let start = central(&bytes);
    unmarked[start] = b'X';
    assert_eq!(
        rejected(call(&unmarked, OBJECTS, &first, 7)),
        "delivery container archive invalid"
    );
}

#[test]
fn an_irregular_member_entry_is_refused() {
    let (bytes, first, _) = pair();
    let start = central(&bytes);
    // flags, method, extra length, comment length, external attributes.
    for (at, value) in [(8usize, 1u8), (10, 8), (30, 1), (32, 1), (41, 0)] {
        let mut changed = bytes.clone();
        changed[start + at] = value;
        assert_eq!(
            rejected(call(&changed, OBJECTS, &first, 7)),
            "delivery container member invalid",
            "offset {at}"
        );
    }
    let duplicate = build(&[(&first, b"{}"), (&first, b"{}")]);
    assert_eq!(
        rejected(call(&duplicate, OBJECTS, &first, 2)),
        "delivery container member invalid"
    );
    let upper = "object-".to_owned() + &"AB".repeat(32) + ".json";
    let misnamed = build(&[(&upper, b"{}")]);
    assert_eq!(
        rejected(call(&misnamed, OBJECTS, &upper, 2)),
        "delivery container member invalid"
    );
    let wrong_kind = format!("pack-{}.zip", "ab".repeat(32));
    let crossed = build(&[(&wrong_kind, b"{}")]);
    assert_eq!(
        rejected(call(&crossed, OBJECTS, &wrong_kind, 2)),
        "delivery container member invalid"
    );
}

#[test]
fn an_object_member_is_bounded_at_sixty_four_kib() {
    let large = vec![b'x'; OBJECT_BYTES + 1];
    let name = object(&large);
    let bytes = build(&[(&name, &large)]);
    assert_eq!(
        rejected(call(&bytes, OBJECTS, &name, large.len())),
        "delivery container member invalid"
    );
    let fits = vec![b'x'; OBJECT_BYTES];
    let name = object(&fits);
    let bytes = build(&[(&name, &fits)]);
    assert!(call(&bytes, OBJECTS, &name, fits.len()).is_ok());
}

#[test]
fn damaged_member_bytes_fail_the_local_checks() {
    let (bytes, first, _) = pair();
    let mut changed = bytes.clone();
    // The first member's data follows its 30-byte header and its name.
    changed[30 + first.len()] ^= 1;
    assert_eq!(
        rejected(call(&changed, OBJECTS, &first, 7)),
        "delivery container archive invalid"
    );
}

#[test]
fn a_pack_container_holds_pack_members() {
    let archive = b"PK-not-inspected";
    let name = format!("pack-{}.zip", digest(archive));
    let bytes = build(&[(&name, archive)]);
    let chosen = call(&bytes, "packs-000003.zip", &name, archive.len()).unwrap();
    assert_eq!(
        STANDARD.decode(chosen["data"].as_str().unwrap()).unwrap(),
        archive
    );
    let (objects, first, _) = pair();
    assert_eq!(
        rejected(call(&objects, "packs-000003.zip", &first, 7)),
        "delivery container member invalid"
    );
}

#[test]
fn an_unreadable_container_or_request_is_refused() {
    let (_, first, _) = pair();
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join(OBJECTS);
    let outcome = member(&json!({
        "path": absent.to_str().unwrap(),
        "asset": OBJECTS,
        "name": first,
        "length": 7,
    }));
    assert_eq!(rejected(outcome), "delivery container unreadable");
    assert_eq!(
        rejected(member(&json!({"asset": OBJECTS}))),
        "delivery object request invalid"
    );
}

#[test]
fn shared_members_keep_one_snapshot_and_the_next_call_reads_again() {
    let (bytes, first, second) = pair();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(OBJECTS);
    fs::write(&path, &bytes).unwrap();
    let reads = read_count();
    let requests = [(&*first, 7), (&*second, 8)]
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            // This iterator is consumed after the real file read and inspection.
            if index == 1 {
                fs::write(&path, b"corrupt").unwrap();
            }
            item
        });
    let replies = members(&path, OBJECTS, requests).unwrap();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["data"], STANDARD.encode(br#"{"n":1}"#));
    assert_eq!(replies[1]["data"], STANDARD.encode(br#"{"n":22}"#));
    assert_eq!(read_count() - reads, 1);
    assert_eq!(
        members(&path, OBJECTS, [(&*first, 7)]).unwrap_err(),
        "delivery container size or terminator invalid"
    );
    assert_eq!(read_count() - reads, 2);
}

#[test]
fn shared_reads_keep_container_bounds_and_whole_directory_checks() {
    let (bytes, first, _) = pair();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(OBJECTS);
    let file = fs::File::create(&path).unwrap();
    file.set_len(location::family(OBJECTS).unwrap().bound() as u64 + 1)
        .unwrap();
    assert_eq!(
        members(&path, OBJECTS, [(&*first, 7)]).unwrap_err(),
        "delivery container unreadable"
    );
    let mut malformed = bytes.clone();
    // Reject an unselected member's unsupported method before selecting the first.
    let next = zip::entry(&bytes, central(&bytes)).unwrap().next;
    malformed[next + 10] = 8;
    fs::write(&path, malformed).unwrap();
    assert_eq!(
        members(&path, OBJECTS, [(&*first, 7)]).unwrap_err(),
        "delivery container member invalid"
    );
}
