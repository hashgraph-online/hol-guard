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

/// The directory the bundle keeps `tag()`'s assets in.
fn slot() -> &'static str {
    "000007"
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
    std::fs::create_dir(dir.path().join(slot())).unwrap();
    std::fs::write(
        dir.path().join(slot()).join("objects-000001.zip"),
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
    assert_eq!(reply["directory"], slot());
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
    let real = bundle.dir.path().join(slot());
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

fn batch_ask(bundle: &Bundle, items: Vec<Value>) -> Outcome {
    batch(&json!({"root": bundle.dir.path(), "source": source(), "items": items}))
}

#[test]
fn a_bounded_batch_checks_every_member_and_preserves_order() {
    let bundle = bundle();
    let second = br#"{"n":2}"#;
    let name = format!("object-{}.json", digest(second));
    std::fs::write(
        bundle.dir.path().join(slot()).join("objects-000001.zip"),
        build(&[(&bundle.name, bundle.data), (&name, second)]),
    )
    .unwrap();
    let item = json!({"target": member(&bundle), "length": bundle.data.len()});
    let other = json!({"target": {"tag": tag(), "asset": "objects-000001.zip", "member": name}, "length": second.len()});
    let requests = (0..BATCH_ITEMS)
        .map(|i| {
            if i % 2 == 0 {
                item.clone()
            } else {
                other.clone()
            }
        })
        .collect();
    let reads = container::read_count();
    let reply = batch_ask(&bundle, requests).unwrap();
    assert_eq!(container::read_count() - reads, 1);
    let items = reply["items"].as_array().unwrap();
    assert_eq!(items.len(), BATCH_ITEMS);
    for (index, item) in items.iter().enumerate() {
        assert_eq!(
            item["data"],
            STANDARD.encode(if index % 2 == 0 { bundle.data } else { second })
        );
    }
    let wrapped = crate::delivery_object::evaluate(&json!({
        "operation": "installed-batch", "root": bundle.dir.path(), "source": source(),
        "items": [{"target": member(&bundle), "length": bundle.data.len()}],
    }))
    .unwrap();
    assert_eq!(wrapped["items"][0], items[0]);
}

#[test]
fn even_maximum_object_batches_have_a_bounded_serialized_reply() {
    let bundle = bundle();
    let bytes = vec![b'a'; OBJECT_BYTES as usize];
    let name = format!("object-{}.json", digest(&bytes));
    std::fs::write(
        bundle.dir.path().join(slot()).join("objects-000001.zip"),
        build(&[(&name, &bytes)]),
    )
    .unwrap();
    let item = json!({"target": {"tag": tag(), "asset": "objects-000001.zip", "member": name}, "length": bytes.len()});
    let reply = batch_ask(&bundle, vec![item; BATCH_ITEMS]).unwrap();
    assert_eq!(reply["items"].as_array().unwrap().len(), BATCH_ITEMS);
    assert!(serde_json::to_vec(&reply).unwrap().len() < 6 * 1024 * 1024);
}

#[test]
fn batches_refuse_empty_oversized_and_non_object_requests() {
    let bundle = bundle();
    let item = json!({"target": member(&bundle), "length": bundle.data.len()});
    for items in [vec![], vec![item; BATCH_ITEMS + 1]] {
        assert_eq!(
            batch_ask(&bundle, items).unwrap_err(),
            "installed bundle batch bounds invalid"
        );
    }
    let pack = json!({"tag": tag(), "asset": format!("pack-{}.zip", "ab".repeat(32))});
    assert_eq!(
        batch_ask(&bundle, vec![json!({"target": pack, "length": 7})]).unwrap_err(),
        "installed bundle batch requires objects"
    );
}

#[test]
fn every_batch_bound_is_checked_before_any_container_is_opened() {
    let bundle = bundle();
    std::fs::remove_file(bundle.dir.path().join(slot()).join("objects-000001.zip")).unwrap();
    let first = json!({"target": member(&bundle), "length": 7});
    let reads = container::read_count();
    for length in [json!(0), json!(OBJECT_BYTES + 1), json!("7")] {
        assert_eq!(
            batch_ask(
                &bundle,
                vec![
                    first.clone(),
                    json!({"target": member(&bundle), "length": length})
                ]
            )
            .unwrap_err(),
            "installed bundle batch bounds invalid"
        );
    }
    let mut other = member(&bundle);
    other["tag"] = json!(format!("extension-data-{}-0.0-000007", "d".repeat(40)));
    assert_eq!(
        batch_ask(&bundle, vec![first, json!({"target": other, "length": 7})]).unwrap_err(),
        "installed bundle asset source differs"
    );
    assert_eq!(container::read_count(), reads);
}

#[test]
fn a_batch_rechecks_changed_members_and_rejects_a_late_corruption() {
    let bundle = bundle();
    let item = json!({"target": member(&bundle), "length": bundle.data.len()});
    assert!(batch_ask(&bundle, vec![item.clone()]).is_ok());
    let different = json!({
        "target": {"tag": tag(), "asset": "objects-000001.zip", "member": format!("object-{}.json", "ab".repeat(32))},
        "length": 7,
    });
    assert!(batch_ask(&bundle, vec![item.clone(), different]).is_err());
    std::fs::write(
        bundle.dir.path().join(slot()).join("objects-000001.zip"),
        b"corrupt",
    )
    .unwrap();
    assert!(batch_ask(&bundle, vec![item]).is_err());
}

#[test]
fn interleaved_assets_and_tags_use_one_read_per_authorized_path() {
    let bundle = bundle();
    let second = br#"{"n":22}"#;
    let name = format!("object-{}.json", digest(second));
    let other_tag = tag().replace("000007", "000008");
    std::fs::create_dir(bundle.dir.path().join("000008")).unwrap();
    for (directory, asset) in [
        (slot(), "objects-000002.zip"),
        ("000008", "objects-000001.zip"),
    ] {
        std::fs::write(
            bundle.dir.path().join(directory).join(asset),
            build(&[(&name, second)]),
        )
        .unwrap();
    }
    let first = json!({"target": member(&bundle), "length": bundle.data.len()});
    let other = json!({"target": {"tag": tag(), "asset": "objects-000002.zip", "member": name}, "length": second.len()});
    let tagged = json!({"target": {"tag": other_tag, "asset": "objects-000001.zip", "member": name}, "length": second.len()});
    let whole =
        json!({"target": {"tag": tag(), "asset": bundle.name}, "length": bundle.data.len()});
    let requests = vec![first.clone(), other, first, whole, tagged];
    let expected: Vec<_> = requests
        .iter()
        .map(|item| {
            ask(
                &bundle,
                item["target"].clone(),
                item["length"].as_u64().unwrap(),
            )
            .unwrap()
        })
        .collect();
    let reads = container::read_count();
    assert_eq!(
        batch_ask(&bundle, requests).unwrap()["items"],
        json!(expected)
    );
    assert_eq!(container::read_count() - reads, 3);
}

#[test]
fn whole_asset_batches_need_neither_root_nor_container_reads() {
    let bundle = bundle();
    let reads = container::read_count();
    let reply = batch(&json!({"source": source(), "items": [{
        "target": {"tag": tag(), "asset": bundle.name}, "length": bundle.data.len(),
    }]}))
    .unwrap();
    assert_eq!(reply["items"][0]["asset"], bundle.name);
    assert_eq!(container::read_count(), reads);
}

#[test]
fn a_later_member_must_pass_length_and_digest_checks_in_the_shared_snapshot() {
    let bundle = bundle();
    let second = br#"{"n":22}"#;
    let name = format!("object-{}.json", digest(second));
    let first = json!({"target": member(&bundle), "length": bundle.data.len()});
    let other = json!({"target": {"tag": tag(), "asset": "objects-000001.zip", "member": name}, "length": second.len()});
    let path = bundle.dir.path().join(slot()).join("objects-000001.zip");
    std::fs::write(
        &path,
        build(&[(&bundle.name, bundle.data), (&name, second)]),
    )
    .unwrap();
    let mut wrong_length = other.clone();
    wrong_length["length"] = json!(second.len() + 1);
    let reads = container::read_count();
    assert_eq!(
        batch_ask(&bundle, vec![first.clone(), wrong_length]).unwrap_err(),
        "delivery container member length differs"
    );
    assert_eq!(container::read_count() - reads, 1);
    // A well-formed ZIP with valid CRC but bytes that differ from the digest name.
    std::fs::write(
        &path,
        build(&[(&bundle.name, bundle.data), (&name, b"tampered")]),
    )
    .unwrap();
    assert_eq!(
        batch_ask(&bundle, vec![first, other]).unwrap_err(),
        "delivery container member integrity invalid"
    );
}

#[cfg(unix)]
#[test]
fn batch_reads_refuse_symlinked_tags_and_container_leaves() {
    for tag_link in [true, false] {
        let bundle = bundle();
        let real = bundle.dir.path().join(slot());
        let real = if tag_link {
            real
        } else {
            real.join("objects-000001.zip")
        };
        let moved = bundle.dir.path().join("moved");
        std::fs::rename(&real, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &real).unwrap();
        let item = json!({"target": member(&bundle), "length": bundle.data.len()});
        assert_eq!(
            batch_ask(&bundle, vec![item]).unwrap_err(),
            "delivery container unreadable"
        );
    }
}

#[test]
#[ignore = "manual timing evidence; no performance threshold"]
fn compare_single_loop_and_batch_on_the_same_real_container() {
    let bundle = bundle();
    let data: Vec<_> = (0..BATCH_ITEMS)
        .map(|index| vec![index as u8; 32 * 1024])
        .collect();
    let names: Vec<_> = data
        .iter()
        .map(|bytes| format!("object-{}.json", digest(bytes)))
        .collect();
    let entries: Vec<_> = names
        .iter()
        .zip(&data)
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let archive = build(&entries);
    std::fs::write(
        bundle.dir.path().join(slot()).join("objects-000001.zip"),
        &archive,
    )
    .unwrap();
    let requests: Vec<_> = names
        .iter()
        .map(|name| {
            json!({
                "target": {"tag": tag(), "asset": "objects-000001.zip", "member": name},
                "length": data[0].len(),
            })
        })
        .collect();
    fn measure(run: impl FnOnce() -> Value) -> (Value, std::time::Duration, usize) {
        let reads = container::read_count();
        let started = std::time::Instant::now();
        let reply = run();
        (reply, started.elapsed(), container::read_count() - reads)
    }
    for round in 0..6 {
        let single = || {
            Value::Array(
                requests
                    .iter()
                    .map(|item| {
                        ask(
                            &bundle,
                            item["target"].clone(),
                            item["length"].as_u64().unwrap(),
                        )
                        .unwrap()
                    })
                    .collect(),
            )
        };
        let grouped = || batch_ask(&bundle, requests.clone()).unwrap()["items"].take();
        let ((single, single_elapsed, single_reads), (grouped, batch_elapsed, batch_reads)) =
            if round % 2 == 0 {
                (measure(single), measure(grouped))
            } else {
                let grouped = measure(grouped);
                (measure(single), grouped)
            };
        assert_eq!(grouped, single);
        assert_eq!((single_reads, batch_reads), (BATCH_ITEMS, 1));
        println!("round={round} first={} fixture_bytes={} objects={} object_bytes={} single_us={} batch_us={} single_reads={single_reads} batch_reads={batch_reads} equal=true", if round % 2 == 0 { "single" } else { "batch" }, archive.len(), BATCH_ITEMS, data[0].len(), single_elapsed.as_micros(), batch_elapsed.as_micros());
    }
}
