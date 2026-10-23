//! Python-frozen product-cell frame bytes with a public synthetic key.

use gauntlet_evidence::FrameCodec;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/python_cell_frames_v1.json")).unwrap()
}

fn codec(fixture: &Value, role: &str) -> FrameCodec {
    FrameCodec::new_product_cell(
        &[b'C'; 32],
        fixture["session"].as_str().unwrap(),
        role,
        fixture["boot"].as_str().unwrap(),
        fixture["boot"].as_str().unwrap(),
        10_000,
        256 * 1024 * 1024,
    )
    .unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn pinned_python_product_cell_frames_match_exact_bytes() {
    let fixture = fixture();
    assert_eq!(fixture["schema"], "hol-gauntlet-python-cell-frames.v1");
    assert_eq!(
        fixture["source_sha256"]["product_cell_protocol.py"],
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../../gauntlet/benchmark/product_cell_protocol.py"
            ))
        )
    );
    assert_eq!(
        fixture["source_sha256"]["vm_bridge_frames.py"],
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../../gauntlet/benchmark/vm_bridge_frames.py"
            ))
        )
    );
    let mut supervisor = codec(&fixture, "cell-supervisor");
    let mut actor = codec(&fixture, "cell-actor");
    assert_eq!(fixture["frames"].as_array().unwrap().len(), 3);
    for (index, row) in fixture["frames"].as_array().unwrap().iter().enumerate() {
        let (sender, receiver) = if index == 1 {
            (&mut actor, &mut supervisor)
        } else {
            (&mut supervisor, &mut actor)
        };
        let expected = bytes(row["hex"].as_str().unwrap());
        let kind = row["kind"].as_str().unwrap();
        assert_eq!(sender.encode(kind, &row["body"]).unwrap(), expected);
        assert_eq!(receiver.decode(&expected[4..], kind).unwrap(), row["body"]);
    }
}

#[test]
fn product_cell_and_vm_domains_cannot_cross_authenticate() {
    let fixture = fixture();
    let frame = bytes(fixture["frames"][0]["hex"].as_str().unwrap());
    let mut vm = FrameCodec::new(
        &[b'C'; 32],
        fixture["session"].as_str().unwrap(),
        "product-collector",
        fixture["boot"].as_str().unwrap(),
        fixture["boot"].as_str().unwrap(),
        10_000,
        256 * 1024 * 1024,
    )
    .unwrap();
    assert!(vm.decode(&frame[4..], "request").is_err());
    assert!(vm.poisoned());
    assert!(FrameCodec::new_product_cell(
        &[b'C'; 32],
        fixture["session"].as_str().unwrap(),
        "controller",
        fixture["boot"].as_str().unwrap(),
        fixture["boot"].as_str().unwrap(),
        10_000,
        256 * 1024 * 1024,
    )
    .is_err());
}
