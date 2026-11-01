//! Python FrameCodec byte vectors from b4efd817 with a public synthetic key.

use gauntlet_evidence::FrameCodec;
use serde_json::Value;
use std::path::Path;

fn fixture() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python_bridge_frames.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn decoder(value: &Value, role: &str) -> FrameCodec {
    let (local_boot, peer_boot) = if role == "controller" {
        (&value["controller_boot"], &value["collector_boot"])
    } else {
        (&value["collector_boot"], &value["controller_boot"])
    };
    FrameCodec::new(
        &[b'K'; 32],
        value["session"].as_str().unwrap(),
        role,
        local_boot.as_str().unwrap(),
        peer_boot.as_str().unwrap(),
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
fn python_frame_bytes_and_bidirectional_sequences_match() {
    let fixture = fixture();
    assert_eq!(
        fixture["source_sha"],
        "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
    );
    let mut controller = decoder(&fixture, "controller");
    let mut collector = decoder(&fixture, "product-collector");
    for (index, row) in fixture["frames"].as_array().unwrap().iter().enumerate() {
        let kind = row["kind"].as_str().unwrap();
        let expected = bytes(row["hex"].as_str().unwrap());
        assert_eq!(
            u32::from_be_bytes(expected[..4].try_into().unwrap()) as usize,
            expected.len() - 4
        );
        let (sender, receiver) = if index == 1 {
            (&mut collector, &mut controller)
        } else {
            (&mut controller, &mut collector)
        };
        assert_eq!(sender.encode(kind, &row["body"]).unwrap(), expected);
        assert_eq!(receiver.decode(&expected[4..], kind).unwrap(), row["body"]);
    }
}

#[test]
fn tamper_replay_direction_and_budget_poison_connection() {
    let fixture = fixture();
    let frame = bytes(fixture["frames"][0]["hex"].as_str().unwrap());
    let mut peer = decoder(&fixture, "product-collector");
    let mut envelope: Value = serde_json::from_slice(&frame[4..]).unwrap();
    envelope["message"]["body"]["job"] = Value::String("forged".into());
    assert!(peer
        .decode(&serde_json::to_vec(&envelope).unwrap(), "request")
        .is_err());
    assert!(peer.poisoned());
    assert!(peer.decode(&frame[4..], "request").is_err());

    let mut peer = decoder(&fixture, "product-collector");
    assert!(peer.decode(&frame[4..], "response").is_err());
    assert!(peer.poisoned());

    let mut peer = decoder(&fixture, "product-collector");
    assert!(peer.decode(&frame[4..], "request").is_ok());
    assert!(peer.decode(&frame[4..], "request").is_err());
    assert!(peer.poisoned());

    let mut self_decoder = decoder(&fixture, "controller");
    assert!(self_decoder.decode(&frame[4..], "request").is_err());
    assert!(self_decoder.poisoned());

    let mut bounded = FrameCodec::new(
        &[b'K'; 32],
        fixture["session"].as_str().unwrap(),
        "controller",
        fixture["controller_boot"].as_str().unwrap(),
        fixture["collector_boot"].as_str().unwrap(),
        1,
        1024,
    )
    .unwrap();
    assert!(bounded
        .encode("request", &fixture["frames"][0]["body"])
        .is_ok());
    assert!(bounded
        .encode("request", &fixture["frames"][0]["body"])
        .is_err());
    assert!(bounded.poisoned());
}

#[test]
fn noncanonical_identity_or_invalid_size_is_refused() {
    let fixture = fixture();
    assert!(FrameCodec::new(
        &[b'K'; 31],
        fixture["session"].as_str().unwrap(),
        "controller",
        fixture["controller_boot"].as_str().unwrap(),
        fixture["collector_boot"].as_str().unwrap(),
        10_000,
        1024,
    )
    .is_err());
    let mut codec = decoder(&fixture, "product-collector");
    assert!(codec.validate_length(0).is_err());
    assert!(codec.poisoned());
}
