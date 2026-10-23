use gauntlet_agent_bridge::{
    read_private_bootstrap, Bootstrap, BootstrapKind, BridgeIoError, OutboundBootstrap,
};
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/python_bootstrap_v1.json")).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn sha(raw: &[u8]) -> String {
    digest(&SHA256, raw)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn python_frozen_vm_and_cell_bootstraps_bind_outside_identity() {
    let fixture = fixture();
    assert_eq!(
        fixture["source_sha256"]["vm_bridge_control.py"],
        sha(include_bytes!(
            "../../../../gauntlet/benchmark/vm_bridge_control.py"
        ))
    );
    assert_eq!(
        fixture["source_sha256"]["product_cell_protocol.py"],
        sha(include_bytes!(
            "../../../../gauntlet/benchmark/product_cell_protocol.py"
        ))
    );
    let vm_raw = bytes(fixture["vm"]["bytes_hex"].as_str().unwrap());
    let vm_hashes = &fixture["vm"]["body"]["hashes"];
    for (kind, local) in [
        (
            BootstrapKind::VmController,
            "22222222-2222-2222-2222-222222222222",
        ),
        (
            BootstrapKind::VmProductCollector,
            "33333333-3333-3333-3333-333333333333",
        ),
    ] {
        let bootstrap = Bootstrap::parse(&vm_raw, kind, local, Some(vm_hashes)).unwrap();
        assert_eq!(
            bootstrap.vm_auth_fingerprint().unwrap(),
            fixture["vm"]["auth_fingerprint"]
        );
        assert!(bootstrap.into_codec(64, 1024 * 1024).is_ok());
    }
    let cell_raw = bytes(fixture["cell"]["bytes_hex"].as_str().unwrap());
    for kind in [
        BootstrapKind::ProductCellSupervisor,
        BootstrapKind::ProductCellActor,
    ] {
        let bootstrap = Bootstrap::parse(
            &cell_raw,
            kind,
            "22222222-2222-2222-2222-222222222222",
            None,
        )
        .unwrap();
        assert!(bootstrap.vm_auth_fingerprint().is_none());
        assert!(bootstrap.into_codec(10_000, 256 * 1024 * 1024).is_ok());
    }
}

#[test]
fn wrong_boot_source_key_fields_and_ambiguous_json_refuse() {
    let fixture = fixture();
    let vm_raw = bytes(fixture["vm"]["bytes_hex"].as_str().unwrap());
    let vm_hashes = &fixture["vm"]["body"]["hashes"];
    assert!(Bootstrap::parse(
        &vm_raw,
        BootstrapKind::VmController,
        "33333333-3333-3333-3333-333333333333",
        Some(vm_hashes),
    )
    .is_err());
    assert!(Bootstrap::parse(
        &vm_raw,
        BootstrapKind::VmController,
        "22222222-2222-2222-2222-222222222222",
        Some(&json!({})),
    )
    .is_err());
    assert!(Bootstrap::parse(
        &vm_raw,
        BootstrapKind::VmController,
        "22222222-2222-2222-2222-222222222222",
        None,
    )
    .is_err());
    let mut altered = fixture["vm"]["body"].clone();
    altered["key_hex"] = Value::String("B".repeat(64));
    assert!(Bootstrap::parse(
        &serde_json::to_vec(&altered).unwrap(),
        BootstrapKind::VmController,
        "22222222-2222-2222-2222-222222222222",
        Some(vm_hashes),
    )
    .is_err());
    altered = fixture["vm"]["body"].clone();
    altered["unexpected"] = json!(true);
    assert!(Bootstrap::parse(
        &serde_json::to_vec(&altered).unwrap(),
        BootstrapKind::VmController,
        "22222222-2222-2222-2222-222222222222",
        Some(vm_hashes),
    )
    .is_err());
    assert!(Bootstrap::parse(
        br#"{"schema":"a","schema":"b"}"#,
        BootstrapKind::ProductCellActor,
        "22222222-2222-2222-2222-222222222222",
        None,
    )
    .is_err());
}

#[test]
fn bounded_private_pipe_read_precedes_key_parsing() {
    let fixture = fixture();
    let raw = bytes(fixture["cell"]["bytes_hex"].as_str().unwrap());
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
    writer.write_all(&raw).unwrap();
    let reader: OwnedFd = reader.into();
    assert_eq!(
        read_private_bootstrap(&reader, deadline(), &AtomicBool::new(false)).unwrap(),
        raw
    );

    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&4097_u32.to_be_bytes()).unwrap();
    let reader: OwnedFd = reader.into();
    assert_eq!(
        read_private_bootstrap(&reader, deadline(), &AtomicBool::new(false)).unwrap_err(),
        BridgeIoError::Invalid("private bootstrap byte budget")
    );
}

#[test]
fn truncated_idle_cancelled_and_wrong_descriptor_refuse() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&10_u32.to_be_bytes()).unwrap();
    writer.write_all(b"{}").unwrap();
    drop(writer);
    let reader: OwnedFd = reader.into();
    assert_eq!(
        read_private_bootstrap(&reader, deadline(), &AtomicBool::new(false)).unwrap_err(),
        BridgeIoError::Eof
    );
    let (reader, _writer) = UnixStream::pair().unwrap();
    let reader: OwnedFd = reader.into();
    assert_eq!(
        read_private_bootstrap(
            &reader,
            Instant::now() + Duration::from_millis(30),
            &AtomicBool::new(false),
        )
        .unwrap_err(),
        BridgeIoError::Deadline
    );
    assert_eq!(
        read_private_bootstrap(&reader, deadline(), &AtomicBool::new(true)).unwrap_err(),
        BridgeIoError::Cancelled
    );
    let file: OwnedFd = tempfile::tempfile().unwrap().into();
    assert!(matches!(
        read_private_bootstrap(&file, deadline(), &AtomicBool::new(false)),
        Err(BridgeIoError::Invalid(_))
    ));
}

#[test]
fn fresh_vm_bootstrap_delivers_once_and_authenticates_peer_frames() {
    let fixture = fixture();
    let hashes = &fixture["vm"]["body"]["hashes"];
    let outbound = OutboundBootstrap::generate(
        BootstrapKind::VmController,
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        Some(hashes),
    )
    .unwrap();
    let fingerprint = outbound.vm_auth_fingerprint().unwrap();
    let other = OutboundBootstrap::generate(
        BootstrapKind::VmController,
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        Some(hashes),
    )
    .unwrap();
    assert_ne!(fingerprint, other.vm_auth_fingerprint().unwrap());
    let (reader, writer) = UnixStream::pair().unwrap();
    let reader: OwnedFd = reader.into();
    let writer: OwnedFd = writer.into();
    let mut controller = outbound
        .deliver(
            &writer,
            deadline(),
            &AtomicBool::new(false),
            64,
            1024 * 1024,
        )
        .unwrap();
    let raw = read_private_bootstrap(&reader, deadline(), &AtomicBool::new(false)).unwrap();
    let peer = Bootstrap::parse(
        &raw,
        BootstrapKind::VmProductCollector,
        "33333333-3333-3333-3333-333333333333",
        Some(hashes),
    )
    .unwrap();
    assert_eq!(peer.vm_auth_fingerprint().unwrap(), fingerprint);
    let mut collector = peer.into_codec(64, 1024 * 1024).unwrap();
    let frame = controller
        .encode("request", &json!({"operation":"observe"}))
        .unwrap();
    assert_eq!(
        collector.decode(&frame[4..], "request").unwrap(),
        json!({"operation":"observe"})
    );
}

#[test]
fn outbound_product_cell_requires_one_boot_and_valid_bounds_before_writing() {
    assert!(OutboundBootstrap::generate(
        BootstrapKind::ProductCellSupervisor,
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        None,
    )
    .is_err());
    let outbound = OutboundBootstrap::generate(
        BootstrapKind::ProductCellSupervisor,
        "22222222-2222-2222-2222-222222222222",
        "22222222-2222-2222-2222-222222222222",
        None,
    )
    .unwrap();
    let (reader, writer) = UnixStream::pair().unwrap();
    let reader: OwnedFd = reader.into();
    let writer: OwnedFd = writer.into();
    assert!(outbound
        .deliver(&writer, deadline(), &AtomicBool::new(false), 0, 1024 * 1024)
        .is_err());
    assert_eq!(
        read_private_bootstrap(
            &reader,
            Instant::now() + Duration::from_millis(30),
            &AtomicBool::new(false),
        )
        .unwrap_err(),
        BridgeIoError::Deadline
    );
}
