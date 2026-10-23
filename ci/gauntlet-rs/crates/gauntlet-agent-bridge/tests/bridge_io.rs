use gauntlet_agent_bridge::{BridgeChannel, BridgeIoError};
use gauntlet_evidence::FrameCodec;
use serde_json::Value;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../gauntlet-evidence/tests/fixtures/python_bridge_frames.json"
    ))
    .unwrap()
}

fn codec(fixture: &Value, role: &str) -> FrameCodec {
    let (local, peer) = if role == "controller" {
        ("controller_boot", "collector_boot")
    } else {
        ("collector_boot", "controller_boot")
    };
    FrameCodec::new(
        &[b'K'; 32],
        fixture["session"].as_str().unwrap(),
        role,
        fixture[local].as_str().unwrap(),
        fixture[peer].as_str().unwrap(),
        10_000,
        256 * 1024 * 1024,
    )
    .unwrap()
}

fn wire(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

fn channel(role: &str) -> (BridgeChannel, UnixStream, UnixStream) {
    let fixture = fixture();
    let (reader, peer_writer) = UnixStream::pair().unwrap();
    let (writer, peer_reader) = UnixStream::pair().unwrap();
    (
        BridgeChannel::new(reader.into(), writer.into(), codec(&fixture, role)).unwrap(),
        peer_writer,
        peer_reader,
    )
}

#[test]
fn unix_socket_transport_matches_python_wire_bytes_and_sequences() {
    let fixture = fixture();
    let (mut controller, mut peer_writer, mut peer_reader) = channel("controller");
    let cancelled = AtomicBool::new(false);
    for row in [&fixture["frames"][0], &fixture["frames"][2]] {
        let expected = wire(row["hex"].as_str().unwrap());
        controller
            .send("request", &row["body"], deadline(), &cancelled)
            .unwrap();
        let mut observed = vec![0; expected.len()];
        peer_reader.read_exact(&mut observed).unwrap();
        assert_eq!(observed, expected);
    }
    let row = &fixture["frames"][1];
    peer_writer
        .write_all(&wire(row["hex"].as_str().unwrap()))
        .unwrap();
    assert_eq!(
        controller
            .receive("response", deadline(), &cancelled)
            .unwrap(),
        row["body"]
    );
    assert!(!controller.poisoned());
}

#[test]
fn two_channels_exchange_authenticated_frames_over_real_pipes() {
    let fixture = fixture();
    let mut to_collector = [0_i32; 2];
    let mut to_controller = [0_i32; 2];
    // SAFETY: each successful pipe initializes exactly two owned descriptors.
    assert_eq!(unsafe { libc::pipe(to_collector.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(to_controller.as_mut_ptr()) }, 0);
    // SAFETY: each descriptor is transferred once into one OwnedFd.
    let [collector_reader, controller_writer] =
        to_collector.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    let [controller_reader, collector_writer] =
        to_controller.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    let mut controller = BridgeChannel::new(
        controller_reader,
        controller_writer,
        codec(&fixture, "controller"),
    )
    .unwrap();
    let mut collector = BridgeChannel::new(
        collector_reader,
        collector_writer,
        codec(&fixture, "product-collector"),
    )
    .unwrap();
    let cancelled = AtomicBool::new(false);
    controller
        .send(
            "request",
            &fixture["frames"][0]["body"],
            deadline(),
            &cancelled,
        )
        .unwrap();
    assert_eq!(
        collector
            .receive("request", deadline(), &cancelled)
            .unwrap(),
        fixture["frames"][0]["body"]
    );
    collector
        .send(
            "response",
            &fixture["frames"][1]["body"],
            deadline(),
            &cancelled,
        )
        .unwrap();
    assert_eq!(
        controller
            .receive("response", deadline(), &cancelled)
            .unwrap(),
        fixture["frames"][1]["body"]
    );
}

#[test]
fn oversized_length_is_rejected_before_body_allocation_and_poisons_channel() {
    let (mut controller, mut peer_writer, _peer_reader) = channel("controller");
    peer_writer
        .write_all(&(12_u32 * 1024 * 1024 + 1).to_be_bytes())
        .unwrap();
    let error = controller
        .receive("response", deadline(), &AtomicBool::new(false))
        .unwrap_err();
    assert!(matches!(error, BridgeIoError::Frame(_)));
    assert!(error.to_string().contains("budget exceeded"));
    assert!(controller.poisoned());
}

#[test]
fn truncated_frame_and_idle_deadline_poison_channel() {
    let (mut truncated, mut peer_writer, _peer_reader) = channel("controller");
    peer_writer.write_all(&10_u32.to_be_bytes()).unwrap();
    peer_writer.write_all(b"{}").unwrap();
    drop(peer_writer);
    assert_eq!(
        truncated
            .receive("response", deadline(), &AtomicBool::new(false))
            .unwrap_err(),
        BridgeIoError::Eof
    );
    assert!(truncated.poisoned());

    let (mut idle, _peer_writer, _peer_reader) = channel("controller");
    assert_eq!(
        idle.receive(
            "response",
            Instant::now() + Duration::from_millis(30),
            &AtomicBool::new(false),
        )
        .unwrap_err(),
        BridgeIoError::Deadline
    );
    assert!(idle.poisoned());
}

#[test]
fn cancellation_and_wrong_direction_poison_channel() {
    let (mut cancelled_channel, _peer_writer, _peer_reader) = channel("controller");
    assert_eq!(
        cancelled_channel
            .receive("response", deadline(), &AtomicBool::new(true))
            .unwrap_err(),
        BridgeIoError::Cancelled
    );
    assert!(cancelled_channel.poisoned());

    let fixture = fixture();
    let (mut wrong_direction, mut peer_writer, _peer_reader) = channel("controller");
    peer_writer
        .write_all(&wire(fixture["frames"][0]["hex"].as_str().unwrap()))
        .unwrap();
    assert!(matches!(
        wrong_direction.receive("response", deadline(), &AtomicBool::new(false)),
        Err(BridgeIoError::Frame(_))
    ));
    assert!(wrong_direction.poisoned());
}

#[test]
fn failed_write_never_leaves_sequence_reusable() {
    let fixture = fixture();
    let (mut channel, _peer_writer, peer_reader) = channel("controller");
    drop(peer_reader);
    assert!(channel
        .send(
            "request",
            &fixture["frames"][0]["body"],
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert!(channel.poisoned());
    assert!(channel
        .send(
            "request",
            &fixture["frames"][0]["body"],
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
}

#[test]
fn regular_file_and_datagram_socket_are_refused() {
    let fixture = fixture();
    let file = tempfile::tempfile().unwrap();
    let (peer, _) = UnixStream::pair().unwrap();
    assert!(matches!(
        BridgeChannel::new(file.into(), peer.into(), codec(&fixture, "controller")),
        Err(BridgeIoError::Invalid(_))
    ));
    let (datagram, _) = UnixDatagram::pair().unwrap();
    let (peer, _) = UnixStream::pair().unwrap();
    assert!(matches!(
        BridgeChannel::new(datagram.into(), peer.into(), codec(&fixture, "controller")),
        Err(BridgeIoError::Invalid(_))
    ));
}
