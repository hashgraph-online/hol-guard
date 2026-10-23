//! Fresh Rust key/bootstrap delivered to an actual pinned Python RPC peer.

use gauntlet_agent_bridge::{BootstrapKind, BridgeChannel, BridgeClient, OutboundBootstrap};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

const PYTHON: &str = r#"
import socket, sys, time
from ci.gauntlet.benchmark.json_data import strict_json_loads
from ci.gauntlet.benchmark.product_cell_protocol import CellCodec, read_bootstrap
from ci.gauntlet.benchmark.vm_bridge_control import source_hashes
from ci.gauntlet.benchmark.vm_bridge_frames import FrameCodec
from ci.gauntlet.benchmark.vm_bridge_io import BridgeIO
from ci.gauntlet.benchmark.vm_bridge_rpc import serve_one

mode, to_python, to_rust = sys.argv[1:]
reader = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
writer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
reader.connect(to_python)
writer.connect(to_rust)
bootstrap = strict_json_loads(read_bootstrap(reader.fileno()))
assert type(bootstrap) is dict and type(bootstrap['key_hex']) is str
if mode == 'cell':
    assert set(bootstrap) == {'schema','session','key_hex','boot_id'}
    assert bootstrap['schema'] == 'product-cell-private-bootstrap.v1'
    codec = CellCodec(bytes.fromhex(bootstrap['key_hex']), session=bootstrap['session'],
        local_role='cell-actor', local_boot=bootstrap['boot_id'], peer_boot=bootstrap['boot_id'])
else:
    assert set(bootstrap) == {'schema','session','key_hex','controller_boot','product_boot','hashes'}
    assert bootstrap['schema'] == 'gauntlet-vm-bridge-private-bootstrap.v1'
    assert bootstrap['hashes'] == source_hashes()
    codec = FrameCodec(bytes.fromhex(bootstrap['key_hex']), session=bootstrap['session'],
        local_role='product-collector', local_boot=bootstrap['product_boot'],
        peer_boot=bootstrap['controller_boot'])
channel = BridgeIO(reader.fileno(), writer.fileno(), codec)
serve_one(channel, {'hello':lambda payload: {'ready':True} if payload == {} else {}},
    deadline=time.monotonic()+5)
"#;

fn accept_bounded(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "Python management connect timed out"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("Python management accept failed: {error}"),
        }
    }
}

fn run(mode: &str) {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 unavailable; live bootstrap interop skipped");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let to_python = directory.path().join("to-python.sock");
    let to_rust = directory.path().join("to-rust.sock");
    let writer_listener = UnixListener::bind(&to_python).unwrap();
    let reader_listener = UnixListener::bind(&to_rust).unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    let child = Command::new("python3")
        .arg("-c")
        .arg(PYTHON)
        .arg(mode)
        .arg(&to_python)
        .arg(&to_rust)
        .env("PYTHONPATH", repository)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let writer: OwnedFd = accept_bounded(&writer_listener).into();
    let reader: OwnedFd = accept_bounded(&reader_listener).into();
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/python_bootstrap_v1.json")).unwrap();
    let (kind, local, peer, hashes) = if mode == "cell" {
        (
            BootstrapKind::ProductCellSupervisor,
            "22222222-2222-2222-2222-222222222222",
            "22222222-2222-2222-2222-222222222222",
            None,
        )
    } else {
        (
            BootstrapKind::VmController,
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            Some(&fixture["vm"]["body"]["hashes"]),
        )
    };
    let bootstrap = OutboundBootstrap::generate(kind, local, peer, hashes).unwrap();
    let codec = bootstrap
        .deliver(
            &writer,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            64,
            1024 * 1024,
        )
        .unwrap();
    let client = BridgeClient::new(BridgeChannel::new(reader, writer, codec).unwrap());
    assert_eq!(
        client
            .call(
                "hello",
                &json!({}),
                Duration::from_secs(5),
                &AtomicBool::new(false)
            )
            .unwrap(),
        json!({"ready":true})
    );
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fresh_rust_product_cell_bootstrap_reaches_python_actor() {
    run("cell");
}

#[test]
fn fresh_rust_vm_bootstrap_reaches_python_collector() {
    run("vm");
}
