//! A real Python BridgeIO/BridgeClient peer over two Unix stream sockets.
//! The synthetic key and IDs are test data, never an execution credential.

use gauntlet_agent_bridge::{
    serve_one, BridgeChannel, BridgeClient, BridgeOperation, OperationResult,
};
use gauntlet_evidence::FrameCodec;
use serde_json::{json, Value};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

const PYTHON: &str = r#"
import json, socket, sys, time
from ci.gauntlet.benchmark.vm_bridge_frames import FrameCodec
from ci.gauntlet.benchmark.vm_bridge_io import BridgeIO
from ci.gauntlet.benchmark.vm_bridge_rpc import BridgeClient, serve_one
from ci.gauntlet.benchmark.product_cell_protocol import CellCodec

mode, to_python, to_rust = sys.argv[1:]
reader = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
writer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
reader.connect(to_python)
writer.connect(to_rust)
cell = mode.startswith('cell_')
server = mode.endswith('server')
role = ('cell-actor' if server else 'cell-supervisor') if cell else ('product-collector' if server else 'controller')
codec = (CellCodec if cell else FrameCodec)((b'C' if cell else b'K')*32,
    session='11111111-1111-1111-1111-111111111111',
    local_role=role,
    local_boot='22222222-2222-2222-2222-222222222222' if cell or not server else '33333333-3333-3333-3333-333333333333',
    peer_boot='22222222-2222-2222-2222-222222222222' if cell or server else '33333333-3333-3333-3333-333333333333')
channel = BridgeIO(reader.fileno(), writer.fileno(), codec)
if server:
    serve_one(channel, {'read_docs':lambda payload: {'python':True, 'path':payload['path']}},
        deadline=time.monotonic()+5)
else:
    result = BridgeClient(channel).call('read_docs', {'path':'/from-python'}, timeout=5)
    print(json.dumps(result), flush=True)
"#;

fn python_available() -> bool {
    Command::new("python3").arg("--version").output().is_ok()
}

fn accept_bounded(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "Python socket connect timed out");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("Python socket accept failed: {error}"),
        }
    }
}

fn start(mode: &str) -> (BridgeChannel, Child, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let to_python = directory.path().join("to-python.sock");
    let to_rust = directory.path().join("to-rust.sock");
    let rust_writer_listener = UnixListener::bind(&to_python).unwrap();
    let rust_reader_listener = UnixListener::bind(&to_rust).unwrap();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository = manifest.ancestors().nth(4).unwrap();
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
    let writer = accept_bounded(&rust_writer_listener);
    let reader = accept_bounded(&rust_reader_listener);
    let cell = mode.starts_with("cell_");
    let server = mode.ends_with("server");
    let (role, local, peer) = if cell && server {
        (
            "cell-supervisor",
            "22222222-2222-2222-2222-222222222222",
            "22222222-2222-2222-2222-222222222222",
        )
    } else if cell {
        (
            "cell-actor",
            "22222222-2222-2222-2222-222222222222",
            "22222222-2222-2222-2222-222222222222",
        )
    } else if server {
        (
            "controller",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
        )
    } else {
        (
            "product-collector",
            "33333333-3333-3333-3333-333333333333",
            "22222222-2222-2222-2222-222222222222",
        )
    };
    let key = if cell { [b'C'; 32] } else { [b'K'; 32] };
    let codec = if cell {
        FrameCodec::new_product_cell(
            &key,
            "11111111-1111-1111-1111-111111111111",
            role,
            local,
            peer,
            10_000,
            256 * 1024 * 1024,
        )
    } else {
        FrameCodec::new(
            &key,
            "11111111-1111-1111-1111-111111111111",
            role,
            local,
            peer,
            10_000,
            256 * 1024 * 1024,
        )
    }
    .unwrap();
    (
        BridgeChannel::new(reader.into(), writer.into(), codec).unwrap(),
        child,
        directory,
    )
}

fn rust_client_calls_python(mode: &str) {
    if !python_available() {
        eprintln!("python3 unavailable; live interop skipped");
        return;
    }
    let (channel, child, _directory) = start(mode);
    let client = BridgeClient::new(channel);
    let reply = client
        .call(
            "read_docs",
            &json!({"path":"/from-rust"}),
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(reply, json!({"python":true,"path":"/from-rust"}));
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn python_client_calls_rust(mode: &str) {
    if !python_available() {
        eprintln!("python3 unavailable; live interop skipped");
        return;
    }
    let (mut channel, child, _directory) = start(mode);
    let mut handler =
        |payload: &Value| -> OperationResult { Ok(json!({"rust":true,"path":payload["path"]})) };
    let mut operations = [BridgeOperation {
        name: "read_docs",
        handler: &mut handler,
    }];
    assert_eq!(
        serve_one(
            &mut channel,
            &mut operations,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .unwrap(),
        "read_docs"
    );
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply, json!({"rust":true,"path":"/from-python"}));
}

#[test]
fn rust_client_calls_pinned_python_bridge_server() {
    rust_client_calls_python("server");
}

#[test]
fn pinned_python_client_calls_rust_fixed_registry() {
    python_client_calls_rust("client");
}

#[test]
fn rust_client_calls_pinned_python_product_cell_actor() {
    rust_client_calls_python("cell_server");
}

#[test]
fn pinned_python_product_cell_supervisor_calls_rust_actor() {
    python_client_calls_rust("cell_client");
}
