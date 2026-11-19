//! A fake Codex host for the `codex_host_read` tests: a private Codex home
//! whose control socket speaks just enough WebSocket and JSON-RPC.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use sha1::{Digest as _, Sha1};

use super::{read_snapshot, Probed, Request, Snapshot, Stop};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A private Codex home with a fake host listening on its control socket.
pub(super) struct Host {
    pub(super) _directory: tempfile::TempDir,
    pub(super) home: PathBuf,
    pub(super) requests: Arc<Mutex<Vec<Value>>>,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) thread: Option<JoinHandle<()>>,
}

impl Host {
    pub(super) fn home(&self) -> &str {
        self.home.to_str().unwrap()
    }

    pub(super) fn control(&self) -> PathBuf {
        self.home.join("app-server-control")
    }

    pub(super) fn socket(&self) -> PathBuf {
        self.control().join("app-server-control.sock")
    }

    pub(super) fn marker(&self) -> PathBuf {
        self.control().join("hol-guard-app-server.pid")
    }

    pub(super) fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }

    pub(super) fn methods(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| request["method"].as_str().unwrap().to_owned())
            .collect()
    }

    pub(super) fn set_marker(&self, pid: u32) {
        std::fs::write(self.marker(), pid.to_string()).unwrap();
        std::fs::set_permissions(self.marker(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    pub(super) fn request(&self) -> Request<'_> {
        Request {
            codex_home: self.home(),
            home_dir: None,
            temp_dir: None,
        }
    }

    pub(super) fn read(&self) -> Probed<Snapshot> {
        read_snapshot(&self.request(), Duration::from_secs(5), &|_| Ok(true))
    }

    pub(super) fn read_error(&self) -> Option<Stop> {
        self.read().err()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn exact(stream: &mut UnixStream, size: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn client_message(stream: &mut UnixStream) -> std::io::Result<Value> {
    let head = exact(stream, 2)?;
    assert_eq!(head[0], 0x81);
    assert_ne!(head[1] & 0x80, 0);
    let size = match head[1] & 0x7F {
        126 => usize::from(u16::from_be_bytes(exact(stream, 2)?.try_into().unwrap())),
        127 => usize::try_from(u64::from_be_bytes(exact(stream, 8)?.try_into().unwrap())).unwrap(),
        size => usize::from(size),
    };
    let mask = exact(stream, 4)?;
    let payload: Vec<u8> = exact(stream, size)?
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % 4])
        .collect();
    Ok(serde_json::from_slice(&payload).unwrap())
}

fn host_message(stream: &mut UnixStream, message: &Value) -> std::io::Result<()> {
    let payload = message.to_string().into_bytes();
    let mut frame = vec![0x81];
    match payload.len() {
        0..=125 => frame.push(u8::try_from(payload.len()).unwrap()),
        126..=65535 => {
            frame.push(126);
            frame.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        _ => {
            frame.push(127);
            frame.extend(u64::try_from(payload.len()).unwrap().to_be_bytes());
        }
    }
    frame.extend(payload);
    stream.write_all(&frame)
}

/// Serves every connection until the host is dropped. A client that the
/// reader rejects before its handshake closes its connection at once, and a
/// test that reads again must still find the host listening.
fn serve(
    listener: &UnixListener,
    stop: &AtomicBool,
    requests: &Mutex<Vec<Value>>,
    handler: &(dyn Fn(&Value) -> Value + Send + Sync),
) -> std::io::Result<()> {
    loop {
        match listener.accept() {
            // The client ending the connection is how every exchange finishes.
            Ok((stream, _)) => {
                let _ = exchange(stream, requests, handler);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}

fn exchange(
    mut stream: UnixStream,
    requests: &Mutex<Vec<Value>>,
    handler: &(dyn Fn(&Value) -> Value + Send + Sync),
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.extend(exact(&mut stream, 1)?);
    }
    let headers = String::from_utf8(headers).unwrap();
    let key = headers
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap();
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(GUID.as_bytes());
    let accept = Base64::encode_string(&digest.finalize());
    stream.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    loop {
        let request = client_message(&mut stream)?;
        requests.lock().unwrap().push(request.clone());
        if request.get("id").is_some() {
            host_message(&mut stream, &handler(&request))?;
        }
    }
}

/// Unix socket paths must fit macOS's 104-byte `sockaddr_un` limit, so the
/// directory is short and under `/tmp`.
pub(super) fn host(handler: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Host {
    let directory = tempfile::Builder::new()
        .prefix("hgr")
        .tempdir_in("/tmp")
        .unwrap();
    let home = directory.path().join(".codex");
    let control = home.join("app-server-control");
    std::fs::create_dir_all(&control).unwrap();
    std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = control.join("app-server-control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let (requests, stop) = (requests.clone(), stop.clone());
        std::thread::spawn(move || {
            let _ = serve(&listener, &stop, &requests, &handler);
        })
    };
    let host = Host {
        _directory: directory,
        home,
        requests,
        stop,
        thread: Some(thread),
    };
    host.set_marker(std::process::id());
    host
}

pub(super) fn default_handler(request: &Value) -> Value {
    let result = match request["method"].as_str().unwrap() {
        "initialize" => json!({ "userAgent": "codex/0.159.2" }),
        "app/installed" => json!({ "apps": [
            { "id": "example", "runtimeName": "example-runtime", "enabled": true, "callable": true }
        ] }),
        "app/read" => json!({
            "apps": [{
                "id": "example",
                "name": "Example connector",
                "tools": [{
                    "name": "send_message",
                    "title": "Send a message",
                    "description": "Change external content",
                    "isReadOnly": true,
                    "inputSchema": { "type": "object" },
                }],
            }],
            "missingAppIds": [],
        }),
        other => panic!("unexpected host method {other}"),
    };
    json!({ "id": request["id"], "result": result })
}
