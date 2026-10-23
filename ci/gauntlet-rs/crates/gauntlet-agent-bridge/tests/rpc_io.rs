use gauntlet_agent_bridge::{
    serve_one, BridgeChannel, BridgeClient, BridgeIoError, BridgeOperation, OperationResult,
};
use gauntlet_evidence::FrameCodec;
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::thread;
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

fn pair() -> (BridgeClient, BridgeChannel) {
    let fixture = fixture();
    let (controller_reader, collector_writer) = UnixStream::pair().unwrap();
    let (collector_reader, controller_writer) = UnixStream::pair().unwrap();
    let client = BridgeClient::new(
        BridgeChannel::new(
            controller_reader.into(),
            controller_writer.into(),
            codec(&fixture, "controller"),
        )
        .unwrap(),
    );
    let server = BridgeChannel::new(
        collector_reader.into(),
        collector_writer.into(),
        codec(&fixture, "product-collector"),
    )
    .unwrap();
    (client, server)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn trusted_registry_serves_success_unknown_failure_and_recovery() {
    let (client, mut server) = pair();
    let worker = thread::spawn(move || {
        let mut calls = 0;
        let mut read_docs = |payload: &Value| -> OperationResult {
            calls += 1;
            if payload["fail"] == true {
                Err("ValueError")
            } else {
                Ok(json!({"path":payload["path"],"ok":true}))
            }
        };
        let mut operations = [BridgeOperation {
            name: "read_docs",
            handler: &mut read_docs,
        }];
        let cancelled = AtomicBool::new(false);
        for expected in ["read_docs", "missing", "read_docs", "read_docs"] {
            assert_eq!(
                serve_one(&mut server, &mut operations, deadline(), &cancelled).unwrap(),
                expected
            );
        }
        calls
    });
    let cancelled = AtomicBool::new(false);
    assert_eq!(
        client
            .call(
                "read_docs",
                &json!({"path":"/public/spec"}),
                Duration::from_secs(2),
                &cancelled,
            )
            .unwrap(),
        json!({"path":"/public/spec","ok":true})
    );
    assert_eq!(
        client
            .call("missing", &json!({}), Duration::from_secs(2), &cancelled)
            .unwrap_err(),
        BridgeIoError::RemoteFailure("unknown-operation")
    );
    assert_eq!(
        client
            .call(
                "read_docs",
                &json!({"fail":true}),
                Duration::from_secs(2),
                &cancelled,
            )
            .unwrap_err(),
        BridgeIoError::RemoteFailure("operation-failed")
    );
    assert_eq!(
        client
            .call(
                "read_docs",
                &json!({"path":"/second"}),
                Duration::from_secs(2),
                &cancelled,
            )
            .unwrap(),
        json!({"path":"/second","ok":true})
    );
    assert_eq!(worker.join().unwrap(), 3);
}

#[test]
fn malformed_response_binding_poisons_the_client_channel() {
    let (client, mut server) = pair();
    let worker = thread::spawn(move || {
        let cancelled = AtomicBool::new(false);
        let request = server.receive("request", deadline(), &cancelled).unwrap();
        server
            .send(
                "response",
                &json!({
                    "request_id":"123e4567-e89b-12d3-a456-426614174000",
                    "operation":request["operation"],
                    "result":{},
                    "error":null,
                }),
                deadline(),
                &cancelled,
            )
            .unwrap();
    });
    let cancelled = AtomicBool::new(false);
    assert!(matches!(
        client.call("read_docs", &json!({}), Duration::from_secs(2), &cancelled),
        Err(BridgeIoError::Frame(_))
    ));
    assert!(matches!(
        client.call("read_docs", &json!({}), Duration::from_secs(2), &cancelled),
        Err(BridgeIoError::Frame(_))
    ));
    worker.join().unwrap();
}

#[test]
fn single_flight_lock_times_out_without_disturbing_first_request() {
    let (client, mut server) = pair();
    let client = Arc::new(client);
    let (started_tx, started_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let cancelled = AtomicBool::new(false);
        let request = server.receive("request", deadline(), &cancelled).unwrap();
        started_tx.send(()).unwrap();
        thread::sleep(Duration::from_millis(150));
        server
            .send(
                "response",
                &json!({
                    "request_id":request["request_id"],
                    "operation":request["operation"],
                    "result":{"ok":true},
                    "error":null,
                }),
                deadline(),
                &cancelled,
            )
            .unwrap();
    });
    let first_client = Arc::clone(&client);
    let first = thread::spawn(move || {
        first_client.call(
            "read_docs",
            &json!({}),
            Duration::from_secs(2),
            &AtomicBool::new(false),
        )
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        client
            .call(
                "read_docs",
                &json!({}),
                Duration::from_millis(30),
                &AtomicBool::new(false),
            )
            .unwrap_err(),
        BridgeIoError::Deadline
    );
    assert_eq!(first.join().unwrap().unwrap(), json!({"ok":true}));
    worker.join().unwrap();
}

#[test]
fn invalid_registry_is_rejected_before_reading_or_poisoning() {
    let (_client, mut server) = pair();
    let mut handler = |_payload: &Value| -> OperationResult { Ok(json!({})) };
    let mut duplicate = |_payload: &Value| -> OperationResult { Ok(json!({})) };
    let mut operations = [
        BridgeOperation {
            name: "read_docs",
            handler: &mut handler,
        },
        BridgeOperation {
            name: "read_docs",
            handler: &mut duplicate,
        },
    ];
    assert_eq!(
        serve_one(
            &mut server,
            &mut operations,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap_err(),
        BridgeIoError::Invalid("fixed trusted operation registry required")
    );
    assert!(!server.poisoned());
}
