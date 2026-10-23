use gauntlet_dashboard::{http, snapshot::PublicRoot};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;

#[test]
fn stale_public_snapshot_keeps_jobs_and_headroom_visible_without_online_claim() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("snapshot.json"),
        serde_json::to_vec(&json!({
            "schema": "hol-gauntlet-dashboard.v1",
            "updated_at": 100.0,
            "jobs": [{"id": "0123456789abcdef", "state": "running", "phase": "build"}],
            "vm": {"status": "running", "disk_free": 10737418240_u64},
            "allocation": {"vm_cpus": 2, "vm_memory_gib": 16, "vm_disk_gib": 48}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        dir.path().join("feature-audit.json"),
        serde_json::to_vec(&json!({
            "schema": "hol-gauntlet-feature-operations.v1",
            "updated_at": 100.0,
            "status": "running",
            "completed_groups": 7
        }))
        .unwrap(),
    )
    .unwrap();
    let root = PublicRoot::open(dir.path()).unwrap();
    let snapshot = root.snapshot(300.0);
    assert_eq!(snapshot["collector_status"], "stale");
    assert_eq!(snapshot["collector_age_seconds"], 200.0);
    assert_eq!(snapshot["jobs"][0]["phase"], "build");
    assert_eq!(snapshot["allocation"]["vm_memory_gib"], 16);
    assert_eq!(snapshot["vm"]["disk_free"], 10737418240_u64);
    assert_eq!(snapshot["feature_audit"]["telemetry_status"], "stale");
}

#[test]
fn protocol_ingestion_needs_both_retained_cells() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("snapshot.json"),
        br#"{"schema":"hol-gauntlet-dashboard.v1","updated_at":100,"jobs":[]}"#,
    )
    .unwrap();
    let cells = vec![
        json!({"model_ingestion_proven": true, "protocol_exposure_stage": "model-context-forwarded"}),
        json!({"model_ingestion_proven": true, "protocol_exposure_stage": "model-context-forwarded"}),
    ];
    let path = dir.path().join("feature-ai.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schema": "hol-gauntlet-live-operations.v1",
            "profile": "feature-ai-protocol",
            "updated_at": 100,
            "status": "passed",
            "cells": cells
        }))
        .unwrap(),
    )
    .unwrap();
    let root = PublicRoot::open(dir.path()).unwrap();
    assert_eq!(
        root.snapshot(101.0)["feature_ai"]["model_ingestion_proven"],
        true
    );
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schema": "hol-gauntlet-live-operations.v1",
            "profile": "feature-ai-protocol",
            "updated_at": 100,
            "status": "passed",
            "cells": [cells[0]]
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        root.snapshot(101.0)["feature_ai"]["model_ingestion_proven"],
        false
    );
}

#[test]
fn malformed_or_symlinked_public_snapshot_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let root = PublicRoot::open(dir.path()).unwrap();
    assert_eq!(root.snapshot(101.0)["collector_status"], "unavailable");
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        outside.path(),
        br#"{"schema":"hol-gauntlet-dashboard.v1","updated_at":100,"jobs":[]}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("snapshot.json")).unwrap();
    assert_eq!(root.snapshot(101.0)["collector_status"], "unavailable");
}

fn exchange(root: PublicRoot, request: &'static [u8]) -> Vec<u8> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        http::handle(stream, &root).unwrap();
    });
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(request).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    server.join().unwrap();
    response
}

fn body(response: &[u8]) -> Value {
    let offset = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    serde_json::from_slice(&response[offset..]).unwrap()
}

#[test]
fn loopback_api_reports_instance_and_rejects_cross_origin_and_writes() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("dashboard-id.json"),
        br#"{"instance_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
    )
    .unwrap();
    let response = exchange(
        PublicRoot::open(dir.path()).unwrap(),
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert_eq!(
        body(&response)["instance_id"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(body(&response)["collector"], "unavailable");
    let page = exchange(
        PublicRoot::open(dir.path()).unwrap(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(page
        .windows(b"Every check.".len())
        .any(|part| part == b"Every check."));
    assert!(page
        .windows(b"script-src 'self'".len())
        .any(|part| part == b"script-src 'self'"));
    let foreign = exchange(
        PublicRoot::open(dir.path()).unwrap(),
        b"GET /api/status HTTP/1.1\r\nHost: evil.example\r\n\r\n",
    );
    assert!(foreign.starts_with(b"HTTP/1.1 403 Forbidden"));
    let write = exchange(
        PublicRoot::open(dir.path()).unwrap(),
        b"POST /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(write.starts_with(b"HTTP/1.1 501 Unsupported method"));
}
