use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn authenticated_unix_request_retains_kernel_identity_over_payload_claims() {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let token = [37; crate::AUTH_TOKEN_BYTES];
    let worker = std::thread::spawn(move || {
        authenticate_resident_stream(&mut server, &token).unwrap();
        let mut pending = read_request_header(Box::new(server)).unwrap();
        let mut payload = vec![0; pending.length];
        pending.stream.read_exact(&mut payload).unwrap();
        assert_eq!(Sha256::digest(&payload).as_slice(), pending.request_digest);
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["peer_uid"], u32::MAX);
        let peer = pending.kernel_peer_identity().unwrap();
        assert_eq!(peer.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(peer.gid(), nix::unistd::getegid().as_raw());
        assert_ne!(peer.uid(), u32::MAX);
        assert_ne!(peer.gid(), u32::MAX);
    });
    client.set_read_timeout(Some(crate::AUTH_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(crate::AUTH_TIMEOUT)).unwrap();
    let nonce = [11; crate::AUTH_NONCE_BYTES];
    client.write_all(&nonce).unwrap();
    let mut proof = [0; crate::AUTH_PROOF_BYTES];
    client.read_exact(&mut proof).unwrap();
    assert_eq!(
        proof,
        hmac_sha256(&token, crate::SERVER_PROOF_LABEL, &nonce)
    );
    client
        .write_all(&hmac_sha256(&token, crate::CLIENT_PROOF_LABEL, &nonce))
        .unwrap();
    let payload = br#"{"peer_uid":4294967295,"peer_gid":4294967295}"#;
    let mut header = Vec::new();
    header.extend_from_slice(crate::REQUEST_MAGIC);
    header.extend_from_slice(&[19; crate::FRAME_REQUEST_ID_BYTES]);
    header.extend_from_slice(&Sha256::digest(payload));
    header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    client.write_all(&header).unwrap();
    client.write_all(payload).unwrap();
    worker.join().unwrap();
}

#[test]
fn tcp_connection_has_no_unix_peer_identity() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        assert!(stream.kernel_peer_identity().unwrap().is_none());
    }
}
