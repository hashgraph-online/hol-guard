use super::*;
use crate::oauth::refresh::http_tests::{agent, response};
use crate::oauth::worker_input_tests::{command, credential};

#[test]
fn disconnect_posts_refresh_material_only_to_fixed_project_revocation_endpoint() {
    for refresh in [true, false] {
        let mut original = credential("subject-one");
        let expected = if refresh {
            original.refresh_token.as_ref().unwrap().as_str().to_owned()
        } else {
            original.refresh_token = None;
            original.access_token.as_str().to_owned()
        };
        let account = GoogleSendAccount::new(original).unwrap();
        let pending = account
            .prepare_command(command("sender@work.example", "pending"))
            .unwrap();
        let (agent, wire) = agent(vec![response(200, "text/plain", "")]);
        assert_eq!(
            account.disconnect_with_agent(&agent),
            GoogleProjectGrantRevocation::Acknowledged
        );
        assert!(!pending.is_current());
        let wire = wire.lock().unwrap();
        assert_eq!(wire.urls, [REVOKE_URL]);
        assert_eq!(wire.requests.len(), 1);
        let request = std::str::from_utf8(&wire.requests[0]).unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("POST /revoke HTTP/1.1\r\n"));
        assert!(!headers.contains(&expected));
        let headers = headers.to_ascii_lowercase();
        assert!(headers
            .lines()
            .any(|line| line == "content-type: application/x-www-form-urlencoded"));
        assert!(!headers.contains("authorization:"));
        let pairs: Vec<_> = oauth2::url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "token");
        assert_eq!(pairs[0].1, expected);
    }
}

#[test]
fn maximum_length_percent_encoded_token_is_sent_without_truncation() {
    let mut original = credential("subject-one");
    let expected = "%".repeat(8192);
    original.refresh_token = Some(Zeroizing::new(expected.clone()));
    let account = GoogleSendAccount::new(original).unwrap();
    let (agent, wire) = agent(vec![response(200, "text/plain", "")]);
    assert_eq!(
        account.disconnect_with_agent(&agent),
        GoogleProjectGrantRevocation::Acknowledged
    );
    let wire = wire.lock().unwrap();
    let request = std::str::from_utf8(&wire.requests[0]).unwrap();
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    assert_eq!(body.len(), 6 + 3 * expected.len());
    let pairs: Vec<_> = oauth2::url::form_urlencoded::parse(body.as_bytes()).collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].1, expected);
}

#[test]
fn failure_or_redirect_keeps_pending_inputs_revoked_and_never_retries() {
    for reply in [
        response(400, "application/json", "{}"),
        response(429, "application/json", "{}"),
        response(503, "application/json", "{}"),
        b"HTTP/1.1 302 Found\r\nLocation: https://untrusted.example/revoke\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        b"invalid HTTP framing\r\n\r\n".to_vec(),
    ] {
        let account = GoogleSendAccount::new(credential("subject-one")).unwrap();
        let pending = account.prepare_command(command("sender@work.example", "pending")).unwrap();
        let (agent, wire) = agent(vec![reply]);
        assert_eq!(account.disconnect_with_agent(&agent), GoogleProjectGrantRevocation::Unconfirmed);
        assert!(!pending.is_current());
        assert_eq!(wire.lock().unwrap().requests.len(), 1);
    }
}

#[test]
fn expired_access_and_local_revocation_do_not_prevent_explicit_project_disconnect() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = account
        .prepare_command(command("sender@work.example", "pending"))
        .unwrap();
    account.revoke();
    account.credential.expires_at = 0;
    assert!(!account.is_current());
    let (agent, wire) = agent(vec![response(200, "application/json", "")]);
    assert_eq!(
        account.disconnect_with_agent(&agent),
        GoogleProjectGrantRevocation::Acknowledged
    );
    assert!(!pending.is_current());
    assert_eq!(wire.lock().unwrap().requests.len(), 1);
}

#[test]
fn disconnect_waits_for_admitted_send_before_provider_revocation() {
    let account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = account
        .prepare_command(command("sender@work.example", "pending"))
        .unwrap();
    let active = account.active.clone();
    let send_lease = active.read().unwrap();
    let (agent, wire) = agent(vec![response(200, "text/plain", "")]);
    let (started, starting) = std::sync::mpsc::channel();
    let (done, completed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        done.send(account.disconnect_with_agent(&agent)).unwrap();
    });
    starting.recv().unwrap();
    assert!(completed
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    assert!(wire.lock().unwrap().requests.is_empty());
    drop(send_lease);
    assert_eq!(
        completed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap(),
        GoogleProjectGrantRevocation::Acknowledged
    );
    worker.join().unwrap();
    assert!(!pending.is_current());
    assert_eq!(wire.lock().unwrap().requests.len(), 1);
}

#[test]
fn unusable_token_still_revokes_locally_without_provider_request() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = account
        .prepare_command(command("sender@work.example", "pending"))
        .unwrap();
    account.credential.refresh_token = Some(Zeroizing::new("".into()));
    let (agent, wire) = agent(Vec::new());
    assert_eq!(
        account.disconnect_with_agent(&agent),
        GoogleProjectGrantRevocation::Unconfirmed
    );
    assert!(!pending.is_current());
    assert!(wire.lock().unwrap().requests.is_empty());
}
