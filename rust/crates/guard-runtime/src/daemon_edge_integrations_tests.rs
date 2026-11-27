use guard_contracts::ProviderConnectionStateV1 as State;
use rusqlite::Connection;
use serde_json::json;

use super::*;
use crate::daemon_route_paths::{
    hosted_dashboard_api_path, local_surface_session_allowed, requires_header_token,
};
use crate::hook_evidence_store_gate::STORAGE_GATE_FILE_NAME;
use crate::managed_policy::parse_managed_policy;
use crate::managed_policy_load::ManagedPolicyStatus;
use crate::provider_integration_routes::tests::provider;
use crate::provider_integration_store::{provider_connection, put_connection, ProviderConnection};

const SHIELD: &str = "provider.exampleshield";
const NOW: u64 = 50_000_000;

struct Edge {
    home: tempfile::TempDir,
    config: ReadConfig,
    providers: Vec<CompiledProviderIntegrationV1>,
}

impl Edge {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("guard.db");
        let handshake = json!({
            "schema": super::super::HANDSHAKE_SCHEMA,
            format!("{}_token", "auth"): "integrations-test-value",
            "guard_home": home.path().to_str().unwrap(),
            "store_path": db.to_str().unwrap(),
            "source": "default",
            "busy_timeout_ms": 2000,
        });
        Self {
            config: ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap(),
            providers: vec![provider()],
            home,
        }
    }

    fn store(&self) -> Connection {
        Connection::open(self.home.path().join("guard.db")).unwrap()
    }

    fn call(
        &self,
        managed: Option<&ManagedProviderSettings>,
        method: &str,
        path: &str,
        body: Value,
    ) -> (u16, Value) {
        self.call_verifying(managed, method, path, body, &|_| {
            panic!("no provider call expected")
        })
    }

    fn call_verifying(
        &self,
        managed: Option<&ManagedProviderSettings>,
        method: &str,
        path: &str,
        body: Value,
        verify: Verify<'_>,
    ) -> (u16, Value) {
        self.call_with(managed, method, path, body, verify, &|_, _| {
            panic!("no lookup expected")
        })
    }

    fn call_with(
        &self,
        managed: Option<&ManagedProviderSettings>,
        method: &str,
        path: &str,
        body: Value,
        verify: Verify<'_>,
        with_transport: WithTransport<'_>,
    ) -> (u16, Value) {
        let body = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        serve(
            &self.config,
            &Served {
                enabled: true,
                managed,
                providers: &self.providers,
                now_ms: NOW,
                verify,
                with_transport,
            },
            method,
            path,
            &body,
        )
    }
}

fn state(status: ManagedPolicyStatus, settings: Option<Value>) -> ManagedPolicyState {
    let mut state = ManagedPolicyState::new(status, "fixture", "fixture_reason");
    state.policy = settings.map(|payload| parse_managed_policy(&payload).unwrap());
    state
}

#[test]
fn provider_routes_need_the_header_token_and_are_never_hosted() {
    for path in [
        "/v1/integrations/providers",
        "/v1/integrations/providers/provider.exampleshield",
        "/v1/integrations/providers/provider.exampleshield/disconnect",
    ] {
        assert!(requires_header_token(path), "{path}");
        assert!(!hosted_dashboard_api_path(path), "{path}");
        assert!(local_surface_session_allowed("POST", path), "{path}");
    }
    assert!(owns("GET", "/v1/integrations/providers"));
    assert!(!owns("DELETE", "/v1/integrations/providers"));
}

#[test]
fn the_list_creates_the_tables_in_the_daemon_store() {
    let edge = Edge::new();
    let none = ManagedProviderSettings::none();
    let (status, body) = edge.call(
        Some(&none),
        "GET",
        "/v1/integrations/providers",
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["providers"][0]["id"], SHIELD);
    assert_eq!(provider_connection(&edge.store(), SHIELD).unwrap(), None);
}

#[test]
fn a_proof_issued_on_one_request_is_spent_on_the_next() {
    let edge = Edge::new();
    let none = ManagedProviderSettings::none();
    edge.call(
        Some(&none),
        "GET",
        "/v1/integrations/providers",
        Value::Null,
    );
    put_connection(
        &edge.store(),
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: format!("{:064x}", 7),
            state: State::Connected,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    let base = format!("/v1/integrations/providers/{SHIELD}");
    let (status, preview) = edge.call(
        Some(&none),
        "POST",
        &format!("{base}/disconnect/preview"),
        Value::Null,
    );
    assert_eq!(status, 200, "{preview}");
    let proof = preview["challenge"].as_str().unwrap().to_owned();

    let disconnect = format!("{base}/disconnect");
    let (status, body) = edge.call(Some(&none), "POST", &disconnect, json!({"proof": proof}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(provider_connection(&edge.store(), SHIELD).unwrap(), None);

    let (status, _) = edge.call(Some(&none), "POST", &disconnect, json!({"proof": proof}));
    assert_ne!(status, 200, "a proof is spent once");
}

#[test]
fn an_unknown_managed_policy_refuses_every_route() {
    let edge = Edge::new();
    let (status, body) = edge.call(None, "GET", "/v1/integrations/providers", Value::Null);
    assert_eq!(status, 503);
    assert_eq!(body["error"], MANAGED_POLICY_UNAVAILABLE);
    assert!(
        !edge.home.path().join("guard.db").exists(),
        "nothing is opened"
    );
}

#[test]
fn managed_settings_fail_closed() {
    assert_eq!(
        managed_settings(&state(ManagedPolicyStatus::Absent, None)),
        Some(ManagedProviderSettings::none())
    );
    for status in [
        ManagedPolicyStatus::Invalid,
        ManagedPolicyStatus::Inaccessible,
        ManagedPolicyStatus::Tampered,
    ] {
        assert_eq!(managed_settings(&state(status, None)), None);
    }
    let schema = crate::managed_policy::POLICY_SCHEMA_VERSION;
    let malformed = state(
        ManagedPolicyStatus::Active,
        Some(json!({"schemaVersion": schema, "settings": {"provider_integrations": "enforce"}})),
    );
    assert_eq!(managed_settings(&malformed), None);

    let locked = state(
        ManagedPolicyStatus::Active,
        Some(json!({
            "schemaVersion": schema,
            "settings": {"provider_integrations": [
                {"provider_id": SHIELD, "capability": "browser.origin-reputation", "effect": "enforce"}
            ]},
            "lockedSettings": ["provider_integrations"],
        })),
    );
    let settings = managed_settings(&locked).unwrap();
    assert!(settings.is_locked());
}

#[test]
fn connect_calls_the_provider_outside_the_store_and_stores_after() {
    let edge = Edge::new();
    let none = ManagedProviderSettings::none();
    let base = format!("/v1/integrations/providers/{SHIELD}");
    let (status, preview) = edge.call(
        Some(&none),
        "POST",
        &format!("{base}/connect/preview"),
        Value::Null,
    );
    assert_eq!(status, 200, "{preview}");
    let key = format!("fixture-edge-{}", "d".repeat(24));
    let body = json!({"key": key, "proof": preview["challenge"]});
    let connect = format!("{base}/connect");

    let refused: Verify<'_> = &|_| {
        Err(crate::provider_integration_routes::RouteAnswer {
            status: 429,
            body: json!({"error": "provider_rate_limited"}),
        })
    };
    let (status, _) = edge.call_verifying(Some(&none), "POST", &connect, body.clone(), refused);
    assert_eq!(status, 429);
    assert_eq!(provider_connection(&edge.store(), SHIELD).unwrap(), None);

    let (status, preview) = edge.call(
        Some(&none),
        "POST",
        &format!("{base}/connect/preview"),
        Value::Null,
    );
    assert_eq!(status, 200);
    let body = json!({"key": key, "proof": preview["challenge"]});
    let gate_free: Verify<'_> = &|prepared| {
        assert_eq!(prepared.provider().id, SHIELD);
        // The gate is a shared lock, so only an exclusive probe shows nobody holds it.
        let gate = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(edge.home.path().join(STORAGE_GATE_FILE_NAME))
            .unwrap();
        assert!(
            fs2::FileExt::try_lock_exclusive(&gate).is_ok(),
            "no storage gate hold during the call"
        );
        fs2::FileExt::unlock(&gate).unwrap();
        assert!(
            ledger().try_lock().is_ok(),
            "the proof ledger is free during the call"
        );
        Ok(true)
    };
    let (status, answer) = edge.call_verifying(Some(&none), "POST", &connect, body, gate_free);
    assert_eq!(status, 200, "{answer}");
    let stored = provider_connection(&edge.store(), SHIELD).unwrap().unwrap();
    assert_eq!(stored.state, State::Connected);
    assert_eq!(stored.last_verified_at_ms, Some(NOW));
}

#[test]
fn approval_link_sessions_cannot_reach_provider_routes() {
    for (method, path) in [
        ("GET", "/v1/integrations/providers"),
        ("GET", "/v1/integrations/providers/provider.exampleshield"),
        (
            "POST",
            "/v1/integrations/providers/provider.exampleshield/disconnect",
        ),
    ] {
        for (claims, allowed) in [
            (json!({"surface": "dashboard"}), true),
            (
                json!({"surface": "approval-center", "request_id": "request-1"}),
                false,
            ),
        ] {
            let frame = json!({"operation": "daemon_route", "request": {
                "schema": "guard-daemon-route-request.v1", "request_id": "route-providers",
                "query": {"kind": "session_authorize", "method": method, "path": path,
                    "claims": claims, "payload": null}}});
            let output: Value = serde_json::from_slice(
                &crate::resident_protocol::evaluate_resident_bytes(
                    frame.to_string().as_bytes(),
                    None,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                output["payload"]["allowed"], allowed,
                "{method} {path} {claims}"
            );
        }
    }
}

#[test]
fn the_test_route_runs_one_lookup_under_the_store() {
    let edge = Edge::new();
    let none = ManagedProviderSettings::none();
    let fake = guard_provider_integrations::testkit::FakeProvider::new(
        &["api.exampleshield.example"],
        "fixture-unused-key-value-000000",
    );
    let path = format!("/v1/integrations/providers/{SHIELD}/test");
    let body = json!({"capability": "browser.origin-reputation",
                      "origin": "https://storefront.example-org.com"});
    let (status, answer) = edge.call_with(
        Some(&none),
        "POST",
        &path,
        body,
        &|_| panic!("no verify expected"),
        &|provider, send| {
            assert_eq!(provider.id, SHIELD);
            send(&fake)
        },
    );
    assert_eq!(
        (status, &answer["error"]),
        (409, &json!("provider_not_connected"))
    );
    assert!(
        fake.requests().is_empty(),
        "an unconnected provider is never called"
    );
}
