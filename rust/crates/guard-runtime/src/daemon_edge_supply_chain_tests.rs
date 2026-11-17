use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;

struct Run {
    reply: Option<Option<Reply>>,
    seen: Vec<String>,
    gated: usize,
}

fn drive(
    home: &str,
    path: &str,
    body: Value,
    steps: &[(&str, Value)],
    refuse: Option<(u16, Value)>,
) -> Run {
    let by_name: HashMap<String, Value> = steps
        .iter()
        .map(|(name, answer)| ((*name).to_owned(), answer.clone()))
        .collect();
    let mut seen = Vec::new();
    let mut gated = 0;
    let mut call = |name: &str, _args: Value| {
        seen.push(name.to_owned());
        by_name.get(name).cloned().ok_or(CallError::Unavailable)
    };
    let mut check = |_: &Map<String, Value>| {
        gated += 1;
        Some(match &refuse {
            Some((status, Value::Object(body))) => Gate::Refused(*status, body.clone()),
            _ => Gate::Passed(None),
        })
    };
    let Value::Object(payload) = body else {
        unreachable!()
    };
    let mut host = Host {
        call: &mut call,
        gate: &mut check,
        guard_home: home,
        args: Map::new(),
    };
    let reply = if payload.is_empty() && path.ends_with("entitlement") {
        route_get(path, &mut host)
    } else {
        route_post(path, &payload, &mut host)
    };
    Run { reply, seen, gated }
}

fn home(tag: &str) -> String {
    format!("/hg-supply-chain-test/{tag}")
}

fn ready(operation_allowed: bool) -> Value {
    json!({
        "entitlement": {"allowed": true},
        "supported_managers": ["npm", "pnpm"],
        "workspace_id": "w",
        "workspace": "ok",
        "access": {
            "operation_allowed": operation_allowed,
            "block": [402, "package_firewall_upgrade_required", "Upgrade first."],
            "available_actions": ["status"],
            "action_states": {},
        },
    })
}

fn answered(run: Run) -> (u16, Value) {
    run.reply.flatten().unwrap_or_else(|| unreachable!())
}

#[test]
fn an_install_passes_the_gate_and_reports_its_receipt() {
    let run = drive(
        &home("install"),
        "/v1/supply-chain/package-shims/install",
        json!({"workspace_id": "w1", "managers": [" NPM "]}),
        &[
            ("supply_chain.prepare", ready(true)),
            (
                "supply_chain.run",
                json!({"result": {"ok": true}, "receipt": {"id": "r"}}),
            ),
        ],
        None,
    );
    assert_eq!(run.gated, 1);
    assert_eq!(run.seen, vec!["supply_chain.prepare", "supply_chain.run"]);
    let (status, body) = answered(run);
    assert_eq!(status, 200);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["operation"], "install");
    assert_eq!(body["receipt"]["id"], "r");
}

#[test]
fn uninstall_maps_to_remove_and_a_refused_gate_stops_it() {
    let run = drive(
        &home("uninstall"),
        "/v1/supply-chain/package-shims/uninstall",
        json!({"workspace_id": "w1"}),
        &[("supply_chain.prepare", ready(true))],
        Some((403, json!({"error": "approval_gate_required"}))),
    );
    assert!(!run.seen.contains(&"supply_chain.run".to_owned()));
    let (status, body) = answered(run);
    assert_eq!(status, 403);
    assert_eq!(body["error"], "approval_gate_required");
}

#[test]
fn a_blocked_operation_names_the_block_and_actions() {
    let run = drive(
        &home("blocked"),
        "/v1/supply-chain/package-shims/test",
        json!({"workspace_id": "w1"}),
        &[("supply_chain.prepare", ready(false))],
        None,
    );
    assert_eq!(run.gated, 0);
    let (status, body) = answered(run);
    assert_eq!(status, 402);
    assert_eq!(body["error"], "package_firewall_upgrade_required");
    assert_eq!(body["available_actions"], json!(["status"]));
    assert_eq!(body["operation"], "test");
}

#[test]
fn managers_are_validated_before_the_gate() {
    for (managers, error) in [
        (json!("npm"), "invalid_managers"),
        (json!([]), "invalid_managers"),
        (json!(["npm", "NPM"]), "duplicate_manager"),
        (json!(["cargo"]), "unsupported_manager"),
    ] {
        let run = drive(
            &home(&format!("managers-{error}-{managers}")),
            "/v1/supply-chain/package-shims/install",
            json!({"workspace_id": "w1", "managers": managers}),
            &[("supply_chain.prepare", ready(true))],
            None,
        );
        assert_eq!(run.gated, 0);
        assert_eq!(
            answered(run),
            (400, json!({"error": error, "operation": "install"}))
        );
    }
}

#[test]
fn the_thirty_first_action_in_a_minute_is_rate_limited() {
    let home = home("rate");
    let steps = [
        (
            "supply_chain.run",
            json!({"result": {"audit_status": "incomplete"}, "receipt": {}, "cloud_sync": {"status": "queued"}}),
        ),
        ("supply_chain.prepare", ready(true)),
    ];
    for _ in 0..RATE_LIMIT {
        let (status, body) = answered(drive(
            &home,
            "/v1/supply-chain/audit",
            json!({"workspaceId": "w2"}),
            &steps,
            None,
        ));
        assert_eq!(status, 200);
        assert_eq!(body["status"], "incomplete");
        assert_eq!(body["cloud_sync"]["status"], "queued");
    }
    let (status, body) = answered(drive(
        &home,
        "/v1/supply-chain/audit",
        json!({"workspaceId": "w2"}),
        &steps,
        None,
    ));
    assert_eq!(status, 429);
    assert_eq!(body["error"], "rate_limited");
    assert!(body["retry_after_seconds"].as_u64().unwrap_or_default() >= 1);
}

#[test]
fn a_change_already_running_is_a_conflict() {
    let home = home("busy");
    let held = hold(&home);
    assert!(held.is_some());
    let run = drive(
        &home,
        "/v1/supply-chain/sync",
        json!({}),
        &[("supply_chain.prepare", ready(true))],
        None,
    );
    assert!(run.seen.is_empty());
    let (status, body) = answered(run);
    assert_eq!(status, 409);
    assert_eq!(body["error"], "operation_in_progress");
    assert_eq!(body["operation"], "sync");
    drop(held);
    assert!(hold(&home).is_some());
}

#[test]
fn the_workspace_falls_back_to_the_library_answer() {
    let run = drive(
        &home("fallback"),
        "/v1/supply-chain/package-shims/test",
        json!({}),
        &[
            ("supply_chain.workspace_id", json!({"workspace_id": null})),
            (
                "supply_chain.prepare",
                json!({"entitlement": {}, "workspace": "invalid", "error": "workspace_dir_required"}),
            ),
        ],
        None,
    );
    assert_eq!(run.seen[0], "supply_chain.workspace_id");
    let (status, body) = answered(run);
    assert_eq!(status, 400);
    assert_eq!(body["error"], "workspace_dir_required");
    assert!(body["message"]
        .as_str()
        .unwrap_or_default()
        .starts_with("Guard needs"));
}

#[test]
fn missing_access_is_authority_unavailable() {
    let run = drive(
        &home("authority"),
        "/v1/supply-chain/package-shims/test",
        json!({"workspace_id": "w"}),
        &[(
            "supply_chain.prepare",
            json!({"entitlement": {"allowed": false}, "workspace": "ok", "access": null}),
        )],
        None,
    );
    let (status, body) = answered(run);
    assert_eq!(status, 503);
    assert_eq!(body["error"], AUTHORITY_UNAVAILABLE);
    assert_eq!(body["available_actions"], json!([]));
}

#[test]
fn repair_all_reports_incomplete_until_repaired() {
    let run = drive(
        &home("repair-all"),
        "/v1/supply-chain/repair",
        json!({"workspace_id": "w"}),
        &[
            ("supply_chain.prepare", ready(true)),
            (
                "supply_chain.repair_all",
                json!({"result": {"repaired": false}, "receipt": {"id": "x"}}),
            ),
        ],
        None,
    );
    assert_eq!(run.gated, 1);
    let (status, body) = answered(run);
    assert_eq!(status, 200);
    assert_eq!(body["operation"], "repair_all");
    assert_eq!(body["status"], "incomplete");
}

#[test]
fn choose_folder_replies() {
    for (answer, status, error) in [
        (json!({"picker": "busy"}), 409, Some("folder_picker_busy")),
        (
            json!({"picker": "unavailable"}),
            503,
            Some("folder_picker_unavailable"),
        ),
        (json!({"picker": "cancelled"}), 200, None),
        (
            json!({"picker": "chosen", "workspace": "invalid", "error": "workspace_dir_invalid"}),
            400,
            Some("workspace_dir_invalid"),
        ),
    ] {
        let run = drive(
            &home("folder"),
            "/v1/supply-chain/choose-folder",
            json!({"x": 1}),
            &[("supply_chain.choose_folder", answer)],
            None,
        );
        let (got, body) = answered(run);
        assert_eq!(got, status);
        assert_eq!(body["error"].as_str(), error);
    }
    let run = drive(
        &home("folder"),
        "/v1/supply-chain/choose-folder",
        json!({"x": 1}),
        &[(
            "supply_chain.choose_folder",
            json!({"picker": "chosen", "workspace": "ok", "workspace_dir": "/w"}),
        )],
        None,
    );
    assert_eq!(
        answered(run),
        (
            200,
            json!({"cancelled": false, "operation": "choose-folder", "workspace_dir": "/w"})
        )
    );
}

#[test]
fn status_and_entitlement_reads() {
    let run = drive(
        &home("status"),
        "/v1/supply-chain/entitlement",
        json!({}),
        &[("supply_chain.entitlement", json!({"allowed": true}))],
        None,
    );
    assert_eq!(answered(run), (200, json!({"allowed": true})));
    let mut steps = HashMap::new();
    steps.insert(
        "supply_chain.status".to_owned(),
        json!({
            "entitlement": {}, "workspace": "ok", "audit_workspace_dir": "/w",
            "connect_flow": {}, "supported_managers": ["npm"], "package_shims": {},
            "access": {"action_states": {"install": "ready"}},
        }),
    );
    let mut call = |name: &str, _: Value| steps.get(name).cloned().ok_or(CallError::Unavailable);
    let mut check = |_: &Map<String, Value>| None;
    let mut host = Host {
        call: &mut call,
        gate: &mut check,
        guard_home: "/hg-supply-chain-test/status",
        args: Map::new(),
    };
    let (status, body) = route_get("/v1/supply-chain/package-shims", &mut host)
        .flatten()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(status, 200);
    assert_eq!(body["actions"]["install"], "ready");
    assert_eq!(body["cli_fallback"]["connect"], "hol-guard connect");
}

#[test]
fn connect_and_unknown_paths_are_not_answered_and_libraries_relay() {
    let run = drive(
        &home("connect"),
        "/v1/supply-chain/package-shims/connect",
        json!({"x": 1}),
        &[],
        None,
    );
    assert!(run.reply.is_none());
    let run = drive(
        &home("other"),
        "/v1/supply-chain/other",
        json!({"x": 1}),
        &[],
        None,
    );
    assert!(run.reply.is_none());
    let run = drive(
        &home("relay"),
        "/v1/supply-chain/package-shims/test",
        json!({"workspace_id": "w"}),
        &[],
        None,
    );
    assert_eq!(run.reply, Some(None));
}

#[test]
fn a_remediation_routes_the_manager_through_the_gate() {
    let run = drive(
        &home("remediate"),
        "/v1/audit/remediations/package_shim_path",
        json!({"manager": " NPM "}),
        &[
            ("supply_chain.prepare", ready(false)),
            (
                "supply_chain.remediate",
                json!({"result": {"manager": "NPM"}, "receipt": {"id": "r"}}),
            ),
        ],
        None,
    );
    assert_eq!(run.gated, 1);
    assert_eq!(
        run.seen,
        vec!["supply_chain.prepare", "supply_chain.remediate"]
    );
    let (status, body) = answered(run);
    assert_eq!(status, 200);
    assert_eq!(body["operation"], "package_shim_path");
    assert_eq!(body["status"], "completed");
}

#[test]
fn a_remediation_refuses_a_missing_or_unknown_manager_and_a_blocked_plan() {
    let path = "/v1/audit/remediations/package_shim_path";
    let run = drive(&home("r-missing"), path, json!({"manager": " "}), &[], None);
    assert_eq!(
        answered(run),
        (
            400,
            json!({"error": "missing_manager", "operation": "package_shim_path"})
        )
    );
    let run = drive(
        &home("r-unknown"),
        path,
        json!({"manager": "cargo"}),
        &[("supply_chain.prepare", ready(true))],
        None,
    );
    assert_eq!(answered(run).1["error"], "unsupported_manager");
    let mut blocked = ready(false);
    blocked["entitlement"]["allowed"] = json!(false);
    let run = drive(
        &home("r-blocked"),
        path,
        json!({"manager": "npm"}),
        &[("supply_chain.prepare", blocked)],
        None,
    );
    assert_eq!(run.gated, 0);
    let (status, body) = answered(run);
    assert_eq!(status, 402);
    assert_eq!(body["operation"], "package_shim_path");
    assert!(drive(
        &home("r-other"),
        "/v1/audit/remediations/other",
        json!({"x": 1}),
        &[],
        None
    )
    .reply
    .is_none());
}
