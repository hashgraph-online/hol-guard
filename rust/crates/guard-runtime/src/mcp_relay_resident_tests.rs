use std::collections::BTreeMap;

use guard_contracts::McpToolArgumentsV1;
use serde_json::json;

use super::request::{arguments, delegated_tool, launcher_home, launcher_path};
use super::*;
use crate::mcp_relay_decide::McpRelayDecideRequestV1;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcp_relay_resident_{}_{}_{}",
        std::process::id(),
        tag,
        crate::unique_nanos::unique_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn relay_args(guard_home: &Path, workspace: Option<PathBuf>) -> RelayArgs {
    RelayArgs {
        harness: "codex",
        elicitation_capable: true,
        guard_home: guard_home.to_path_buf(),
        home: None,
        workspace,
        server_name: "files".to_owned(),
        server_id: Some("srv".to_owned()),
        source_scope: "project".to_owned(),
        config_path: "/work/.codex/config.toml".to_owned(),
        transport: "stdio".to_owned(),
        command: "npx".to_owned(),
        args: vec!["-y".to_owned(), "server-files".to_owned()],
        server_env_keys: vec!["API_TOKEN".to_owned(), "REGION".to_owned()],
    }
}

fn launch(identity: Value) -> Launch {
    let launch_env: BTreeMap<String, String> = [
        ("PATH".to_owned(), "/usr/bin".to_owned()),
        ("API_TOKEN".to_owned(), "secret".to_owned()),
    ]
    .into_iter()
    .collect();
    Launch {
        argv: vec!["/usr/bin/npx".to_owned()],
        child_env: launch_env.clone(),
        launch_env,
        identity,
        cwd: PathBuf::from("/"),
    }
}

fn identity() -> Value {
    json!({
        "executable": {"path": "/usr/bin/npx", "sha256": "ab"},
        "launch_cwd": "/work",
        "entrypoint": {"kind": "not-applicable"},
    })
}

fn process(cwd: &Path) -> ProcessFacts {
    ProcessFacts {
        path: Some(OsString::from("/usr/bin:/bin")),
        home: Some(OsString::from("/home/user/")),
        cwd: Some(cwd.to_path_buf()),
    }
}

pub(super) fn facts() -> RelayFacts {
    let guard_home = temp_dir("facts");
    let args = relay_args(&guard_home, None);
    relay_facts(&args, &launch(identity()), &process(&guard_home)).unwrap()
}

fn params(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

#[test]
fn session_facts_bind_the_launch_once() {
    let guard_home = temp_dir("bind");
    let workspace = temp_dir("bind_ws");
    let args = relay_args(&guard_home, Some(workspace.clone()));
    let facts = relay_facts(&args, &launch(identity()), &process(&guard_home)).unwrap();
    let canonical = |path: &Path| {
        std::fs::canonicalize(path)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(facts.guard_home, canonical(&guard_home));
    assert_eq!(facts.workspace.as_deref(), workspace.to_str());
    assert_eq!(facts.hash_workspace, canonical(&workspace));
    assert_eq!(facts.launcher_path.as_deref(), Some("/usr/bin:/bin"));
    assert_eq!(facts.path.as_deref(), Some("/usr/bin:/bin"));
    assert_eq!(facts.launcher_home, "/home/user");
    assert_eq!(
        facts.fingerprint["command"],
        json!(["npx", "-y", "server-files"])
    );
    assert_eq!(
        facts.fingerprint["resolved_executable"],
        json!({
            "path": "/usr/bin/npx",
            "sha256": "ab",
            "command": "npx",
            "launch_cwd": "/work",
            "entrypoint": {"kind": "not-applicable"},
        })
    );
    let hash = facts.fingerprint["configured_env_values_hash"]
        .as_str()
        .unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(
        facts.server_identity["env_values_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        facts.server_identity["env_keys"],
        json!(["API_TOKEN", "REGION"])
    );
    assert_eq!(facts.server_identity["transport"], json!("stdio"));
}

#[test]
fn session_facts_need_the_launch_identity_and_home() {
    let guard_home = temp_dir("need");
    let args = relay_args(&guard_home, None);
    let mut partial = identity();
    partial.as_object_mut().unwrap().remove("launch_cwd");
    assert!(relay_facts(&args, &launch(partial), &process(&guard_home)).is_none());
    let mut homeless = process(&guard_home);
    homeless.home = None;
    assert!(relay_facts(&args, &launch(identity()), &homeless).is_none());
    let missing = relay_args(&guard_home.join("absent"), None);
    assert!(relay_facts(&missing, &launch(identity()), &process(&guard_home)).is_none());
}

#[test]
fn launcher_path_anchors_relative_entries() {
    let mut facts = process(Path::new("/work"));
    assert_eq!(
        launcher_path(&facts),
        Some(Some("/usr/bin:/bin".to_owned()))
    );
    facts.path = Some(OsString::from("node_modules/.bin::/bin"));
    assert_eq!(
        launcher_path(&facts),
        Some(Some("/work/node_modules/.bin::/bin".to_owned()))
    );
    facts.cwd = Some(PathBuf::from("/"));
    assert_eq!(
        launcher_path(&facts),
        Some(Some("/node_modules/.bin::/bin".to_owned()))
    );
    facts.cwd = None;
    assert_eq!(launcher_path(&facts), None);
    facts.path = None;
    assert_eq!(launcher_path(&facts), Some(None));
}

#[test]
fn launcher_home_drops_trailing_separators() {
    assert_eq!(
        launcher_home(&OsString::from("/home/u//")).unwrap(),
        "/home/u"
    );
    assert_eq!(launcher_home(&OsString::from("/")).unwrap(), "/");
    assert_eq!(launcher_home(&OsString::from("")).unwrap(), "/");
}

#[test]
fn only_composio_tools_are_not_sent() {
    for name in ["composio_x", "a__COMPOSIO_SEARCH_TOOLS"] {
        assert!(delegated_tool(name), "{name}");
    }
    // Shell tools reach the resident, whose package check defers an intent.
    for name in ["read", "bash", " Shell ", "RUN_COMMAND", "my_composio_x"] {
        assert!(!delegated_tool(name), "{name}");
    }
    assert!(!delegated_tool("composio__read"));
}

#[test]
fn arguments_keep_the_host_order() {
    let value = json!({"b": 1, "a": "x"});
    let order = ["b".to_owned(), "a".to_owned()];
    assert_eq!(
        arguments(Some(&value), Some(&order[..])),
        Some(McpToolArgumentsV1::Mapping {
            entries: vec![("b".to_owned(), json!(1)), ("a".to_owned(), json!("x"))],
        })
    );
    assert_eq!(arguments(Some(&value), None), None);
    assert_eq!(arguments(Some(&value), Some(&order[..1])), None);
    let wrong = ["b".to_owned(), "c".to_owned()];
    assert_eq!(arguments(Some(&value), Some(&wrong[..])), None);
    let single = json!({"a": [1, -2, 0]});
    assert!(arguments(Some(&single), None).is_some());
    assert_eq!(
        arguments(None, None),
        Some(McpToolArgumentsV1::Other { value: Value::Null })
    );
    assert_eq!(
        arguments(Some(&json!("{\"a\":1}")), None),
        Some(McpToolArgumentsV1::Json {
            text: "{\"a\":1}".to_owned()
        })
    );
    let command = json!({"cmd": "npm install left-pad"});
    assert_eq!(
        arguments(Some(&command), None),
        Some(McpToolArgumentsV1::Mapping {
            entries: vec![("cmd".to_owned(), json!("npm install left-pad"))],
        })
    );
}

#[test]
fn request_matches_the_decide_wire_shape() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    let call = params(json!({"name": "read", "arguments": {"path": "a.txt"}}));
    let (request, expected) = decide_request(&facts, &call, None, &catalog, &no_prompt()).unwrap();
    assert_eq!(expected, catalog.snapshot());
    // The bytes the resident reads wrap the same request in its operation.
    let payload: Value =
        serde_json::from_slice(&request::decide_payload(&request).unwrap()).unwrap();
    assert_eq!(payload["operation"], json!("mcp_relay_decide"));
    assert_eq!(payload["request"], request);
    assert_eq!(
        request["build"]["tool"],
        json!({"kind": "catalog", "entry": null})
    );
    assert_eq!(request["build"]["provider_catalog_hash"], Value::Null);
    let fingerprint = &request["build"]["server_fingerprint"];
    assert_eq!(fingerprint["tool_catalog_state"], json!(expected.state));
    assert_eq!(
        fingerprint["tool_catalog_fingerprint"],
        json!(expected.fingerprint)
    );
    assert_eq!(request["params"], json!(call));
    let decoded: McpRelayDecideRequestV1 = serde_json::from_value(request).unwrap();
    assert_eq!(decoded.build.tool_name, "read");
    assert_eq!(decoded.hash_workspace, facts.hash_workspace);
    assert_eq!(decoded.path.as_deref(), Some("/usr/bin:/bin"));
    let shell = params(json!({"name": "bash", "arguments": {"command": "ls"}}));
    assert!(decide_request(&facts, &shell, None, &catalog, &no_prompt()).is_some());
}

#[test]
fn calls_the_relay_cannot_send_are_not_requested() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    for call in [
        json!({"arguments": {}}),
        json!({"name": "", "arguments": {}}),
        json!({"name": 7}),
        json!({"name": "caf\u{e9}"}),
        json!({"name": "composio_x", "arguments": {}}),
    ] {
        assert!(
            decide_request(&facts, &params(call.clone()), None, &catalog, &no_prompt()).is_none(),
            "{call}"
        );
    }
}

#[test]
fn replies_map_to_forward_or_block() {
    let forward = json!({"schema": RESULT_SCHEMA, "outcome": "forward", "ticket": "e:1"});
    assert_eq!(
        reply(&serde_json::to_vec(&forward).unwrap()),
        Some(Reply::Forward {
            ticket: "e:1".to_owned()
        })
    );
    let block = json!({
        "schema": RESULT_SCHEMA,
        "outcome": "block",
        "message": "blocked",
        "data": {"guardPolicyAction": "block"},
    });
    assert_eq!(
        reply(&serde_json::to_vec(&block).unwrap()),
        Some(Reply::Block {
            message: "blocked".to_owned(),
            data: json!({"guardPolicyAction": "block"}),
        })
    );
    let prompt = json!({"schema": RESULT_SCHEMA, "outcome": "elicit", "params": {"mode": "form"}});
    assert_eq!(
        reply(&serde_json::to_vec(&prompt).unwrap()),
        Some(Reply::Elicit {
            params: json!({"mode": "form"}),
        })
    );
    // The package evaluation the relay performs before the call is decided.
    let evaluate = json!({"schema": RESULT_SCHEMA, "outcome": "evaluate"});
    assert_eq!(
        reply(&serde_json::to_vec(&evaluate).unwrap()),
        Some(Reply::Evaluate { ticket: None })
    );
    // The one a claim asks for carries the ticket its rows are held against
    // again, which the second claim spends.
    let postclaim = json!({"schema": RESULT_SCHEMA, "outcome": "evaluate", "ticket": "claim-1:2"});
    assert_eq!(
        reply(&serde_json::to_vec(&postclaim).unwrap()),
        Some(Reply::Evaluate {
            ticket: Some("claim-1:2".to_owned())
        })
    );
    let claim = json!({"schema": RESULT_SCHEMA, "outcome": "claim", "ticket": "claim-1:1"});
    let held = Some(Reply::Claim {
        ticket: "claim-1:1".to_owned(),
    });
    assert_eq!(reply(&serde_json::to_vec(&claim).unwrap()), held);
    for other in [
        json!({"schema": RESULT_SCHEMA, "outcome": "claim", "ticket": ""}),
        json!({"schema": RESULT_SCHEMA, "outcome": "defer", "reason": "x"}),
        json!({"schema": "other", "outcome": "forward", "ticket": "e:1"}),
        // A forward without a ticket could never be recorded.
        json!({"schema": RESULT_SCHEMA, "outcome": "forward"}),
        json!({"schema": RESULT_SCHEMA, "outcome": "forward", "ticket": ""}),
        json!({"schema": RESULT_SCHEMA, "outcome": "forward", "ticket": 1}),
        json!({"schema": RESULT_SCHEMA, "outcome": "block", "message": "m"}),
        // A prompt the relay cannot raise is no decision.
        json!({"schema": RESULT_SCHEMA, "outcome": "elicit"}),
        json!({"schema": RESULT_SCHEMA, "outcome": "elicit", "params": "form"}),
    ] {
        assert_eq!(reply(&serde_json::to_vec(&other).unwrap()), None);
    }
    assert_eq!(reply(b"not json"), None);
}

#[test]
fn without_a_resident_every_call_is_blocked() {
    let message = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "read", "arguments": {}}});
    let call = params(message["params"].clone());
    let catalog = RelayCatalog::default();
    let expected = ToolCallVerdict::Respond(no_decision_response(message.get("id"), &call));
    let mut unbound = ResidentRelayAuthority {
        facts: None,
        resident: None,
        commits: Commits::default(),
        kick: None,
        warming: false,
        report: None,
        inline_available: false,
        inline_answer: None,
    };
    assert_eq!(unbound.decide(&message, &call, None, &catalog), expected);
    // A claim goes only to the resident that decided the call.
    let ticket = ClaimTicket {
        message: message.clone(),
        expected: catalog.snapshot(),
        claim: "claim-1:1".to_owned(),
        request: json!(null),
    };
    assert_eq!(unbound.claim(ticket), expected);
    let mut unreachable = ResidentRelayAuthority {
        facts: Some(facts()),
        resident: None,
        commits: Commits::default(),
        kick: None,
        warming: false,
        report: None,
        inline_available: false,
        inline_answer: None,
    };
    assert_eq!(
        unreachable.decide(&message, &call, None, &catalog),
        expected
    );
}

fn forward(id: i64, evidence: &str) -> ForwardTicket {
    ForwardTicket {
        message: json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "read", "arguments": {}}}),
        expected: RelayCatalog::default().snapshot(),
        evidence: Some(evidence.to_owned()),
    }
}

fn authority() -> ResidentRelayAuthority {
    ResidentRelayAuthority {
        facts: Some(facts()),
        resident: None,
        commits: Commits::default(),
        kick: None,
        warming: false,
        report: None,
        inline_available: false,
        inline_answer: None,
    }
}

/// A session whose client offers no inline prompt and raised none.
pub(super) fn no_prompt() -> Value {
    json!({"available": false, "answer": null})
}

#[test]
fn only_a_declared_elicitation_capability_offers_the_prompt() {
    let mut relay = authority();
    for (params, available) in [
        (json!({"capabilities": {"elicitation": {}}}), true),
        (
            json!({"capabilities": {"elicitation": {"form": true}}}),
            true,
        ),
        (json!({"capabilities": {"elicitation": true}}), false),
        (json!({"capabilities": {}}), false),
        (json!({"capabilities": null}), false),
        (json!("initialize"), false),
    ] {
        relay.inline_available = !available;
        relay.client_capabilities(Some(&params));
        assert_eq!(relay.inline_available, available, "{params}");
    }
    relay.inline_available = true;
    relay.client_capabilities(None);
    assert!(!relay.inline_available);
}

#[test]
fn the_prompt_answer_waits_for_the_call_that_raised_it() {
    let mut relay = authority();
    assert_eq!(relay.inline_answer, None);
    let approved = json!({"result": {"action": "accept", "content": {"decision": "approve"}}});
    relay.elicited(Some(&approved));
    assert_eq!(relay.inline_answer, Some(InlineReply::Allow));
    // `_request_inline_approval` answers an unanswered prompt with a cancel.
    relay.elicited(None);
    assert_eq!(relay.inline_answer, Some(InlineReply::Fallthrough));
}

#[test]
fn the_request_carries_the_prompt_the_relay_owns() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    let call = params(json!({"name": "read", "arguments": {"path": "a.txt"}}));
    let inline = json!({"available": true, "answer": "denied"});
    let (request, _) = decide_request(&facts, &call, None, &catalog, &inline).unwrap();
    assert_eq!(request["inline"], inline);
    let decoded: McpRelayDecideRequestV1 = serde_json::from_value(request).unwrap();
    assert!(decoded.inline.available);
    assert_eq!(decoded.inline.answer, Some(InlineReply::Denied));
}

#[test]
fn the_second_send_carries_the_evaluation_and_nothing_else_new() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    let call = params(json!({"name": "bash", "arguments": {"command": "npm install left-pad"}}));
    let (request, _) = decide_request(&facts, &call, None, &catalog, &no_prompt()).unwrap();
    let environment: Map<String, Value> = [("PATH".to_owned(), json!("/usr/bin"))]
        .into_iter()
        .collect();
    let evaluation: Map<String, Value> = [("decision".to_owned(), json!("allow"))]
        .into_iter()
        .collect();
    let payload = request::evaluated_request(&request, environment, evaluation).unwrap();
    let payload: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(payload["operation"], json!("mcp_relay_decide"));
    let sent = payload["request"].as_object().unwrap().clone();
    assert_eq!(sent["environment"], json!({"PATH": "/usr/bin"}));
    assert_eq!(sent["package_evaluation"], json!({"decision": "allow"}));
    // Every other field is the request the first send carried, so the two
    // decides of one call are the same call.
    let mut first = sent;
    first.remove("environment");
    first.remove("package_evaluation");
    assert_eq!(Value::Object(first), request);
    // The resident reads the environment and the evaluation as optional, so
    // the first send omits both.
    let decoded: McpRelayDecideRequestV1 = serde_json::from_value(request).unwrap();
    assert!(decoded.environment.is_empty());
    assert!(decoded.package_evaluation.is_none());
}

/// A package claim is sent twice: the round that asks for the evaluation, and
/// the round that carries it and spends the rows held against the new ticket.
#[test]
fn the_second_claim_carries_the_evaluation_and_the_held_ticket() {
    let authority = authority();
    let first: Value =
        serde_json::from_slice(&authority.claim_payload("claim-1:1", None).unwrap()).unwrap();
    assert_eq!(first["operation"], json!("mcp_relay_claim"));
    assert_eq!(first["request"]["ticket"], json!("claim-1:1"));
    let evaluation: Map<String, Value> = [("decision".to_owned(), json!("allow"))]
        .into_iter()
        .collect();
    let second: Value = serde_json::from_slice(
        &authority
            .claim_payload("claim-1:2", Some(evaluation))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second["request"]["ticket"], json!("claim-1:2"));
    assert_eq!(
        second["request"]["package_evaluation"],
        json!({"decision": "allow"})
    );
    // The same claim of the same session: only the ticket its rows are held
    // against and the evaluation it spends them with differ.
    assert_eq!(
        second["request"]["guard_home"],
        first["request"]["guard_home"]
    );
    // The authority reads the evaluation as optional, so the round that asks
    // for it omits it rather than sending an empty one.
    let asked: crate::mcp_relay_claims::McpRelayClaimRequestV1 =
        serde_json::from_value(first["request"].clone()).unwrap();
    assert!(asked.package_evaluation.is_none());
}

/// The process the relay runs in reports its own environment, which the
/// execution context a package policy digests is built from.
#[test]
fn the_relaying_process_reports_its_environment() {
    // A host with a variable this process cannot read as UTF-8 is one the
    // proxy could not have sent either, and reports nothing at all.
    let Some(environment) = request::process_environment() else {
        return;
    };
    let path = std::env::var("PATH").unwrap();
    assert_eq!(environment.get("PATH"), Some(&json!(path)));
}

fn result(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {}})
}

/// Settle with a resident that answers every ticket with `answer`.
fn settle_with(commits: &mut Commits, answer: impl Fn(&str) -> Sent) -> Vec<String> {
    let mut sent = Vec::new();
    commits.settle(|ticket| {
        sent.push(ticket.to_owned());
        answer(ticket)
    });
    sent
}

#[test]
fn a_forward_dropped_at_the_boundary_is_never_committed() {
    let mut authority = authority();
    let dropped = forward(5, "e:1");
    let message = dropped.message.clone();
    assert_eq!(
        authority.boundary_changed(dropped),
        no_decision_response(message.get("id"), &params(message["params"].clone()))
    );
    assert!(authority.commits.due.is_empty());

    assert_eq!(authority.complete(forward(6, "e:2"), result(6)), result(6));
    assert_eq!(authority.commits.due, vec!["e:2".to_owned()]);
}

#[test]
fn a_nested_forward_commits_both_its_own_and_the_outer_record() {
    let mut authority = authority();
    // The outer call is in flight when the child's reverse request carries a
    // nested call, which completes first.
    let outer = forward(1, "e:outer");
    let inner = forward(2, "e:inner");
    assert_eq!(authority.complete(inner, result(2)), result(2));
    assert_eq!(
        settle_with(&mut authority.commits, |_| Sent::Committed),
        vec!["e:inner".to_owned()]
    );
    // A nested call dropped at the boundary leaves the outer ticket intact.
    authority.boundary_changed(forward(3, "e:dropped"));
    assert_eq!(authority.complete(outer, result(1)), result(1));
    assert_eq!(
        settle_with(&mut authority.commits, |_| Sent::Committed),
        vec!["e:outer".to_owned()]
    );
    assert!(authority.commits.due.is_empty() && authority.commits.retained.is_empty());
}

#[test]
fn a_ticket_the_drain_kept_is_retried_after_a_later_forward() {
    let mut commits = Commits::default();
    commits.due.push("e:1".to_owned());
    commits.due.push("e:2".to_owned());
    // The drain is full: nothing after the first refusal is sent.
    assert_eq!(
        settle_with(&mut commits, |_| Sent::Retained),
        vec!["e:1".to_owned()]
    );
    assert_eq!(commits.retained, ["e:1", "e:2"]);
    // Without a new forward nothing is retried.
    assert!(settle_with(&mut commits, |_| Sent::Committed).is_empty());

    commits.due.push("e:3".to_owned());
    let sent = settle_with(&mut commits, |ticket| {
        if ticket == "e:2" {
            Sent::Gone
        } else {
            Sent::Committed
        }
    });
    assert_eq!(sent, ["e:1", "e:2", "e:3"]);
    assert!(commits.due.is_empty() && commits.retained.is_empty());
}

#[test]
fn retained_tickets_are_bounded_and_drop_the_oldest() {
    let mut commits = Commits {
        due: (0..MAX_RETAINED + 2).map(|n| format!("e:{n}")).collect(),
        retained: VecDeque::new(),
    };
    settle_with(&mut commits, |_| Sent::Retained);
    assert_eq!(commits.retained.len(), MAX_RETAINED);
    assert_eq!(commits.retained.front().map(String::as_str), Some("e:2"));
    assert_eq!(
        commits.retained.back().cloned(),
        Some(format!("e:{}", MAX_RETAINED + 1))
    );
}

#[test]
fn commit_answers_map_to_what_the_resident_kept() {
    let answer = |committed: Value, retained: Value| {
        let body =
            json!({"schema": COMMIT_RESULT_SCHEMA, "committed": committed, "retained": retained});
        committed_answer(&body)
    };
    assert_eq!(answer(json!(true), json!(false)), Sent::Committed);
    assert_eq!(answer(json!(false), json!(true)), Sent::Retained);
    assert_eq!(answer(json!(false), json!(false)), Sent::Gone);
    assert_eq!(answer(json!(null), json!(false)), Sent::Retained);
    let foreign = json!({"schema": "other", "committed": false, "retained": false});
    assert_eq!(committed_answer(&foreign), Sent::Retained);
    assert_eq!(committed(b"not json"), Sent::Retained);
    // Without a reachable resident the ticket is kept for a retry.
    assert_eq!(authority().commit("e:1"), Sent::Retained);
}

fn committed_answer(body: &Value) -> Sent {
    committed(&serde_json::to_vec(body).unwrap())
}
