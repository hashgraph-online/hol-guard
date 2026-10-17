use super::*;
use crate::claim_reuse_then_tests::{case, claim, LOCAL_POLICY, ONE_SHOT};
use crate::store_vectors_support_tests::dump_store;
use serde_json::json;

/// A decide request for `tool` with `arguments` in the relay's wire form.
fn request(tool: &str, arguments: Value) -> McpRelayDecideRequestV1 {
    serde_json::from_value(wire(tool, arguments)).unwrap()
}

/// The same request as the relay sends it, which the relay's own gate reads
/// back to evaluate the call.
fn wire(tool: &str, arguments: Value) -> Value {
    json!({
        "guard_home": "/guard",
        "hash_workspace": "/work",
        "build": {
            "harness": "codex",
            "server_name": "files",
            "tool_name": tool,
            "source_scope": "project",
            "config_path": "/work/.codex/config.toml",
            "transport": "stdio",
            "server_id": null,
            "server_fingerprint": null,
            "server_identity": null,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": null},
        },
        "arguments": arguments,
        "path": "/usr/bin:/bin",
        "launcher_home": "/home/user",
        "catalog_state": "present",
        "params": {"name": tool},
    })
}

fn mapping(entries: Value) -> Value {
    json!({"format": "mapping", "entries": entries})
}

/// Whether the gate found a package request. The intent itself is the gate's
/// answer, and `PackageIntent` is not comparable.
fn gate(request: &McpRelayDecideRequestV1) -> Result<bool, &'static str> {
    package_gate(request).map(|intent| intent.is_some())
}

#[test]
fn a_call_without_a_package_intent_goes_on() {
    for (tool, arguments) in [
        ("bash", mapping(json!([["command", "ls -la"]]))),
        ("bash", mapping(json!([["command", "   "]]))),
        ("Shell", json!({"format": "json", "text": "git status"})),
        ("read", mapping(json!([["path", "package.json"]]))),
        // Only a shell tool's other argument keys are read as commands.
        (
            "search",
            mapping(json!([["query", "npm install left-pad"]])),
        ),
        ("read", json!({"format": "other", "value": null})),
    ] {
        assert_eq!(
            gate(&request(tool, arguments.clone())),
            Ok(false),
            "{tool} {arguments}"
        );
    }
}

#[test]
fn a_package_intent_is_the_gate_s_answer() {
    for (tool, arguments) in [
        (
            "bash",
            mapping(json!([["command", "npm install left-pad"]])),
        ),
        (
            "RUN_COMMAND",
            mapping(json!([["argv", ["pip", "install", "requests"]]])),
        ),
        (
            "bash",
            json!({"format": "json", "text": " npm install left-pad "}),
        ),
        // `_command_argument` reads any tool's command keys.
        ("read", mapping(json!([["cmd", "pip install requests"]]))),
        (
            "files",
            mapping(json!([["shellCommand", "  pnpm add left-pad "]])),
        ),
    ] {
        assert_eq!(
            gate(&request(tool, arguments.clone())),
            Ok(true),
            "{tool} {arguments}"
        );
    }
}

/// The relay evaluates the request it sent, so both halves of one call read
/// the same intent out of the same gate.
#[test]
fn the_relay_reads_the_same_intent_out_of_the_request_it_sent() {
    let intent = |tool, arguments| {
        crate::mcp_relay_decide::relayed_package_intent(wire(tool, arguments)).is_some()
    };
    let install = mapping(json!([["command", "npm install left-pad"]]));
    assert!(intent("bash", install));
    assert!(!intent("bash", mapping(json!([["command", "ls -la"]]))));
    // A request the gate refuses carries no intent for the relay either.
    let separated = mapping(json!([["command", "\u{1c}npm install left-pad"]]));
    assert!(!intent("read", separated));
    // Nor does one this process cannot read as a decide request at all.
    assert!(
        crate::mcp_relay_decide::relayed_package_intent(json!({"guard_home": "/guard"})).is_none()
    );
}

#[test]
fn a_command_the_two_strips_read_differently_defers() {
    let separated = mapping(json!([["command", "\u{1c}npm install left-pad"]]));
    assert_eq!(gate(&request("read", separated)), Err(PACKAGE_AMBIGUOUS));
    let nested = mapping(json!([["steps", [{"run": "ls\u{1f}"}]]]));
    assert_eq!(gate(&request("bash", nested)), Err(PACKAGE_AMBIGUOUS));
    let tool = mapping(json!([["command", "ls"]]));
    assert_eq!(gate(&request("\u{1d}bash", tool)), Err(PACKAGE_AMBIGUOUS));
    // Separators inside a command are no stripping matter.
    let inner = mapping(json!([["command", "ls\u{1c}-la"]]));
    assert_eq!(gate(&request("read", inner)), Ok(false));
}

#[test]
fn only_a_resolved_workspace_reaches_the_parser() {
    let call = || request("bash", mapping(json!([["command", "ls"]])));
    for workspace in ["/", "/work", "/work/a.b", "/work/..a"] {
        let mut request = call();
        request.workspace = Some(workspace.to_owned());
        assert_eq!(gate(&request), Ok(false), "{workspace}");
    }
    for workspace in [
        "//work",
        "/work//a",
        "/work/",
        "/work/./a",
        "/work/.",
        "/work/../a",
        "/work/..",
        "work",
        "",
        "/wo\0rk",
    ] {
        let mut request = call();
        request.workspace = Some(workspace.to_owned());
        assert_eq!(gate(&request), Err(WORKSPACE_UNNORMALIZED), "{workspace:?}");
    }
}

#[test]
fn a_package_intent_after_the_claim_rolls_it_back() {
    let intent = request(
        "bash",
        mapping(json!([["command", "npm install left-pad"]])),
    );
    for id in [ONE_SHOT, LOCAL_POLICY] {
        let case = case(id);
        let before = dump_store(&case.connection);
        // As `after_claim` refuses the call the gate now finds a package
        // request in.
        let mut refused = None;
        let answer = claim::<()>(&case, &mut |_| match gate(&intent) {
            Ok(false) => Ok(Some(())),
            Ok(true) => {
                refused = Some(PACKAGE_CLAIMED);
                Ok(None)
            }
            Err(reason) => {
                refused = Some(reason);
                Ok(None)
            }
        });
        assert_eq!(answer.unwrap(), None, "{id}");
        assert_eq!(refused, Some(PACKAGE_CLAIMED), "{id}");
        assert_eq!(dump_store(&case.connection), before, "{id}: nothing spent");
        assert!(case.connection.is_autocommit(), "{id}: no open transaction");
    }
}

#[cfg(unix)]
#[test]
fn a_call_sent_to_the_package_policy_hands_its_server_to_the_proxy() {
    use crate::mcp_relay_servers::{RelayServerV1, SERVER_PROXY_TOOLS, SERVER_UNKNOWN};
    use crate::policy_store::policy_store_direct_lane::tests::fixture;

    let fixture = fixture("relay-package-server");
    let servers = fixture.store.mcp_relay_servers();
    let server = RelayServerV1 {
        harness: "codex".to_owned(),
        server_name: "files".to_owned(),
        source_scope: "project".to_owned(),
        config_path: "/work/.codex/config.toml".to_owned(),
        server_id: None,
        identity_hash: "d".repeat(64),
    };
    let mut call = request(
        "bash",
        mapping(json!([["command", "npm install left-pad"]])),
    );
    super::super::mark_package_server(&call, &fixture.store);
    // A call without a server identity names no server.
    assert_eq!(servers.relayable(&server), Err(SERVER_UNKNOWN));
    call.build.server_identity = Some(
        serde_json::from_value(json!({
            "config_path": "/work/.codex/config.toml",
            "command": "files-mcp",
            "args_hash": "e".repeat(64),
            "package_name": null,
            "package_version": null,
            "package_source": "unknown",
            "transport": "stdio",
            "env_keys": [],
            "env_values_hash": "f".repeat(64),
            "identity_hash": "d".repeat(64),
        }))
        .unwrap(),
    );
    servers.record(&server, false);
    super::super::mark_package_server(&call, &fixture.store);
    assert_eq!(servers.relayable(&server), Err(SERVER_PROXY_TOOLS));
}
