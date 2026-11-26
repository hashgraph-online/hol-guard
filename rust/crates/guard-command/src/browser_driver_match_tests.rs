use serde_json::{json, Value};

use super::*;
use crate::browser_driver_compile::{compile_browser_driver, BrowserDriverOrigin};

fn profile(id: &str, matches: Value, tools: Value) -> Value {
    json!({
        "schemaVersion": "guard.browser-driver.v1",
        "id": id,
        "name": "Example browser tools",
        "publisher": {"name": "Example Org", "verified": false},
        "match": matches,
        "profileMode": {"default": "unknown"},
        "tools": tools
    })
}

fn compile(value: &Value, origin: BrowserDriverOrigin) -> CompiledBrowserDriverV1 {
    let bytes = serde_json::to_vec(value).unwrap();
    compile_browser_driver(&bytes, origin, &[]).expect("fixture profile compiles")
}

fn matches(servers: &[&str], packages: &[&str], namespaces: &[&str], harness: &[&str]) -> Value {
    json!({
        "mcpServerNames": servers,
        "packages": packages,
        "toolNamespaces": namespaces,
        "harnessTools": harness
    })
}

fn pilot() -> CompiledBrowserDriverV1 {
    compile(
        &profile(
            "browser.example-pilot",
            matches(
                &["example-pilot"],
                &["@example-org/pilot-mcp"],
                &["mcp__example-pilot__"],
                &[],
            ),
            json!([
                {"name": "open_page", "verb": "Navigate", "url": ["url"]},
                {"name": "press", "verb": "Click"}
            ]),
        ),
        BrowserDriverOrigin::Contributed,
    )
}

fn call<'a>(harness_tool_name: &'a str) -> BrowserToolCallIdentity<'a> {
    BrowserToolCallIdentity {
        harness_tool_name,
        ..Default::default()
    }
}

#[test]
fn resolves_each_identity_kind() {
    let drivers = [pilot()];
    let by_server = BrowserToolCallIdentity {
        harness_tool_name: "mcp__renamed__open_page",
        mcp_server_name: Some("example-pilot"),
        mcp_tool_name: Some("open_page"),
        package: None,
    };
    let found = match_browser_driver(&drivers, &by_server).expect("server name matches");
    assert_eq!(found.kind, BrowserDriverMatchKind::McpServerName);
    assert_eq!(found.tool_name, "open_page");
    assert!(found.tool.is_some());

    let by_package = BrowserToolCallIdentity {
        harness_tool_name: "mcp__renamed__press",
        mcp_server_name: Some("renamed"),
        mcp_tool_name: Some("press"),
        package: Some("@example-org/pilot-mcp"),
    };
    let found = match_browser_driver(&drivers, &by_package).expect("package matches");
    assert_eq!(found.kind, BrowserDriverMatchKind::Package);
    assert_eq!(found.tool_name, "press");

    let found = match_browser_driver(&drivers, &call("mcp__example-pilot__open_page"))
        .expect("namespace matches");
    assert_eq!(found.kind, BrowserDriverMatchKind::ToolNamespace);
    assert_eq!(found.tool_name, "open_page");
}

#[test]
fn harness_built_in_tools_match_by_name() {
    let built_in = compile(
        &profile(
            "browser.example-harness",
            matches(&[], &[], &[], &["web-pilot"]),
            json!([{"name": "web-pilot", "discriminator": "action",
                "cases": {"open": {"verb": "Navigate"}}}]),
        ),
        BrowserDriverOrigin::Contributed,
    );
    let drivers = [built_in];
    let found = match_browser_driver(&drivers, &call("web-pilot")).expect("harness tool matches");
    assert_eq!(found.kind, BrowserDriverMatchKind::HarnessTool);
    assert!(matches!(
        found.tool,
        Some(CompiledBrowserToolV1::Discriminated { .. })
    ));
    assert!(match_browser_driver(&drivers, &call("web-pilot-2")).is_none());
}

#[test]
fn an_unlisted_tool_on_a_matched_driver_is_unclassified() {
    let drivers = [pilot()];
    let found = match_browser_driver(&drivers, &call("mcp__example-pilot__evaluate"))
        .expect("namespace matches");
    assert!(found.is_unclassified());
    assert_eq!(found.tool_name, "evaluate");
}

#[test]
fn no_profile_means_no_match() {
    let drivers = [pilot()];
    for name in [
        "mcp__other__open_page",
        "mcp__example-pilot__",
        "mcp__example-pilot",
        "open_page",
        "",
    ] {
        assert!(
            match_browser_driver(&drivers, &call(name)).is_none(),
            "{name:?}"
        );
    }
    let server_without_tool = BrowserToolCallIdentity {
        harness_tool_name: "mcp__x__y",
        mcp_server_name: Some("example-pilot"),
        mcp_tool_name: Some(""),
        package: None,
    };
    assert!(match_browser_driver(&drivers, &server_without_tool).is_none());
    assert!(match_browser_driver(&[], &call("mcp__example-pilot__open_page")).is_none());
}

#[test]
fn exact_identity_beats_a_namespace() {
    let by_namespace = compile(
        &profile(
            "browser.a-namespace",
            matches(&[], &[], &["mcp__shared__"], &[]),
            json!([{"name": "open_page", "verb": "Read"}]),
        ),
        BrowserDriverOrigin::FirstParty,
    );
    let by_server = compile(
        &profile(
            "browser.z-server",
            matches(&["shared"], &[], &[], &[]),
            json!([{"name": "open_page", "verb": "Navigate"}]),
        ),
        BrowserDriverOrigin::Contributed,
    );
    let identity = BrowserToolCallIdentity {
        harness_tool_name: "mcp__shared__open_page",
        mcp_server_name: Some("shared"),
        mcp_tool_name: Some("open_page"),
        package: None,
    };
    for drivers in [
        [by_namespace.clone(), by_server.clone()],
        [by_server.clone(), by_namespace.clone()],
    ] {
        let found = match_browser_driver(&drivers, &identity).expect("both claim the call");
        assert_eq!(found.driver.id, "browser.z-server");
        assert_eq!(found.kind, BrowserDriverMatchKind::McpServerName);
    }
}

#[test]
fn first_party_beats_contributed_at_the_same_rank() {
    let first_party = compile(
        &profile(
            "browser.z-first",
            matches(&["example-pilot"], &[], &[], &[]),
            json!([{"name": "open_page", "verb": "Navigate"}]),
        ),
        BrowserDriverOrigin::FirstParty,
    );
    let drivers_orders = [
        [pilot(), first_party.clone()],
        [first_party.clone(), pilot()],
    ];
    let identity = BrowserToolCallIdentity {
        harness_tool_name: "mcp__example-pilot__open_page",
        mcp_server_name: Some("example-pilot"),
        mcp_tool_name: Some("open_page"),
        package: None,
    };
    for drivers in drivers_orders {
        let found = match_browser_driver(&drivers, &identity).expect("both claim the server");
        assert_eq!(found.driver.id, "browser.z-first");
        assert_eq!(
            found.driver.trust_class,
            BrowserDriverTrustClassV1::FirstParty
        );
    }
}

#[test]
fn the_longer_namespace_wins_and_ties_break_by_id() {
    let short = compile(
        &profile(
            "browser.a-short",
            matches(&[], &[], &["mcp__pilot__"], &[]),
            json!([{"name": "x__open", "verb": "Read"}]),
        ),
        BrowserDriverOrigin::Contributed,
    );
    let long = compile(
        &profile(
            "browser.b-long",
            matches(&[], &[], &["mcp__pilot__x__"], &[]),
            json!([{"name": "open", "verb": "Navigate"}]),
        ),
        BrowserDriverOrigin::Contributed,
    );
    for drivers in [[short.clone(), long.clone()], [long.clone(), short.clone()]] {
        let found = match_browser_driver(&drivers, &call("mcp__pilot__x__open")).unwrap();
        assert_eq!(found.driver.id, "browser.b-long");
        assert_eq!(found.tool_name, "open");
    }

    let twin = compile(
        &profile(
            "browser.c-twin",
            matches(&[], &[], &["mcp__pilot__"], &[]),
            json!([{"name": "x__open", "verb": "Read"}]),
        ),
        BrowserDriverOrigin::FirstParty,
    );
    let other_twin = compile(
        &profile(
            "browser.b-twin",
            matches(&[], &[], &["mcp__pilot__"], &[]),
            json!([{"name": "x__open", "verb": "Read"}]),
        ),
        BrowserDriverOrigin::FirstParty,
    );
    for drivers in [
        [twin.clone(), other_twin.clone()],
        [other_twin.clone(), twin.clone()],
    ] {
        let found = match_browser_driver(&drivers, &call("mcp__pilot__x__open")).unwrap();
        assert_eq!(found.driver.id, "browser.b-twin");
    }
}
