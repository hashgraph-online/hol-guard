use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;

fn read(body: &[u8]) -> Value {
    dispatch(&json!({ "body": STANDARD.encode(body) })).expect("well-formed request")
}

fn page(servers: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "metadata": { "count": 1 }, "servers": servers }))
        .expect("fixture encodes")
}

fn entry(server: Value) -> Value {
    json!({
        "server": server,
        "_meta": { "io.modelcontextprotocol.registry/official": { "status": "active" } },
    })
}

fn invalid() -> Value {
    json!({ "error": "registry_response_invalid" })
}

#[test]
fn a_listing_is_bounded_unverified_and_keeps_only_https_endpoints() {
    let answer = read(&page(json!([entry(json!({
        "name": "io.github.ComposioHQ/composio",
        "version": "1.0.5",
        "description": "d".repeat(600),
        "remotes": [
            { "type": "streamable-http", "url": "https://connect.composio.dev/mcp" },
            { "type": "sse", "url": "http://plain.example/mcp" },
            { "type": "websocket", "url": "https://other.example/mcp" },
        ],
    }))])));
    let listing = &answer["listing"];
    assert_eq!(listing["count"], 1);
    assert_eq!(listing["coverage"], "search-page");
    assert_eq!(listing["more_available"], false);
    let result = &listing["results"][0];
    assert_eq!(result["title"], "io.github.ComposioHQ/composio");
    assert_eq!(result["description"].as_str().map(str::len), Some(500));
    assert_eq!(result["status"], "active");
    assert_eq!(
        result["remote_endpoints"],
        json!([{ "url": "https://connect.composio.dev/mcp", "transport": "streamable-http" }])
    );
    for flag in ["verified_package", "configured", "installed"] {
        assert_eq!(result[flag], false, "{flag}");
    }
}

#[test]
fn a_next_cursor_marks_more_results_and_an_unknown_status_stays_unknown() {
    let mut body = json!({
        "metadata": { "nextCursor": "abc" },
        "servers": [entry(json!({ "name": "a.b/c", "version": "1" }))],
    });
    body["servers"][0]["_meta"]["io.modelcontextprotocol.registry/official"]["status"] =
        json!("retired");
    let listing = &read(&serde_json::to_vec(&body).expect("fixture encodes"))["listing"];
    assert_eq!(listing["more_available"], true);
    assert_eq!(listing["results"][0]["status"], "unknown");
}

#[test]
fn malformed_pages_are_refused() {
    let named = |name: Value| entry(json!({ "name": name, "version": "1" }));
    for body in [
        b"not json".to_vec(),
        b"\xff\xfe".to_vec(),
        br#"{"servers":[],"servers":[],"metadata":{}}"#.to_vec(),
        br#"{"servers":[],"metadata":{"count":NaN}}"#.to_vec(),
        br#"{"servers":[],"metadata":{"count":Infinity}}"#.to_vec(),
        br#"{"servers":[],"metadata":{"count":-Infinity}}"#.to_vec(),
        br#"{"servers":[],"metadata":{"count":1e400}}"#.to_vec(),
        br#"{"servers":[]}"#.to_vec(),
        br#"{"servers":{},"metadata":{}}"#.to_vec(),
        page(json!([{}])),
        page(json!([named(json!("-leading-dash"))])),
        page(json!([named(json!("a".repeat(257)))])),
        page(json!([entry(
            json!({ "name": "a", "version": "v".repeat(81) })
        )])),
        page(json!([entry(
            json!({ "name": "a", "version": "1", "remotes": {} })
        )])),
        page(json!([{ "server": { "name": "a", "version": "1" } }])),
        page(Value::Array(vec![named(json!("a")); 21])),
    ] {
        assert_eq!(read(&body), invalid(), "{}", String::from_utf8_lossy(&body));
    }
}

#[test]
fn an_undecodable_or_oversize_body_is_an_invalid_request() {
    assert!(dispatch(&json!({ "body": "!!" })).is_err());
    assert!(dispatch(&json!({})).is_err());
    assert!(dispatch(&json!({ "body": STANDARD.encode(vec![b' '; 512_001]) })).is_err());
}

fn options(packages: Value) -> Value {
    let answer = read(&page(json!([entry(
        json!({ "name": "a", "version": "1", "packages": packages })
    )])));
    answer["listing"]["results"][0]["package_options"].clone()
}

#[test]
fn only_literal_pinned_stdio_recipes_become_options() {
    let found = options(json!([
        {
            "registryType": "pypi",
            "registryBaseUrl": "https://pypi.org",
            "identifier": "hol-guard",
            "version": "2.2.0",
            "runtimeHint": "uvx",
            "transport": { "type": "stdio" },
            "environmentVariables": [],
            "runtimeArguments": [],
            "packageArguments": [{ "type": "positional", "value": "mcp" }],
        },
        {
            "registryType": "npm",
            "identifier": "@safe/example",
            "version": "1.2.3",
            "runtimeHint": "npx",
            "transport": { "type": "stdio" },
            "packageArguments": [],
        },
        {
            "registryType": "npm",
            "identifier": "@safe/example",
            "version": "1.2.3",
            "runtimeHint": "npx",
            "transport": { "type": "stdio" },
        },
        {
            "registryType": "npm",
            "identifier": "@safe/with-env",
            "version": "1.0.0",
            "runtimeHint": "npx",
            "transport": { "type": "stdio" },
            "environmentVariables": [{ "name": "TOKEN" }],
        },
        {
            "registryType": "npm",
            "identifier": "@safe/unpinned",
            "version": "latest",
            "runtimeHint": "npx",
            "transport": { "type": "stdio" },
        },
        {
            "registryType": "npm",
            "identifier": "@safe/templated",
            "version": "1.0.0",
            "runtimeHint": "npx",
            "transport": { "type": "stdio" },
            "packageArguments": [{ "type": "positional", "value": "${TOKEN}" }],
        },
    ]));
    assert_eq!(
        found,
        json!([
            {
                "registry_type": "pypi",
                "identifier": "hol-guard",
                "version": "2.2.0",
                "command": "uvx",
                "arguments": ["hol-guard@2.2.0", "mcp"],
                "transport": "stdio",
                "verified_package": false,
            },
            {
                "registry_type": "npm",
                "identifier": "@safe/example",
                "version": "1.2.3",
                "command": "npx",
                "arguments": ["-y", "@safe/example@1.2.3"],
                "transport": "stdio",
                "verified_package": false,
            },
        ])
    );
}

#[test]
fn foreign_registries_names_and_arguments_drop_the_recipe() {
    let npm = |overrides: Value| {
        let mut package = json!({
            "registryType": "npm",
            "identifier": "pkg",
            "version": "1.0.0",
            "runtimeHint": "npx",
            "transport": { "type": "stdio" },
        });
        for (key, value) in overrides.as_object().expect("overrides object") {
            package[key] = value.clone();
        }
        package
    };
    assert_eq!(
        options(json!([npm(json!({}))])).as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        options(json!([npm(json!({ "registryBaseUrl": null }))]))
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    for overrides in [
        json!({ "registryBaseUrl": "https://mirror.example" }),
        json!({ "identifier": "Upper" }),
        json!({ "identifier": "@scope/nested/pkg" }),
        json!({ "identifier": "@/pkg" }),
        json!({ "runtimeHint": "bunx" }),
        json!({ "transport": { "type": "streamable-http" } }),
        json!({ "transport": "stdio" }),
        json!({ "runtimeArguments": ["--inspect"] }),
        json!({ "packageArguments": null }),
        json!({ "packageArguments": [{ "type": "named", "value": "x" }] }),
        json!({ "packageArguments": [{ "type": "positional", "value": "" }] }),
        json!({ "packageArguments": [{ "type": "positional", "value": "a\nb" }] }),
        json!({ "packageArguments": [{ "type": "positional", "value": "x".repeat(161) }] }),
        json!({ "packageArguments": vec![json!({ "type": "positional", "value": "x" }); 17] }),
    ] {
        assert_eq!(
            options(json!([npm(overrides.clone())])),
            json!([]),
            "{overrides}"
        );
    }
}

#[test]
fn only_the_first_eight_packages_are_read_and_the_count_is_capped() {
    let filler = json!({ "registryType": "oci" });
    let mut packages = vec![filler; 120];
    packages[8] = json!({
        "registryType": "pypi",
        "identifier": "late",
        "version": "1.0",
        "runtimeHint": "uvx",
        "transport": { "type": "stdio" },
    });
    let answer = read(&page(json!([entry(
        json!({ "name": "a", "version": "1", "packages": packages })
    )])));
    let result = &answer["listing"]["results"][0];
    assert_eq!(result["package_options"], json!([]));
    assert_eq!(result["package_count"], 100);
}
