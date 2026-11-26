use serde_json::{json, Value};

use super::*;

const VERIFIED: &[&str] = &["Example Verified Org"];

fn example() -> Value {
    json!({
        "schemaVersion": "guard.browser-driver.v1",
        "id": "browser.example-pilot",
        "name": "Example Pilot browser tools",
        "publisher": {"name": "Example Org", "verified": false},
        "referenceUrls": ["https://example.org/pilot/tools"],
        "referenceVersion": "1.2.0",
        "match": {
            "mcpServerNames": ["example-pilot"],
            "packages": ["@example-org/pilot-mcp"],
            "toolNamespaces": ["mcp__example-pilot__"],
            "harnessTools": []
        },
        "profileMode": {
            "default": "unknown",
            "flags": {
                "isolated": ["--isolated"],
                "shared": ["--use-my-profile"],
                "remoteDebugging": ["--cdp-url"]
            }
        },
        "tools": [
            {"name": "open_page", "verb": "Navigate", "url": ["url"]},
            {"name": "press", "verb": "Click", "element": {"name": ["label", "ref"]}},
            {"name": "fill", "verb": "Type", "element": {"name": ["label"]}, "text": ["value"]},
            {"name": "run_js", "verb": "Evaluate", "script": ["code"]},
            {"name": "act", "discriminator": "action", "cases": {
                "left_click": {"verb": "Click"},
                "type": {"verb": "Type", "text": ["text"]},
                "screenshot": {"verb": "Screenshot"},
                "key": {"verb": "Key", "text": ["text"]}
            }},
            {"name": "send_protocol", "cdpPassthrough": {"method": ["method"], "params": ["params"]}}
        ],
        "volatileFields": ["tabId", "timeout"],
        "icon": "Globe"
    })
}

fn compile(value: &Value) -> CompileResult<CompiledBrowserDriverV1> {
    compile_contributed(value)
}

fn compile_contributed(value: &Value) -> CompileResult<CompiledBrowserDriverV1> {
    let bytes = serde_json::to_vec(value).unwrap();
    compile_browser_driver(&bytes, BrowserDriverOrigin::Contributed, VERIFIED)
}

fn compile_first_party(value: &Value) -> CompileResult<CompiledBrowserDriverV1> {
    let bytes = serde_json::to_vec(value).unwrap();
    compile_browser_driver(&bytes, BrowserDriverOrigin::FirstParty, VERIFIED)
}

fn with(pointer: &str, replacement: Value) -> Value {
    let mut value = example();
    *value.pointer_mut(pointer).expect("pointer exists") = replacement;
    value
}

fn rejects(value: Value, expected: BrowserDriverCompileError) {
    assert_eq!(
        compile(&value).expect_err("profile must be refused"),
        expected
    );
}

fn tool_with(tool: Value) -> Value {
    with("/tools", json!([tool]))
}

#[test]
fn accepts_the_prd_example_and_projects_intents() {
    let driver = compile(&example()).expect("example compiles");
    assert_eq!(driver.id, "browser.example-pilot");
    assert_eq!(driver.trust_class, BrowserDriverTrustClassV1::Contributed);
    assert!(!driver.publisher_verified);
    assert_eq!(driver.profile_mode_default, BrowserProfileModeV1::Unknown);
    assert_eq!(driver.profile_flags.remote_debugging, vec!["--cdp-url"]);
    let CompiledBrowserToolV1::Fixed(open) = &driver.tools["open_page"] else {
        panic!("open_page is a fixed tool");
    };
    assert_eq!(open.intent, BrowserIntentV1::Navigation);
    assert_eq!(open.pointers.url, vec!["url"]);
    let CompiledBrowserToolV1::Fixed(run_js) = &driver.tools["run_js"] else {
        panic!("run_js is a fixed tool");
    };
    assert_eq!(run_js.intent, BrowserIntentV1::Privileged);
    let CompiledBrowserToolV1::Discriminated {
        discriminator,
        cases,
    } = &driver.tools["act"]
    else {
        panic!("act is a discriminated tool");
    };
    assert_eq!(discriminator, "action");
    assert_eq!(cases["screenshot"].intent, BrowserIntentV1::Inspect);
    assert_eq!(cases["type"].pointers.text, vec!["text"]);
    assert_eq!(
        driver.tools["send_protocol"],
        CompiledBrowserToolV1::CdpPassthrough {
            method: vec!["method".into()],
            params: vec!["params".into()],
        }
    );
}

#[test]
fn verb_intent_table_matches_the_prd() {
    use BrowserIntentV1 as I;
    use BrowserVerbV1 as V;
    let table = [
        (V::Navigate, I::Navigation),
        (V::Read, I::Inspect),
        (V::Screenshot, I::Inspect),
        (V::Scroll, I::Inspect),
        (V::Click, I::Interact),
        (V::Type, I::Interact),
        (V::Key, I::Interact),
        (V::Select, I::Interact),
        (V::Upload, I::Transfer),
        (V::Download, I::Transfer),
        (V::Evaluate, I::Privileged),
        (V::CookieRead, I::Privileged),
        (V::CookieWrite, I::Privileged),
        (V::StorageRead, I::Privileged),
        (V::StorageWrite, I::Privileged),
        (V::Intercept, I::Privileged),
        (V::Permission, I::Privileged),
        (V::TabControl, I::Privileged),
        (V::Attach, I::Privileged),
        (V::Other, I::Privileged),
    ];
    for (verb, intent) in table {
        assert_eq!(browser_verb_intent(verb), intent, "{verb:?}");
    }
}

#[test]
fn rejects_bad_bytes_and_json() {
    let refuse = |bytes: &[u8]| {
        compile_browser_driver(bytes, BrowserDriverOrigin::Contributed, VERIFIED).unwrap_err()
    };
    assert_eq!(refuse(b""), BrowserDriverCompileError::SourceBytesInvalid);
    let oversized = vec![b' '; BROWSER_DRIVER_MAX_BYTES + 1];
    assert_eq!(
        refuse(&oversized),
        BrowserDriverCompileError::SourceBytesInvalid
    );
    assert_eq!(refuse(b"{"), BrowserDriverCompileError::JsonInvalid);
    let mut trailing = serde_json::to_vec(&example()).unwrap();
    trailing.extend_from_slice(b" {}");
    assert_eq!(refuse(&trailing), BrowserDriverCompileError::JsonInvalid);
}

#[test]
fn rejects_duplicate_keys_at_every_level() {
    let text = serde_json::to_string(&example()).unwrap();
    let top = text.replacen(
        "\"id\":\"browser.example-pilot\"",
        "\"id\":\"browser.example-pilot\",\"id\":\"browser.other\"",
        1,
    );
    let case = text.replacen(
        "\"left_click\":{\"verb\":\"Click\"}",
        "\"left_click\":{\"verb\":\"Click\"},\"left_click\":{\"verb\":\"Read\"}",
        1,
    );
    let nested = text.replacen(
        "\"verified\":false",
        "\"verified\":false,\"verified\":true",
        1,
    );
    for source in [top, case, nested] {
        assert_ne!(source, text, "the fixture edit must apply");
        let refused = compile_browser_driver(
            source.as_bytes(),
            BrowserDriverOrigin::Contributed,
            VERIFIED,
        )
        .unwrap_err();
        assert_eq!(refused, BrowserDriverCompileError::JsonInvalid);
    }
}

#[test]
fn rejects_unknown_fields() {
    let mut value = example();
    value["intent"] = json!("browser.inspect");
    rejects(value, BrowserDriverCompileError::JsonInvalid);
    rejects(
        tool_with(json!({"name": "peek", "verb": "Read", "intent": "browser.inspect"})),
        BrowserDriverCompileError::JsonInvalid,
    );
}

#[test]
fn rejects_explicit_null_for_optional_fields() {
    for (pointer, field) in [
        ("", "referenceVersion"),
        ("", "icon"),
        ("/publisher", "url"),
        ("/profileMode", "flags"),
    ] {
        let mut value = example();
        value.pointer_mut(pointer).unwrap()[field] = Value::Null;
        rejects(value, BrowserDriverCompileError::JsonInvalid);
    }
    for tool in [
        json!({"name": "open_page", "verb": "Navigate", "url": null}),
        json!({"name": "open_page", "verb": null, "url": ["url"]}),
        json!({"name": "press", "verb": "Click", "element": null}),
        json!({"name": "act", "discriminator": "action", "cases": null}),
        json!({"name": "send_protocol", "cdpPassthrough": {"method": ["method"], "params": null}}),
        json!({"name": "act", "discriminator": "action", "cases": {"go": {"verb": "Navigate", "url": null}}}),
    ] {
        rejects(tool_with(tool), BrowserDriverCompileError::JsonInvalid);
    }
}

#[test]
fn urls_follow_the_schema_length_and_domain_rules() {
    let long_path = format!("https://example.org/{}", "\u{e9}".repeat(120));
    assert_eq!(long_path.chars().count(), 140);
    assert!(long_path.len() > 256);
    for url in [
        long_path.as_str(),
        "https://example.a1",
        "https://example.org/x-1",
    ] {
        compile(&with("/referenceUrls", json!([url])))
            .unwrap_or_else(|error| panic!("{url}: {error:?}"));
    }
    let too_long = format!("https://example.org/{}", "a".repeat(237));
    assert_eq!(too_long.chars().count(), 257);
    rejects(
        with("/referenceUrls", json!([too_long])),
        BrowserDriverCompileError::ReferenceInvalid,
    );
    rejects(
        with("/referenceUrls", json!(["https://example.1a"])),
        BrowserDriverCompileError::ReferenceInvalid,
    );
}

#[test]
fn rejects_header_fields() {
    use BrowserDriverCompileError as E;
    rejects(
        with("/schemaVersion", json!("guard.browser-driver.v2")),
        E::SchemaVersionUnsupported,
    );
    for id in [
        "example-pilot",
        "browser.",
        "browser.Example",
        "browser.-pilot",
        "browser.pilot-",
    ] {
        rejects(with("/id", json!(id)), E::IdInvalid);
    }
    rejects(with("/name", json!("")), E::NameInvalid);
    rejects(with("/name", json!("x".repeat(81))), E::NameInvalid);
    rejects(with("/name", json!("line\nbreak")), E::NameInvalid);
    rejects(with("/publisher/name", json!(" ")), E::PublisherInvalid);
    rejects(
        with(
            "/publisher",
            json!({"name": "Example Org", "url": "http://example.org", "verified": false}),
        ),
        E::PublisherInvalid,
    );
    rejects(
        with("/referenceUrls", json!(["https://example.org/?q=1"])),
        E::ReferenceInvalid,
    );
    rejects(
        with("/referenceUrls", json!(["https://localhost/tools"])),
        E::ReferenceInvalid,
    );
    rejects(
        with(
            "/referenceUrls",
            json!(["https://example.org/a", "https://example.org/a"]),
        ),
        E::ReferenceInvalid,
    );
    rejects(
        with("/volatileFields", json!(["tab-id"])),
        E::VolatileFieldInvalid,
    );
    rejects(with("/icon", json!("globe")), E::IconInvalid);
}

#[test]
fn publisher_verified_needs_the_maintainer_list() {
    rejects(
        with(
            "/publisher",
            json!({"name": "Example Org", "verified": true}),
        ),
        BrowserDriverCompileError::PublisherVerificationUnproven,
    );
    let driver = compile(&with(
        "/publisher",
        json!({"name": "Example Verified Org", "verified": true}),
    ))
    .expect("listed publisher compiles");
    assert!(driver.publisher_verified);
}

#[test]
fn match_lists_are_literal_bounded_and_unique() {
    use BrowserDriverCompileError as E;
    rejects(
        with(
            "/match",
            json!({"mcpServerNames": [], "packages": [], "toolNamespaces": [], "harnessTools": []}),
        ),
        E::MatchEmpty,
    );
    for entry in ["pilot.*", "Pilot", "^pilot$", "pilot server", ""] {
        rejects(
            with("/match/mcpServerNames", json!([entry])),
            E::MatchEntryInvalid,
        );
    }
    rejects(
        with("/match/packages", json!(["@example-org"])),
        E::MatchEntryInvalid,
    );
    rejects(
        with("/match/toolNamespaces", json!(["mcp__pilot"])),
        E::MatchEntryInvalid,
    );
    let too_many: Vec<String> = (0..33).map(|index| format!("pilot-{index}")).collect();
    rejects(
        with("/match/harnessTools", json!(too_many)),
        E::MatchEntryInvalid,
    );
    rejects(
        with(
            "/match/mcpServerNames",
            json!(["example-pilot", "example-pilot"]),
        ),
        E::MatchEntryDuplicate,
    );
}

#[test]
fn reserved_names_are_first_party_only() {
    let claims = [
        ("/match/mcpServerNames", json!(["playwright"])),
        ("/match/harnessTools", json!(["bash"])),
        ("/match/packages", json!(["@playwright/mcp"])),
        ("/match/packages", json!(["@example-org/chrome"])),
        ("/match/packages", json!(["puppeteer"])),
        ("/match/toolNamespaces", json!(["mcp__playwright__"])),
        ("/match/toolNamespaces", json!(["browser__"])),
    ];
    for (pointer, entry) in claims {
        let value = with(pointer, entry.clone());
        assert_eq!(
            compile_contributed(&value).unwrap_err(),
            BrowserDriverCompileError::ReservedNameClaimed,
            "{pointer} {entry}"
        );
        let driver = compile_first_party(&value).expect("first-party may claim reserved names");
        assert_eq!(driver.trust_class, BrowserDriverTrustClassV1::FirstParty);
    }
}

#[test]
fn rejects_profile_mode_values() {
    use BrowserDriverCompileError as E;
    rejects(
        with("/profileMode/default", json!("incognito")),
        E::ProfileModeInvalid,
    );
    rejects(
        with("/profileMode/flags/isolated", json!(["isolated"])),
        E::ProfileModeInvalid,
    );
    rejects(
        with("/profileMode/flags/shared", json!(["--a=b"])),
        E::ProfileModeInvalid,
    );
    rejects(
        with("/profileMode/flags", json!({"dedicated": ["--x", "--x"]})),
        E::ProfileModeInvalid,
    );
}

#[test]
fn rejects_tool_lists_and_names() {
    use BrowserDriverCompileError as E;
    rejects(with("/tools", json!([])), E::ToolsInvalid);
    let too_many: Vec<Value> = (0..257)
        .map(|index| json!({"name": format!("tool-{index}"), "verb": "Read"}))
        .collect();
    rejects(with("/tools", json!(too_many)), E::ToolsInvalid);
    rejects(
        tool_with(json!({"name": "Open", "verb": "Navigate"})),
        E::ToolNameInvalid,
    );
    rejects(
        with(
            "/tools",
            json!([{"name": "peek", "verb": "Read"}, {"name": "peek", "verb": "Click"}]),
        ),
        E::ToolNameDuplicate,
    );
}

#[test]
fn a_tool_has_exactly_one_shape() {
    use BrowserDriverCompileError as E;
    rejects(tool_with(json!({"name": "peek"})), E::ToolShapeInvalid);
    rejects(
        tool_with(
            json!({"name": "peek", "verb": "Read", "discriminator": "action",
            "cases": {"read": {"verb": "Read"}}}),
        ),
        E::ToolShapeInvalid,
    );
    rejects(
        tool_with(json!({"name": "peek", "discriminator": "action"})),
        E::ToolShapeInvalid,
    );
    rejects(
        tool_with(json!({"name": "peek", "url": ["url"],
            "cdpPassthrough": {"method": ["method"]}})),
        E::ToolShapeInvalid,
    );
}

#[test]
fn rejects_verbs_pointers_and_cases() {
    use BrowserDriverCompileError as E;
    rejects(
        tool_with(json!({"name": "peek", "verb": "read"})),
        E::VerbInvalid,
    );
    rejects(
        tool_with(json!({"name": "peek", "verb": "Inspect"})),
        E::VerbInvalid,
    );
    rejects(
        tool_with(json!({"name": "peek", "url": ["url"]})),
        E::VerbInvalid,
    );
    rejects(
        tool_with(json!({"name": "go", "verb": "Navigate", "url": []})),
        E::PointerInvalid,
    );
    rejects(
        tool_with(json!({"name": "go", "verb": "Navigate", "url": ["a.b"]})),
        E::PointerInvalid,
    );
    let nine: Vec<String> = (0..9).map(|index| format!("arg{index}")).collect();
    rejects(
        tool_with(json!({"name": "go", "verb": "Navigate", "url": nine})),
        E::PointerInvalid,
    );
    rejects(
        tool_with(json!({"name": "send", "cdpPassthrough": {"method": []}})),
        E::PointerInvalid,
    );
    rejects(
        tool_with(
            json!({"name": "act", "discriminator": "1action", "cases": {"a": {"verb": "Read"}}}),
        ),
        E::PointerInvalid,
    );
    rejects(
        tool_with(json!({"name": "act", "discriminator": "action", "cases": {}})),
        E::CasesInvalid,
    );
    rejects(
        tool_with(
            json!({"name": "act", "discriminator": "action", "cases": {"Left": {"verb": "Click"}}}),
        ),
        E::CasesInvalid,
    );
    rejects(
        tool_with(json!({"name": "act", "discriminator": "action", "cases": {"left": {}}})),
        E::VerbInvalid,
    );
}

fn driver_bytes(id: &str, server: &str) -> Vec<u8> {
    let mut value = example();
    value["id"] = json!(id);
    value["match"] = json!({
        "mcpServerNames": [server], "packages": [], "toolNamespaces": [], "harnessTools": []
    });
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn a_set_refuses_duplicate_ids_and_contributed_identity_conflicts() {
    use BrowserDriverOrigin::{Contributed, FirstParty};
    let first = driver_bytes("browser.one", "pilot-one");
    let same_id = driver_bytes("browser.one", "pilot-two");
    let same_server = driver_bytes("browser.two", "pilot-one");
    assert_eq!(
        compile_browser_driver_set(&[(&first, Contributed), (&same_id, Contributed)], VERIFIED)
            .unwrap_err(),
        BrowserDriverCompileError::DriverIdDuplicate
    );
    assert_eq!(
        compile_browser_driver_set(
            &[(&first, Contributed), (&same_server, Contributed)],
            VERIFIED
        )
        .unwrap_err(),
        BrowserDriverCompileError::DriverIdentityConflict
    );
    let compiled = compile_browser_driver_set(
        &[(&first, FirstParty), (&same_server, Contributed)],
        VERIFIED,
    )
    .expect("first-party and contributed may share an identity");
    assert_eq!(compiled.len(), 2);
}

#[test]
fn error_codes_are_stable_and_distinct() {
    use BrowserDriverCompileError as E;
    let all = [
        E::SourceBytesInvalid,
        E::JsonInvalid,
        E::SchemaVersionUnsupported,
        E::IdInvalid,
        E::NameInvalid,
        E::PublisherInvalid,
        E::PublisherVerificationUnproven,
        E::ReferenceInvalid,
        E::MatchEmpty,
        E::MatchEntryInvalid,
        E::MatchEntryDuplicate,
        E::ReservedNameClaimed,
        E::ProfileModeInvalid,
        E::ToolsInvalid,
        E::ToolNameInvalid,
        E::ToolNameDuplicate,
        E::ToolShapeInvalid,
        E::VerbInvalid,
        E::PointerInvalid,
        E::CasesInvalid,
        E::VolatileFieldInvalid,
        E::IconInvalid,
        E::DriverIdDuplicate,
        E::DriverIdentityConflict,
    ];
    let codes: BTreeSet<&str> = all.iter().map(|error| error.code()).collect();
    assert_eq!(codes.len(), all.len());
    assert!(codes.iter().all(|code| code.starts_with("browser_driver_")));
}
