use crate::cloud_pack::{pack_from_value, parse_pack, CloudActionPack};
use crate::cloud_pack_artifact::pack_digest;
use crate::cloud_pack_diff::diff;
use crate::cloud_pack_fixtures::run;
use crate::cloud_pack_request::{render, render_connected};
use serde_json::{json, Map, Value};

const OUTLOOK: &str = include_str!("../../../../contributions/cloud-actions/outlook.json");
const LIST: &str = "outlook.messages.list";

/// The shipped Outlook pack with its `transports` block removed, so the
/// sign-in checks below reach the connection block.
fn outlook_value() -> Value {
    let mut pack: Value = serde_json::from_str(OUTLOOK).unwrap();
    pack.as_object_mut().unwrap().remove("transports");
    pack
}

fn tenant() -> Value {
    json!({"values": {"tenant": {
        "title": "Tenant subdomain",
        "pattern": "^[a-z0-9][a-z0-9-]{0,30}$",
        "maxLength": 31
    }}})
}

/// Outlook with every request sent to `{tenant}.mail.example.com`.
fn hosted_value() -> Value {
    let mut pack = outlook_value();
    pack["connection"] = tenant();
    pack["hosts"] = json!(["{tenant}.mail.example.com"]);
    for action in pack["actions"].as_array_mut().unwrap() {
        action["executor"]["request"]["host"] = json!("{tenant}.mail.example.com");
    }
    pack
}

fn hosted() -> CloudActionPack {
    pack_from_value(hosted_value()).unwrap()
}

/// Outlook with the list action addressed to one tenant by path.
fn pathed() -> CloudActionPack {
    let mut pack = outlook_value();
    pack["connection"] = tenant();
    let list = pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == LIST)
        .unwrap();
    list["executor"]["request"]["path"] =
        json!("/v1.0/users/{tenant}/mailFolders/{folder}/messages");
    pack_from_value(pack).unwrap()
}

fn values(tenant: &str) -> Map<String, Value> {
    let mut values = Map::new();
    values.insert("tenant".into(), json!(tenant));
    values
}

fn list_arguments() -> Value {
    json!({"folder": "inbox", "top": 10})
}

fn render_list(
    pack: &CloudActionPack,
    values: &Map<String, Value>,
) -> Result<String, &'static str> {
    render_connected(
        pack.connection.as_ref(),
        pack.action(LIST).unwrap(),
        &list_arguments(),
        values,
    )
    .map(|request| request.url)
    .map_err(|error| error.code)
}

fn refused(pack: Value) -> (&'static str, String) {
    let error = pack_from_value(pack).unwrap_err();
    (error.code, error.pointer)
}

#[test]
fn a_pack_without_connection_values_serializes_and_digests_as_before() {
    for text in crate::cloud_pack_explain::SHIPPED_SOURCES {
        let source: Value = serde_json::from_str(text).unwrap();
        let pack = parse_pack(text.as_bytes()).unwrap();
        let value = serde_json::to_value(&pack).unwrap();
        assert_eq!(
            value.get("connection").is_some(),
            source.get("connection").is_some(),
            "{}",
            pack.provider.id
        );
    }
    let plain = pack_from_value(outlook_value()).unwrap();
    let mut stripped = pathed();
    assert_ne!(
        pack_digest(&plain).unwrap(),
        pack_digest(&stripped).unwrap()
    );
    stripped.connection = None;
    let mut restored = plain.clone();
    restored.actions = stripped.actions.clone();
    assert_eq!(
        pack_digest(&restored).unwrap(),
        pack_digest(&stripped).unwrap()
    );
}

#[test]
fn a_host_value_is_filled_from_the_connection_only() {
    let pack = hosted();
    let url = render_list(&pack, &values("acme")).unwrap();
    assert!(url.starts_with("https://acme.mail.example.com/v1.0/me/mailFolders/inbox/messages?"));
    assert_eq!(
        render_list(&pack, &Map::new()),
        Err("connection_value_missing")
    );
    for value in [
        "evil.com#",
        "Acme",
        "acme.attacker",
        "-acme",
        "",
        " ",
        "a/b",
        "acme\n",
    ] {
        assert_eq!(
            render_list(&pack, &values(value)),
            Err("connection_value_invalid"),
            "{value:?}"
        );
    }
    let mut extra = values("acme");
    extra.insert("region".into(), json!("eu"));
    assert_eq!(render_list(&pack, &extra), Err("connection_value_unknown"));
    // A caller can never name the value: it is not one of the action's arguments.
    let action = pack.action(LIST).unwrap();
    let error = render_connected(
        pack.connection.as_ref(),
        action,
        &json!({"folder": "inbox", "tenant": "attacker"}),
        &values("acme"),
    )
    .unwrap_err();
    assert_eq!(error.code, "unknown_argument");
    // The plain renderer has no connection, so a templated host cannot resolve.
    assert_eq!(
        render(action, &list_arguments()).unwrap_err().code,
        "connection_value_missing"
    );
}

#[test]
fn a_path_value_is_encoded_like_an_argument() {
    let pack = pathed();
    let url = render_list(&pack, &values("acme-eu")).unwrap();
    assert!(url
        .starts_with("https://graph.microsoft.com/v1.0/users/acme-eu/mailFolders/inbox/messages?"));
    for value in ["..", "acme/../x", "acme%2f"] {
        assert_eq!(
            render_list(&pack, &values(value)),
            Err("connection_value_invalid"),
            "{value}"
        );
    }
    // A pack without connection values refuses any it is given.
    let plain = pack_from_value(outlook_value()).unwrap();
    let error = render_connected(
        None,
        plain.action(LIST).unwrap(),
        &list_arguments(),
        &values("acme"),
    )
    .unwrap_err();
    assert_eq!(error.code, "connection_value_unknown");
}

#[test]
fn connection_blocks_outside_the_closed_form_are_refused() {
    let invalid = "cloud_pack_connection_invalid";
    let shape = "cloud_pack_shape_invalid";
    let with = |connection: Value| {
        let mut pack = outlook_value();
        pack["connection"] = connection;
        pack
    };
    assert_eq!(refused(with(json!(null))).0, shape);
    assert_eq!(refused(with(json!({"values": {}}))).0, invalid);
    assert_eq!(
        refused(with(json!({"values": {"tenant": {"title": "T", "pattern": "^a$", "maxLength": 1, "default": "a"}}}))).0,
        shape
    );
    for (name, value) in [
        (
            "tenant",
            json!({"title": "T", "pattern": "^[a-z+$", "maxLength": 8}),
        ),
        (
            "tenant",
            json!({"title": "T", "pattern": "^[a-z]+$", "maxLength": 0}),
        ),
        (
            "tenant",
            json!({"title": "T", "pattern": "^[a-z]+$", "maxLength": 129}),
        ),
        (
            "tenant",
            json!({"title": " ", "pattern": "^[a-z]+$", "maxLength": 8}),
        ),
        (
            "Tenant",
            json!({"title": "T", "pattern": "^[a-z]+$", "maxLength": 8}),
        ),
        // The stored pattern must carry its own anchors, as the schema requires.
        (
            "tenant",
            json!({"title": "T", "pattern": "[a-z]+", "maxLength": 8}),
        ),
        // `folder` is an argument of the list action; a value may not shadow it.
        (
            "folder",
            json!({"title": "T", "pattern": "^[a-z]+$", "maxLength": 8}),
        ),
    ] {
        let (code, pointer) = refused(with(json!({"values": {name: value}})));
        assert_eq!(
            (code, pointer),
            (invalid, format!("/connection/values/{name}")),
            "{name}"
        );
    }
    let five: Map<String, Value> = (0..5)
        .map(|index| {
            (
                format!("value_{index}"),
                json!({"title": "T", "pattern": "^[a-z]+$", "maxLength": 8}),
            )
        })
        .collect();
    assert_eq!(refused(with(json!({"values": five}))).0, invalid);
    let mut none = with(tenant());
    none["auth"] = json!({"mode": "none", "scopes": []});
    assert_eq!(refused(none), (invalid, "/connection".to_string()));
    let mut boxed: Value = serde_json::from_str(include_str!(
        "../../../../contributions/cloud-actions/box.json"
    ))
    .unwrap();
    boxed["connection"] = tenant();
    assert_eq!(refused(boxed), (invalid, "/connection".to_string()));
}

#[test]
fn a_host_may_name_only_a_declared_value_and_only_as_its_first_label() {
    let mut undeclared = hosted_value();
    undeclared.as_object_mut().unwrap().remove("connection");
    assert_eq!(refused(undeclared).0, "cloud_pack_hosts_invalid");
    for host in [
        "{region}.mail.example.com",
        "{tenant}.com",
        "mail.{tenant}.example.com",
        "{tenant}-mail.example.com",
        "{tenant}.Mail.example.com",
    ] {
        let mut pack = hosted_value();
        pack["hosts"] = json!([host]);
        assert_eq!(refused(pack).0, "cloud_pack_hosts_invalid", "{host}");
    }
    // A path may not name a value the pack does not declare.
    let mut pack = outlook_value();
    pack["actions"][0]["executor"]["request"]["path"] = json!("/v1.0/users/{tenant}/messages");
    assert_eq!(refused(pack).0, "cloud_pack_request_path_invalid");
}

#[test]
fn any_change_to_a_connection_value_is_reviewed() {
    let plain = pack_from_value(outlook_value()).unwrap();
    let mut unpinned = pathed();
    unpinned.connection = None;
    let pinned = pathed();
    let added = diff(&unpinned, &pinned).unwrap();
    assert!(added.widening);
    let codes: Vec<_> = added.changes.iter().map(|change| change.code).collect();
    assert_eq!(codes, ["connection_value_added"]);
    let removed = diff(&pinned, &unpinned).unwrap();
    assert!(removed.widening);
    let mut looser = pathed();
    looser
        .connection
        .as_mut()
        .unwrap()
        .values
        .get_mut("tenant")
        .unwrap()
        .pattern = "^[a-z0-9./-]{1,31}$".into();
    let changed = diff(&pinned, &looser).unwrap();
    assert!(changed.widening);
    assert!(changed
        .changes
        .iter()
        .any(|change| change.code == "connection_value_changed"));
    assert!(!diff(&pinned, &pinned).unwrap().widening);
    assert!(!diff(&plain, &plain).unwrap().widening);
}

#[test]
fn fixtures_render_with_the_connection_values_they_name() {
    let mut pack = pathed();
    let expected = render_connected(
        pack.connection.as_ref(),
        pack.action(LIST).unwrap(),
        &list_arguments(),
        &values("acme"),
    )
    .unwrap();
    let expected = serde_json::to_value(expected).unwrap();
    let action = pack
        .actions
        .iter_mut()
        .find(|a| a.action_id == LIST)
        .unwrap();
    let fixture = action
        .fixtures
        .iter_mut()
        .find(|f| f.expect.request.is_some())
        .unwrap();
    fixture.arguments = list_arguments();
    fixture.connection = values("acme");
    fixture.expect.request = Some(expected);
    fixture.expect.facts = None;
    fixture.expect.decisions = None;
    let name = fixture.name.clone();
    let failed = |pack: &CloudActionPack| {
        run(pack)
            .results
            .into_iter()
            .find(|result| result.fixture == name)
            .unwrap()
            .failure
    };
    assert_eq!(failed(&pack), None);
    pack.actions
        .iter_mut()
        .find(|a| a.action_id == LIST)
        .unwrap()
        .fixtures
        .iter_mut()
        .find(|f| f.name == name)
        .unwrap()
        .connection = Map::new();
    assert_eq!(
        failed(&pack).as_deref(),
        Some("request refused: connection_value_missing")
    );
}

#[test]
fn the_render_op_takes_connection_values() {
    let pack = serde_json::to_value(hosted()).unwrap();
    let line = |connection: Value| {
        let request = json!({
            "op": "render", "pack": pack, "actionId": LIST,
            "arguments": list_arguments(), "connection": connection
        });
        crate::cloud_pack_cli::answer(&serde_json::to_vec(&request).unwrap())
    };
    let ok = line(json!({"tenant": "acme"}));
    assert_eq!(ok["ok"], json!(true), "{ok}");
    assert!(ok["request"]["url"]
        .as_str()
        .unwrap()
        .starts_with("https://acme.mail.example.com/"));
    let missing = line(json!({}));
    assert_eq!(missing["error"]["code"], json!("connection_value_missing"));
    assert_eq!(missing["error"]["argument"], json!("tenant"));
    assert_eq!(
        line(json!("acme"))["error"]["code"],
        json!("request_invalid")
    );
}

#[test]
fn bounds_that_join_to_the_same_text_still_differ() {
    let set = |title: &str, pattern: &str| {
        let mut pack = pathed();
        let value = pack
            .connection
            .as_mut()
            .unwrap()
            .values
            .get_mut("tenant")
            .unwrap();
        value.title = title.into();
        value.pattern = pattern.into();
        pack
    };
    // Joined with `:` both read `Tenant:^x:^[a-z]{1,8}$`.
    let old = set("Tenant", "^x:^[a-z]{1,8}$");
    let new = set("Tenant:^x", "^[a-z]{1,8}$");
    let changed = diff(&old, &new).unwrap();
    assert!(changed.widening);
    assert!(changed
        .changes
        .iter()
        .any(|change| change.code == "connection_value_changed"));
}

#[test]
fn a_filled_host_stays_within_the_dns_name_limit() {
    // A 253-byte suffix is a valid host by itself; any label in front of it is not.
    let suffix = format!(
        "{}.{}.{}.{}.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(57)
    );
    assert_eq!(suffix.len(), 253);
    let host = format!("{{tenant}}.{suffix}");
    let mut pack = hosted_value();
    pack["hosts"] = json!([host]);
    for action in pack["actions"].as_array_mut().unwrap() {
        action["executor"]["request"]["host"] = json!(host);
    }
    let pack = pack_from_value(pack).unwrap();
    assert_eq!(
        render_list(&pack, &values("a")),
        Err("connection_value_invalid")
    );
}

#[test]
fn a_query_value_is_never_dropped_for_want_of_a_connection() {
    let mut pack = outlook_value();
    pack["connection"] = tenant();
    let list = pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == LIST)
        .unwrap();
    list["executor"]["request"]["query"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "tenant", "value": {"arg": {"name": "tenant"}}}));
    let pack = pack_from_value(pack).unwrap();
    let url = render_list(&pack, &values("acme")).unwrap();
    assert!(url.contains("tenant=acme"), "{url}");
    let action = pack.action(LIST).unwrap();
    assert_eq!(
        render(action, &list_arguments()).unwrap_err().code,
        "connection_value_missing"
    );
    // A pack with no connection values renders as before.
    let plain = pack_from_value(outlook_value()).unwrap();
    assert!(render(plain.action(LIST).unwrap(), &list_arguments()).is_ok());
}

#[test]
fn a_fixture_connection_value_must_be_text() {
    let mut pack = serde_json::to_value(pathed()).unwrap();
    pack["actions"][0]["fixtures"][0]["connection"] = json!({"tenant": 42});
    assert_eq!(refused(pack).0, "cloud_pack_fixtures_invalid");
}
