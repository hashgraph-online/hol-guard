use guard_command::browser_first_party_drivers::{
    first_party_profile_digest, PLAYWRIGHT_DRIVER_ID, PUPPETEER_DRIVER_ID,
};
use guard_contracts::{BrowserMcpArtifactV1, McpToolPolicyObservationV1};
use serde_json::{json, Value};

use super::*;
use crate::mcp_tool_policy_grants::normalized_browser_intent;

const SERVER_IDENTITY: &str = "server-identity-example";
const SCHEMA: &str = "schema-text-example";
const ROUTINE: [&str; 1] = ["browser_interaction"];

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn filed(tool: &str) -> Value {
    json!({
        "version": 1,
        "intent": "browser.interact",
        "operation": tool,
        "target_origin": "https://shop.example.test",
        "mcp_server_name": "playwright",
        "mcp_server_identity_hash": SERVER_IDENTITY,
        "mcp_tool_name": tool,
        "mcp_schema_hash": SCHEMA,
    })
}

fn element_arguments() -> Map<String, Value> {
    json!({"element": "Add to basket", "ref": "e12"})
        .as_object()
        .cloned()
        .expect("object")
}

fn hash_in(home: &Path, tool: &str) -> Option<String> {
    driver_identity_hash(home, &filed(tool))
}

#[test]
fn need_names_the_first_party_profile_and_digests_the_schema_text() {
    let asked = need("initial", filed("browser_click").as_object().unwrap()).expect("need");
    assert_eq!(asked["kind"], NEED_KIND);
    assert_eq!(asked["profile_id"], PLAYWRIGHT_DRIVER_ID);
    assert_eq!(
        asked["profile_digest"],
        json!(first_party_profile_digest(PLAYWRIGHT_DRIVER_ID).unwrap())
    );
    assert_eq!(asked["profiled"], true);
    let schema = asked["schema_hash"].as_str().unwrap();
    assert!(is_digest(schema) && schema != SCHEMA);
    let mut unknown = filed("browser_click");
    unknown["mcp_server_name"] = json!("example-unlisted-server");
    assert!(need("initial", unknown.as_object().unwrap()).is_none());
    let mut anonymous = filed("browser_click");
    anonymous["mcp_server_identity_hash"] = Value::Null;
    assert!(need("initial", anonymous.as_object().unwrap()).is_none());
}

#[test]
fn ledger_answers_one_hash_per_driver_and_none_for_an_unprofiled_tool() {
    let home = tempfile::tempdir().expect("home");
    let first = hash_in(home.path(), "browser_click").expect("covered");
    assert!(is_digest(&first));
    assert_eq!(
        hash_in(home.path(), "browser_navigate"),
        Some(first.clone())
    );
    assert_eq!(hash_in(home.path(), "browser_click"), Some(first));
    assert_eq!(hash_in(home.path(), "example_unlisted_tool"), None);
}

#[test]
fn answer_is_null_without_a_store_and_ignores_other_needs() {
    let asked = need("initial", filed("browser_click").as_object().unwrap()).unwrap();
    assert_eq!(
        answer(None, None, &asked),
        Some(json!({"driver_identity_hash": null}))
    );
    let other = json!({"kind": "grant_lookup", "selector": "x"});
    assert_eq!(answer(None, None, &other), None);
}

#[test]
fn full_scope_lists_site_selectors_in_prd_order() {
    let mut scoped = scoped_intent(
        &filed("browser_click"),
        Some(&digest('a')),
        &element_arguments(),
        "codex",
    );
    scoped["session_ref_digest"] = json!(digest('b'));
    scoped["site_group"] = json!("example.test");
    let selectors = site_grant_selectors(&scoped, &ROUTINE);
    let shapes: Vec<&str> = selectors
        .iter()
        .map(|selector| selector.split(':').nth(3).unwrap_or_default())
        .collect();
    assert_eq!(shapes, ["session", "site", "site", "group"]);
    assert!(selectors[1].ends_with(":category:browser_interaction"));
    assert!(!selectors[2].contains(":category:"));
    assert!(selectors
        .iter()
        .all(|selector| selector.contains(&digest('a'))));
}

#[test]
fn shared_profile_reaches_session_site_only() {
    let mut scoped = scoped_intent(
        &filed("browser_click"),
        Some(&digest('a')),
        &element_arguments(),
        "codex",
    );
    scoped["session_ref_digest"] = json!(digest('b'));
    let risks = ["browser_interaction", "browser_shared_profile"];
    let selectors = site_grant_selectors(&scoped, &risks);
    assert_eq!(selectors.len(), 1);
    assert!(selectors[0].contains(":session:"));
    scoped.as_object_mut().unwrap().remove("session_ref_digest");
    assert!(site_grant_selectors(&scoped, &risks).is_empty());
}

#[test]
fn unclean_or_unknown_surface_offers_no_site_selector() {
    let mut password = scoped_intent(
        &filed("browser_click"),
        Some(&digest('a')),
        &element_arguments(),
        "codex",
    );
    password["element"] = json!({"is_password": true, "is_payment": false});
    assert!(site_grant_selectors(&password, &ROUTINE).is_empty());
    let unknown = scoped_intent(
        &filed("example_unlisted_tool"),
        Some(&digest('a')),
        &element_arguments(),
        "codex",
    );
    assert_eq!(unknown["element"], "unclassified");
    assert!(site_grant_selectors(&unknown, &ROUTINE).is_empty());
    let unscoped = scoped_intent(&filed("browser_click"), None, &element_arguments(), "codex");
    assert!(unscoped.get("driver_identity_hash").is_none());
    assert!(site_grant_selectors(&unscoped, &ROUTINE).is_empty());
}

fn subject() -> McpToolPolicySubjectV1 {
    McpToolPolicySubjectV1 {
        config: Map::new(),
        workspace: None,
        artifact: BrowserMcpArtifactV1 {
            name: "playwright".to_owned(),
            command: Some("browser_click".to_owned()),
            metadata: json!({
                "server_name": "playwright",
                "browser_current_page_url": "https://shop.example.test/cart",
                "mcp_server_identity": {"identity_hash": SERVER_IDENTITY},
                "mcp_tool_identity": {"schema_hash": SCHEMA},
            })
            .as_object()
            .cloned()
            .unwrap(),
        },
        artifact_type: "mcp_tool".to_owned(),
        artifact_id: "codex:project:playwright:browser_click".to_owned(),
        harness: "codex".to_owned(),
        publisher: None,
        artifact_hash: "exact-hash".to_owned(),
        arguments: McpToolArgumentsV1::Mapping {
            entries: element_arguments().into_iter().collect(),
        },
        extension: None,
    }
}

fn selectors_with(observations: &[McpToolPolicyObservationV1]) -> Flow<Vec<String>> {
    let subject = subject();
    let intent = normalized_browser_intent(&subject.artifact, &subject.arguments)
        .expect("normalizes")
        .expect("browser intent");
    let ctx = Ctx {
        observations,
        lookup: None,
        memo: None,
        catalog: None,
        provider_store: None,
    };
    let risks = vec!["browser_interaction".to_owned()];
    selectors_in_order(&ctx, Phase::Initial, &subject, Some(&intent), &risks)
}

#[test]
fn flow_asks_for_the_driver_scope_then_tries_site_before_legacy_selectors() {
    let Err(Stop::Need(need)) = selectors_with(&[]) else {
        panic!("expected the driver scope need");
    };
    assert_eq!(need["kind"], NEED_KIND);
    let home = tempfile::tempdir().expect("home");
    let result = answer(None, Some(home.path()), &need).expect("answered");
    let observed = [McpToolPolicyObservationV1 { need, result }];
    let Ok(selectors) = selectors_with(&observed) else {
        panic!("expected selectors");
    };
    assert_eq!(selectors.len(), 5, "{selectors:?}");
    assert!(selectors[0].starts_with("browser-grant:v2:"));
    assert!(selectors[0].ends_with(":category:browser_interaction"));
    assert!(selectors[1].starts_with("browser-grant:v2:"));
    assert!(selectors[2..]
        .iter()
        .all(|selector| selector.starts_with("mcp-temporary-grant:v1:")));
}

#[test]
fn flow_without_a_driver_identity_keeps_the_legacy_selectors() {
    let Err(Stop::Need(need)) = selectors_with(&[]) else {
        panic!("expected the driver scope need");
    };
    let result = answer(None, None, &need).expect("answered");
    let observed = [McpToolPolicyObservationV1 { need, result }];
    let Ok(selectors) = selectors_with(&observed) else {
        panic!("expected selectors");
    };
    assert_eq!(selectors.len(), 3);
}

#[test]
fn first_party_profile_digests_are_distinct_digests() {
    let playwright = first_party_profile_digest(PLAYWRIGHT_DRIVER_ID).expect("listed");
    let puppeteer = first_party_profile_digest(PUPPETEER_DRIVER_ID).expect("listed");
    assert!(is_digest(&playwright) && is_digest(&puppeteer));
    assert_ne!(playwright, puppeteer);
    assert_eq!(first_party_profile_digest("browser.example-unlisted"), None);
}

#[test]
fn a_decision_snapshot_reads_the_ledger_without_recording_the_call() {
    let home = tempfile::tempdir().expect("home");
    let asked = need("initial", filed("browser_click").as_object().unwrap()).unwrap();
    let snapshot = open(home.path()).expect("store");
    ensure_browser_session_schema(&snapshot).expect("schema");
    // An unrecorded tool is not covered, and reading it records nothing.
    assert_eq!(
        answer(Some(&snapshot), None, &asked),
        Some(json!({"driver_identity_hash": null}))
    );
    assert_eq!(
        answer(Some(&snapshot), None, &asked),
        Some(json!({"driver_identity_hash": null}))
    );
    let filed_hash = hash_in(home.path(), "browser_click").expect("filed");
    assert_eq!(
        answer(Some(&snapshot), None, &asked),
        Some(json!({ "driver_identity_hash": filed_hash }))
    );
    let mut intent = filed("browser_click");
    intent["driver_identity_hash"] = json!(filed_hash);
    assert!(is_current_driver(&snapshot, &intent));
    let mut changed = filed("browser_click");
    changed["mcp_schema_hash"] = json!("schema-text-changed");
    assert!(driver_identity_hash(home.path(), &changed).is_some());
    assert!(!is_current_driver(&snapshot, &intent));
}

#[test]
fn a_store_without_the_ledger_answers_no_identity() {
    let home = tempfile::tempdir().expect("home");
    let asked = need("initial", filed("browser_click").as_object().unwrap()).unwrap();
    let bare = open(home.path()).expect("store");
    assert_eq!(
        answer(Some(&bare), None, &asked),
        Some(json!({"driver_identity_hash": null}))
    );
    assert!(!is_current_driver(&bare, &filed("browser_click")));
}
