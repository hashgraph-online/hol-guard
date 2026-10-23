use super::*;

fn structural_fixture() -> (Value, BTreeMap<String, String>, Value, Value) {
    let sources: BTreeMap<String, String> = EXECUTION_SOURCES
        .iter()
        .map(|name| ((*name).to_owned(), "0".repeat(64)))
        .collect();
    let requirements: BTreeMap<String, String> = REQUIREMENTS
        .iter()
        .map(|name| ((*name).to_owned(), "reviewed".to_owned()))
        .collect();
    let runtime = json!({"source_sha":"outside"});
    let platform = json!({"machine":"aarch64"});
    let package = json!({
        "schema":"local-executor-conformance.v1",
        "scope":"local-diagnostic-only",
        "qualification_eligible":false,
        "platform":platform,
        "runtime":runtime,
        "public_assets":{"sdk":{},"bun":{}},
        "execution_sources":sources,
        "review":{
            "schema":"local-executor-equivalence-review.v1",
            "reviewer_role":"implementation-author",
            "verdict":"scoped-local-conformance",
            "requirements":requirements,
            "document":"reviewed",
            "document_sha256":sha256(b"reviewed"),
        },
        "controls":{},
    });
    (package, sources, runtime, platform)
}

fn inspect_fixture(
    package: &Value,
    sources: &BTreeMap<String, String>,
    runtime: &Value,
    platform: &Value,
) -> Result<LocalConformancePackageShadow> {
    let raw = canonical_value(package).unwrap();
    verify_local_conformance_package_ineligible(
        &raw,
        &sha256(&raw),
        runtime,
        platform,
        sources,
        None,
    )
}

#[test]
fn exact_source_and_role_sets_are_frozen() {
    assert_eq!(EXECUTION_SOURCES.len(), 50);
    assert_eq!(EXECUTION_SOURCES.iter().collect::<BTreeSet<_>>().len(), 50);
    assert_eq!(ROLES.iter().collect::<BTreeSet<_>>().len(), 5);
}

#[test]
fn bounded_reader_refuses_digest_and_ambiguous_json() {
    let raw = br#"{"schema":"x","schema":"y"}"#;
    assert!(verify_local_conformance_package_ineligible(
        raw,
        &sha256(raw),
        &json!({}),
        &json!({}),
        &BTreeMap::new(),
        None
    )
    .is_err());
    assert!(verify_local_conformance_package_ineligible(
        b"{}",
        &"0".repeat(64),
        &json!({}),
        &json!({}),
        &BTreeMap::new(),
        None
    )
    .is_err());
    assert!(verify_local_conformance_package_ineligible(
        &vec![b' '; MAX_PACKAGE_BYTES + 1],
        &"0".repeat(64),
        &json!({}),
        &json!({}),
        &BTreeMap::new(),
        None
    )
    .is_err());
}

#[test]
fn package_cannot_choose_runtime_source_set_review_or_roles() {
    let (mut package, sources, runtime, platform) = structural_fixture();
    assert_eq!(
        inspect_fixture(&package, &sources, &runtime, &platform)
            .unwrap_err()
            .to_string(),
        INVALID.to_string()
    );
    package["runtime"]["source_sha"] = json!("candidate-chosen");
    assert!(inspect_fixture(&package, &sources, &runtime, &platform)
        .unwrap_err()
        .to_string()
        .contains("outside pins"));
    package["runtime"] = runtime.clone();
    package["execution_sources"][EXECUTION_SOURCES[0]] = json!("1".repeat(64));
    assert_eq!(
        inspect_fixture(&package, &sources, &runtime, &platform)
            .unwrap_err()
            .to_string(),
        SOURCE.to_string()
    );
    package["execution_sources"][EXECUTION_SOURCES[0]] = json!("0".repeat(64));
    package["review"]["document"] = json!("changed");
    assert!(inspect_fixture(&package, &sources, &runtime, &platform)
        .unwrap_err()
        .to_string()
        .contains("review digest"));
}

#[test]
fn outside_control_key_map_is_complete_and_precedes_signed_opening() {
    let (mut package, sources, runtime, platform) = structural_fixture();
    let mut keys = BTreeMap::new();
    for (index, role) in ROLES.iter().enumerate() {
        let key = format!("{:064x}", index + 1);
        keys.insert((*role).to_owned(), key.clone());
        package["controls"][role] = json!({
            "public_key":key,
            "record":{},
            "record_digest":sha256(b"{}"),
        });
    }
    let raw = canonical_value(&package).unwrap();
    let inspect = |keys: &BTreeMap<String, String>| {
        verify_local_conformance_package_with_key_pins_ineligible(
            &raw,
            &sha256(&raw),
            &runtime,
            &platform,
            &sources,
            None,
            keys,
        )
        .unwrap_err()
        .to_string()
    };
    let mut wrong = keys.clone();
    wrong.remove("cancel");
    assert!(inspect(&wrong).contains("exact outside control key pins"));
    wrong = keys.clone();
    wrong.insert("boundary".to_owned(), "0".repeat(64));
    assert!(inspect(&wrong).contains("control key differs from outside pin"));
    wrong = keys.clone();
    wrong.insert("cancel".to_owned(), keys["boundary"].clone());
    assert!(inspect(&wrong).contains("exact outside control key pins"));
    assert_eq!(inspect(&keys), CONTROL.to_string());
}
