//! Registry metadata reads inside one evaluation share a single GET.

use super::*;
use guard_command::egress_broker::EgressScope;
use guard_contracts::{EgressOutcomeV1, EgressSuppliedV1};
use std::collections::BTreeMap;

const URL: &str = "https://registry.npmjs.org/zod";
const INSTALL_V1: &str = "application/vnd.npm.install-v1+json";

fn answered(need: &guard_contracts::EgressNeedV1, body: &str) -> EgressSuppliedV1 {
    EgressSuppliedV1 {
        class: need.class.clone(),
        method: need.method.clone(),
        url: need.url.clone(),
        body_sha256: need.body_sha256.clone(),
        occurrence: need.occurrence,
        outcome: EgressOutcomeV1::Response {
            status: 200,
            headers: BTreeMap::new(),
            body: Some(body.to_owned()),
            body_file: None,
        },
    }
}

#[test]
fn a_repeated_read_asks_the_caller_once() {
    let registry = ResidentRegistryMetadata::default();
    let scope = EgressScope::enter(&[], None).unwrap();
    assert!(registry.fetch_registry_metadata(URL, INSTALL_V1).is_none());
    assert!(registry.fetch_registry_metadata(URL, INSTALL_V1).is_none());
    let needs = scope.finish();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].occurrence, 1);
}

#[test]
fn a_repeated_read_reuses_the_supplied_document() {
    let first_round = ResidentRegistryMetadata::default();
    let scope = EgressScope::enter(&[], None).unwrap();
    first_round.fetch_registry_metadata(URL, INSTALL_V1);
    let need = scope.finish().remove(0);

    let body = r#"{"dist-tags":{"latest":"4.1.0"},"versions":{"4.1.0":{}}}"#;
    let replay = ResidentRegistryMetadata::default();
    let scope = EgressScope::enter(&[answered(&need, body)], None).unwrap();
    let resolved = replay.fetch_registry_metadata(URL, INSTALL_V1).unwrap();
    let again = replay.fetch_registry_metadata(URL, INSTALL_V1).unwrap();
    assert_eq!(resolved, again);
    assert_eq!(again.version_order, vec!["4.1.0".to_owned()]);
    assert!(scope.finish().is_empty());
}

#[test]
fn a_different_accept_header_is_its_own_read() {
    let registry = ResidentRegistryMetadata::default();
    let scope = EgressScope::enter(&[], None).unwrap();
    registry.fetch_registry_metadata(URL, INSTALL_V1);
    registry.fetch_registry_metadata(URL, "application/json");
    assert_eq!(scope.finish().len(), 2);
}
