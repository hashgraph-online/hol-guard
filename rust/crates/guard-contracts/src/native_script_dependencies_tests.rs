use super::tests::subject;
use crate::{NativeScriptPackageBindingV1, NativeScriptPackageStateV1 as State};

fn binding() -> NativeScriptPackageBindingV1 {
    NativeScriptPackageBindingV1 {
        root_scope_sha256: "a".repeat(64),
        ecosystem: "npm".into(),
        name: Some("captured-dep".into()),
        version: Some("1.0.0".into()),
        metadata_sha256: "b".repeat(64),
        state: State::Declared,
        code_input_indices: vec![1],
    }
}

#[test]
fn native_package_binding_empty_legacy_shape_and_identity_are_preserved() {
    let original = subject();
    let wire = serde_json::to_value(&original).unwrap();
    assert!(wire.get("package_bindings").is_none());
    let roundtrip = serde_json::from_value::<crate::NativeBashSubjectV1>(wire).unwrap();
    assert_eq!(original.identity_sha256(), roundtrip.identity_sha256());
}

#[test]
fn native_package_binding_declared_context_participates_in_subject_identity() {
    let mut value = subject();
    value.package_bindings.push(binding());
    let original = value.identity_sha256().unwrap();
    value.package_bindings[0].version = Some("1.0.1".into());
    assert_ne!(original, value.identity_sha256().unwrap());
    let mut wire = serde_json::to_value(value).unwrap();
    wire["package_bindings"][0]["can_run_once"] = true.into();
    assert!(serde_json::from_value::<crate::NativeBashSubjectV1>(wire).is_err());
}

#[test]
fn native_package_binding_rejects_interpreter_unowned_and_duplicate_membership() {
    for indices in [vec![], vec![0], vec![2], vec![1, 1]] {
        let mut value = subject();
        let mut package = binding();
        package.code_input_indices = indices;
        value.package_bindings.push(package);
        assert_eq!(value.validate(), Err("native_bash_subject_package_invalid"));
    }
    let mut value = subject();
    value.package_bindings = vec![binding(), binding()];
    value.package_bindings[1].root_scope_sha256 = "c".repeat(64);
    assert!(value.validate().is_err());
}

#[test]
fn native_package_binding_unknown_metadata_is_not_a_declared_identity() {
    let mut value = subject();
    let mut package = binding();
    package.state = State::MetadataUnavailable;
    value.package_bindings.push(package);
    assert!(value.validate().is_err());
    value.package_bindings[0].name = None;
    value.package_bindings[0].version = None;
    assert_eq!(value.validate(), Ok(()));
}

#[test]
fn native_package_binding_rejects_unbounded_or_malformed_identity() {
    for (name, digest) in [
        ("x".repeat(215), "b".repeat(64)),
        ("captured-dep".into(), "g".repeat(64)),
    ] {
        let mut value = subject();
        let mut package = binding();
        package.name = Some(name);
        package.metadata_sha256 = digest;
        value.package_bindings.push(package);
        assert!(value.validate().is_err());
    }
}
