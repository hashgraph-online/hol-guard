use super::*;

#[test]
fn six_role_key_map_requires_exact_names_and_bytes() {
    let mut keys: BTreeMap<String, String> = ROLES
        .iter()
        .map(|role| ((*role).to_owned(), "a".repeat(64)))
        .collect();
    assert_eq!(validated_keys(&keys).unwrap().len(), 6);
    keys.remove("cancel");
    assert!(validated_keys(&keys).is_err());
    keys.insert("unexpected".to_owned(), "a".repeat(64));
    assert!(validated_keys(&keys).is_err());
    keys.remove("unexpected");
    keys.insert("cancel".to_owned(), "A".repeat(64));
    assert!(validated_keys(&keys).is_err());
}
