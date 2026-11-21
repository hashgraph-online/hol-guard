use super::*;

#[test]
fn a_managed_layer_cannot_be_added() {
    let layers = vec![cloud(vec![extension_control(ALPHA, "disabled")])];
    assert_eq!(refusal(Vec::new(), layers), some("managed_layer_mutation"));
}

#[test]
fn a_managed_layer_cannot_be_changed() {
    let current = vec![cloud(vec![extension_control(ALPHA, "disabled")])];
    let changed = vec![cloud(vec![extension_control(ALPHA, "enabled")])];
    assert_eq!(
        refusal(current.clone(), changed),
        some("managed_layer_mutation")
    );
    let mut lockdown = current[0].clone();
    lockdown.global_lockdown = true;
    assert_eq!(
        refusal(current, vec![lockdown]),
        some("managed_layer_mutation")
    );
}

#[test]
fn a_managed_layer_cannot_be_dropped() {
    let current = vec![cloud(vec![extension_control(ALPHA, "disabled")])];
    assert_eq!(
        refusal(current, vec![local(Vec::new())]),
        some("managed_layer_mutation")
    );
}

#[test]
fn an_unchanged_managed_layer_is_accepted() {
    let managed = cloud(vec![extension_control(ALPHA, "disabled")]);
    let layers = vec![
        local(vec![extension_control(BETA, "disabled")]),
        managed.clone(),
    ];
    assert_eq!(refusal(vec![managed], layers), None);
}

#[test]
fn a_managed_alias_is_canonical_before_it_is_compared() {
    let current = vec![cloud(vec![extension_control(BETA, "disabled")])];
    let layers = vec![cloud(vec![extension_control(BETA_ALIAS, "disabled")])];
    assert_eq!(refusal(current, layers), None);
}

#[test]
fn a_required_extension_cannot_be_given_a_control() {
    let layers = vec![local(vec![extension_control(GAMMA, "disabled")])];
    assert_eq!(refusal(Vec::new(), layers), some("immutable_extension"));
}

#[test]
fn a_fixed_permission_cannot_be_given_a_control() {
    let layers = vec![local(vec![permission_control(GAMMA_FIXED, "disabled")])];
    assert_eq!(refusal(Vec::new(), layers), some("immutable_permission"));
}

#[test]
fn a_legacy_immutable_control_may_stay_as_it_is() {
    let legacy = vec![local(vec![
        extension_control(GAMMA, "disabled"),
        permission_control(GAMMA_FIXED, "disabled"),
    ])];
    assert_eq!(refusal(legacy.clone(), legacy), None);
}

#[test]
fn a_legacy_immutable_control_cannot_change() {
    let current = vec![local(vec![
        extension_control(GAMMA, "disabled"),
        permission_control(GAMMA_FIXED, "disabled"),
    ])];
    let extension = vec![local(vec![
        extension_control(GAMMA, "enabled"),
        permission_control(GAMMA_FIXED, "disabled"),
    ])];
    assert_eq!(
        refusal(current.clone(), extension),
        some("immutable_extension")
    );
    let permission = vec![local(vec![
        extension_control(GAMMA, "disabled"),
        permission_control(GAMMA_FIXED, "enabled"),
    ])];
    assert_eq!(refusal(current, permission), some("immutable_permission"));
}

#[test]
fn a_legacy_immutable_control_may_be_dropped() {
    let current = vec![local(vec![
        extension_control(GAMMA, "disabled"),
        permission_control(GAMMA_FIXED, "disabled"),
    ])];
    assert_eq!(refusal(current.clone(), vec![local(Vec::new())]), None);
    assert_eq!(refusal(current, Vec::new()), None);
}

#[test]
fn only_a_legacy_control_in_the_local_layer_counts() {
    let current = vec![cloud(vec![extension_control(GAMMA, "disabled")])];
    let layers = vec![
        local(vec![extension_control(GAMMA, "disabled")]),
        cloud(vec![extension_control(GAMMA, "disabled")]),
    ];
    assert_eq!(refusal(current, layers), some("immutable_extension"));
}

#[test]
fn mutability_applies_the_managed_and_immutable_rules() {
    let managed = vec![cloud(vec![extension_control(ALPHA, "disabled")])];
    assert_eq!(
        mutability_refusal(registry(), managed.clone(), Vec::new()),
        some("managed_layer_mutation")
    );
    assert_eq!(
        mutability_refusal(registry(), managed.clone(), managed.clone()),
        None
    );
    assert_eq!(
        mutability_refusal(
            registry(),
            Vec::new(),
            vec![local(vec![extension_control(GAMMA, "disabled")])]
        ),
        some("immutable_extension")
    );
    assert_eq!(
        mutability_refusal(
            registry(),
            Vec::new(),
            vec![local(vec![permission_control(GAMMA_FIXED, "disabled")])]
        ),
        some("immutable_permission")
    );
}

#[test]
fn mutability_follows_the_registry_it_is_given() {
    let mut relaxed = registry();
    relaxed.extensions[2].required = false;
    relaxed.permissions[1].configurable = true;
    let layers = vec![local(vec![
        extension_control(GAMMA, "disabled"),
        permission_control(GAMMA_FIXED, "disabled"),
    ])];
    assert_eq!(
        mutability_refusal(relaxed, Vec::new(), layers.clone()),
        None
    );
    assert_eq!(
        mutability_refusal(registry(), Vec::new(), layers),
        some("immutable_extension")
    );
}

#[test]
fn mutability_leaves_unknown_targets_to_the_mutation_check() {
    let layers = vec![local(vec![
        extension_control(UNKNOWN, "disabled"),
        permission_control(UNKNOWN_PERMISSION, "disabled"),
    ])];
    assert_eq!(mutability_refusal(registry(), Vec::new(), layers), None);
}

#[test]
fn mutability_resolves_an_alias_to_its_extension() {
    // A stored layer may still name an extension by an alias.
    let mut aliased = registry();
    aliased.extensions[1].required = true;
    let layers = vec![local(vec![extension_control(BETA_ALIAS, "disabled")])];
    assert_eq!(
        mutability_refusal(aliased, Vec::new(), layers),
        some("immutable_extension")
    );
}
