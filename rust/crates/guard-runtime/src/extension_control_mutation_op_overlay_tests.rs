use super::*;

#[test]
fn the_overlay_names_extensions_and_permissions_the_catalog_lacks() {
    let layers = vec![local(vec![
        extension_control(DELTA, "disabled"),
        permission_control(DELTA_READ, "disabled"),
    ])];
    let (refused, canonical) = verdict(validate_query(
        registry(),
        digest(),
        Vec::new(),
        layers.clone(),
    ));
    assert_eq!(refused, None);
    assert_eq!(canonical, layers);
}

#[test]
fn the_overlay_decides_what_it_names_is_fixed() {
    assert_eq!(
        refusal(
            Vec::new(),
            vec![local(vec![extension_control(DELTA_REQUIRED, "disabled")])]
        ),
        some("immutable_extension")
    );
    assert_eq!(
        refusal(
            Vec::new(),
            vec![local(vec![permission_control(DELTA_FIXED, "disabled")])]
        ),
        some("immutable_permission")
    );
}

#[test]
fn the_catalog_wins_where_the_overlay_names_the_same_target() {
    let mut shadowed = registry();
    shadowed.overlay = vec![
        overlay(ALPHA, true, vec![catalog_permission(ALPHA_READ, false)]),
        overlay(GAMMA, false, vec![catalog_permission(GAMMA_FIXED, true)]),
    ];
    let layers = vec![local(vec![
        extension_control(ALPHA, "disabled"),
        permission_control(ALPHA_READ, "disabled"),
    ])];
    let (accepted, _) = verdict(validate_query(
        shadowed.clone(),
        digest(),
        Vec::new(),
        layers,
    ));
    assert_eq!(accepted, None);
    let fixed = vec![local(vec![extension_control(GAMMA, "disabled")])];
    let (refused, _) = verdict(validate_query(
        shadowed.clone(),
        digest(),
        Vec::new(),
        fixed,
    ));
    assert_eq!(refused, some("immutable_extension"));
    let fixed_permission = vec![local(vec![permission_control(GAMMA_FIXED, "disabled")])];
    let (refused, _) = verdict(validate_query(
        shadowed,
        digest(),
        Vec::new(),
        fixed_permission,
    ));
    assert_eq!(refused, some("immutable_permission"));
}

#[test]
fn a_catalog_alias_wins_over_an_overlay_id() {
    let mut aliased = registry();
    aliased.overlay = vec![overlay(BETA_ALIAS, true, Vec::new())];
    let layers = vec![local(vec![extension_control(BETA_ALIAS, "disabled")])];
    let (refusal, canonical) = verdict(validate_query(aliased, digest(), Vec::new(), layers));
    assert_eq!(refusal, None);
    assert_eq!(
        canonical[0].controls,
        vec![extension_control(BETA, "disabled")]
    );
}

#[test]
fn the_first_overlay_extension_decides_a_shared_permission() {
    let mut shared = registry();
    shared.overlay = vec![
        overlay(DELTA, false, vec![catalog_permission(DELTA_FIXED, true)]),
        overlay(
            DELTA_REQUIRED,
            false,
            vec![catalog_permission(DELTA_FIXED, false)],
        ),
    ];
    let layers = vec![local(vec![permission_control(DELTA_FIXED, "disabled")])];
    assert_eq!(
        verdict(validate_query(shared, digest(), Vec::new(), layers)).0,
        None
    );
}

#[test]
fn a_registry_with_a_repeated_id_is_a_broken_request() {
    let invalid = "native_extension_control_registry_invalid";
    let mut repeated_extension = registry();
    repeated_extension
        .extensions
        .push(catalog_extension(ALPHA, &[], false));
    assert_eq!(
        error_code(validate_query(
            repeated_extension,
            digest(),
            Vec::new(),
            Vec::new()
        )),
        invalid
    );
    let mut repeated_permission = registry();
    repeated_permission
        .permissions
        .push(catalog_permission(ALPHA_READ, true));
    assert_eq!(
        error_code(validate_query(
            repeated_permission,
            digest(),
            Vec::new(),
            Vec::new()
        )),
        invalid
    );
    let mut repeated_overlay = registry();
    repeated_overlay
        .overlay
        .push(overlay(DELTA, false, Vec::new()));
    assert_eq!(
        error_code(ExtensionControlQueryV1::MutabilityValidate {
            registry: repeated_overlay,
            current_layers: Vec::new(),
            layers: Vec::new(),
        }),
        invalid
    );
}
