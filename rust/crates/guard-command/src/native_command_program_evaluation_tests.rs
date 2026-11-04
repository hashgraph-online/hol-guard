use super::is_versioned_package_token;

#[test]
fn versioned_package_token_accepts_npm_and_pip_version_forms() {
    assert!(is_versioned_package_token(
        "llm-search-eval@0.5.0",
        "llm-search-eval"
    ));
    assert!(is_versioned_package_token(
        "llm-search-eval@latest",
        "llm-search-eval"
    ));
    assert!(is_versioned_package_token(
        "llm-search-eval==0.5.0",
        "llm-search-eval"
    ));
}

#[test]
fn versioned_package_token_rejects_other_packages_and_specifiers() {
    assert!(!is_versioned_package_token(
        "llm-search-eval",
        "llm-search-eval"
    ));
    assert!(!is_versioned_package_token(
        "llm-search-evalx==0.5.0",
        "llm-search-eval"
    ));
    assert!(!is_versioned_package_token(
        "llm-search-eval-extra@1",
        "llm-search-eval"
    ));
    assert!(!is_versioned_package_token(
        "llm-search-eval=0.5.0",
        "llm-search-eval"
    ));
    assert!(!is_versioned_package_token(
        "llm-search-eval>=0.5.0",
        "llm-search-eval"
    ));
    assert!(!is_versioned_package_token(
        "other==0.5.0",
        "llm-search-eval"
    ));
}
