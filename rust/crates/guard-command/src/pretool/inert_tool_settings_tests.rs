use super::inert_tool_setting;

#[test]
fn a_reporting_or_repeating_value_is_inert() {
    for (name, value) in [
        ("GOFLAGS", "-count=1"),
        ("GOFLAGS", "-count=1 -v"),
        ("GOFLAGS", "-mod=readonly"),
        ("GOFLAGS", "-mod=vendor -trimpath"),
        ("GOFLAGS", "-buildvcs=false"),
        ("PYTEST_ADDOPTS", "-q"),
        ("PYTEST_ADDOPTS", "-q -x"),
        ("PYTEST_ADDOPTS", "--maxfail=1"),
        ("PYTEST_ADDOPTS", "--maxfail 1 --tb=short"),
        ("PYTEST_ADDOPTS", "-k slow"),
        ("PYTEST_ADDOPTS", "--disable-warnings -v"),
        ("RUSTFLAGS", "-Dwarnings"),
        ("RUSTFLAGS", "-D warnings"),
        ("RUSTFLAGS", "-Aunused_imports -Dwarnings"),
        ("RUSTDOCFLAGS", "-Dwarnings"),
        ("goflags", "-count=1"),
    ] {
        assert!(inert_tool_setting(name, value), "{name}={value}");
    }
}

#[test]
fn a_value_that_can_name_code_a_file_or_a_search_path_is_not_inert() {
    for (name, value) in [
        // Each of these is the reason the name is refused in the first place.
        ("GOFLAGS", "-toolexec=./x"),
        ("GOFLAGS", "-exec=./x"),
        ("GOFLAGS", "-ldflags=-X=main.version=1"),
        ("GOFLAGS", "-gcflags=all=-N"),
        ("GOFLAGS", "-overlay=overlay.json"),
        ("GOFLAGS", "-pkgdir=/tmp/pkg"),
        ("GOFLAGS", "-mod=mod"),
        ("GOFLAGS", "-count=1 -toolexec=./x"),
        ("GOFLAGS", "-count=all"),
        ("GOFLAGS", ""),
        ("PYTEST_ADDOPTS", "-pevil"),
        ("PYTEST_ADDOPTS", "-p evil"),
        ("PYTEST_ADDOPTS", "-c/tmp/x.ini"),
        ("PYTEST_ADDOPTS", "--rootdir=/tmp"),
        ("PYTEST_ADDOPTS", "--junitxml=out.xml"),
        ("PYTEST_ADDOPTS", "-W error::DeprecationWarning"),
        ("PYTEST_ADDOPTS", "-q --import-mode=importlib"),
        ("PYTEST_ADDOPTS", "-q -- -p evil"),
        ("PYTEST_ADDOPTS", "-q tests/test_one.py"),
        ("PYTEST_ADDOPTS", "--tb"),
        ("PYTEST_ADDOPTS", "-k not slow"),
        ("PYTEST_ADDOPTS", ""),
        ("RUSTFLAGS", "-Clinker=./ld"),
        ("RUSTFLAGS", "-C linker=./ld"),
        ("RUSTFLAGS", "-L/tmp/libs"),
        ("RUSTFLAGS", "--extern evil=./evil.rlib"),
        ("RUSTFLAGS", "-Zunstable-options"),
        ("RUSTFLAGS", "-Dwarnings -Clinker=./ld"),
        ("RUSTFLAGS", ""),
        // A name this module does not read stays with the shared screens.
        ("NODE_OPTIONS", "--no-warnings"),
        ("LD_PRELOAD", ""),
        ("MAKEFLAGS", "-j4"),
    ] {
        assert!(!inert_tool_setting(name, value), "{name}={value}");
    }
}
