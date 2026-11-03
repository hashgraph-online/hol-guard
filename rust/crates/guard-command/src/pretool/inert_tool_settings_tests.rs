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
        ("BROWSERSLIST_DISABLE_CACHE", "1"),
        ("BROWSERSLIST_IGNORE_OLD_DATA", "1"),
        ("CYPRESS_INSTALL_BINARY", "0"),
        ("ELECTRON_SKIP_BINARY_DOWNLOAD", "true"),
        ("ESLINT_USE_FLAT_CONFIG", "true"),
        ("ESLINT_USE_FLAT_CONFIG", "false"),
        ("HUSKY_SKIP_HOOKS", "1"),
        ("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1"),
        ("PUPPETEER_SKIP_DOWNLOAD", "true"),
        ("SHARP_IGNORE_GLOBAL_LIBVIPS", "0"),
        ("puppeteer_skip_download", "1"),
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
        // An option that takes a value is inert only when it is given one,
        // so the walk never steps over a word it has not read.
        ("PYTEST_ADDOPTS", "--maxfail --"),
        ("PYTEST_ADDOPTS", "--maxfail -pevil"),
        ("PYTEST_ADDOPTS", "--maxfail="),
        ("PYTEST_ADDOPTS", "--tb= -q"),
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
        // The switches above are read for the one word each accepts. A value
        // that names somewhere to fetch from, a file, or anything the tool
        // would read as more than a yes or a no leaves the setting refused.
        ("CYPRESS_INSTALL_BINARY", "https://example.test/cypress.zip"),
        ("CYPRESS_INSTALL_BINARY", "/tmp/cypress.zip"),
        ("CYPRESS_INSTALL_BINARY", "1"),
        ("CYPRESS_INSTALL_BINARY", "true"),
        ("ESLINT_USE_FLAT_CONFIG", "1"),
        ("ESLINT_USE_FLAT_CONFIG", "./eslint.config.js"),
        ("PUPPETEER_SKIP_DOWNLOAD", "maybe"),
        ("PUPPETEER_SKIP_DOWNLOAD", "1 2"),
        ("PUPPETEER_SKIP_DOWNLOAD", ""),
        ("SHARP_IGNORE_GLOBAL_LIBVIPS", "/usr/lib"),
        // A longer name that only starts with one of them is a different
        // setting, and keeps the screens the name test gives it.
        ("PUPPETEER_SKIP_DOWNLOAD_DIR", "1"),
        ("ESLINT_USE_FLAT_CONFIG_PATH", "true"),
        ("PUPPETEER_SKIP", "1"),
        // Neighbours in the same families that really do name code or a path.
        ("PUPPETEER_EXECUTABLE_PATH", "/usr/bin/chrome"),
        ("PLAYWRIGHT_BROWSERS_PATH", "/tmp/browsers"),
        ("ELECTRON_RUN_AS_NODE", "1"),
    ] {
        assert!(!inert_tool_setting(name, value), "{name}={value}");
    }
}
