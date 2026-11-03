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
        ("NPM_CONFIG_LOGLEVEL", "error"),
        ("NPM_CONFIG_LOGLEVEL", "silent"),
        ("NPM_CONFIG_PROGRESS", "false"),
        ("NPM_CONFIG_FUND", "false"),
        ("NPM_CONFIG_AUDIT", "false"),
        ("NPM_CONFIG_COLOR", "always"),
        ("NPM_CONFIG_UPDATE_NOTIFIER", "false"),
        // npm reads the lowercase spelling, which is the one a shell prefix
        // usually carries.
        ("npm_config_loglevel", "error"),
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
        // npm's own keys for the shell it runs scripts with, the files it
        // reads its configuration from, where it caches and which registry
        // it talks to. Each is the reason the whole `npm_config_` family is
        // refused by name, and none of them is on the reporting list.
        ("NPM_CONFIG_SCRIPT_SHELL", "/bin/sh"),
        ("NPM_CONFIG_SHELL", "/bin/sh"),
        ("NPM_CONFIG_USERCONFIG", "/tmp/npmrc"),
        ("NPM_CONFIG_GLOBALCONFIG", "/tmp/npmrc"),
        ("NPM_CONFIG_CACHE", "/tmp/cache"),
        ("NPM_CONFIG_PREFIX", "/tmp/prefix"),
        ("NPM_CONFIG_REGISTRY", "https://example.invalid/"),
        ("NPM_CONFIG_NODE_OPTIONS", "--require ./evil.js"),
        // A listed key carrying a value npm does not read for it. The list
        // answers for the pair, never for the key alone.
        ("NPM_CONFIG_LOGLEVEL", "/tmp/log"),
        ("NPM_CONFIG_LOGLEVEL", "error extra"),
        ("NPM_CONFIG_LOGLEVEL", ""),
        ("NPM_CONFIG_PROGRESS", "maybe"),
        // A key outside the list, however harmless it reads.
        ("NPM_CONFIG_FOO", "1"),
        // The prefix is the whole family marker, so a name that only starts
        // like it is not one of npm's keys at all.
        ("NPM_CONFIGLOGLEVEL", "error"),
        ("NPM_CONFIG", "error"),
        // A name this module does not read stays with the shared screens.
        ("NODE_OPTIONS", "--no-warnings"),
        ("LD_PRELOAD", ""),
        ("MAKEFLAGS", "-j4"),
    ] {
        assert!(!inert_tool_setting(name, value), "{name}={value}");
    }
}
