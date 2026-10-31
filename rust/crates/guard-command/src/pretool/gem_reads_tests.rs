use super::{gemrc_inert, inert_gemrc_line, safe_gem_arguments};
use std::fs;

fn safe(command: &str) -> bool {
    let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    safe_gem_arguments(&arguments)
}

#[test]
fn index_and_inventory_queries_are_read_only() {
    for command in [
        "list",
        "list --local",
        "list -l -d",
        "list rails",
        "search -r rails",
        "search --remote --exact rails",
        "query -i rake",
        "info rake",
        "info --remote rake",
        "which rake",
        "which -a rake",
        "contents rake",
        "contents --all --lib-only",
        "dependency rake",
        "dependency -R --pipe rake",
        "specification rake",
        "specification --yaml rake",
        "specification rake dependencies",
        "outdated",
        "outdated --local",
        "environment",
        "environment gemdir",
        "sources",
        "sources --list",
        "sources -l",
    ] {
        assert!(safe(command), "gem {command}");
    }
}

#[test]
fn source_writes_and_value_options_stay_reviewed() {
    for command in [
        "",
        "install rails",
        "update",
        "uninstall rake",
        "cleanup",
        "pristine rake",
        "build rake.gemspec",
        "push rake-1.0.gem",
        "yank rake",
        "owner rake",
        "fetch rake",
        "unpack rake",
        "open rake",
        "exec rake",
        "generate_index",
        "sources --add https://example.invalid",
        "sources -a https://example.invalid",
        "sources --remove https://example.invalid",
        "sources --clear-all",
        "sources --update",
        "list -u",
        "list --update-sources",
        "search --clear-sources rails",
        "search -s https://example.invalid rails",
        "info --config-file /tmp/gemrc rake",
        "list -v 1.2.3",
        "contents --spec-dir /tmp/specs rake",
        "outdated --platform ruby",
        "specification ./rake.gemspec",
        "specification rake-1.0.gem",
        // The field is answered with `send`, and this one compiles and runs
        // the gem's own `extconf.rb`.
        "specification rake build_extensions",
        "specification rake activate",
        "specification rake dependencies summary",
        "info ../rake",
        "info https://example.invalid/rake",
        "which",
        "contents",
        "specification",
        "environment gemdir gempath",
        "environment credentials",
    ] {
        assert!(!safe(command), "gem {command}");
    }
}

#[test]
fn a_gemrc_that_only_shortens_the_output_is_inert() {
    for line in [
        "",
        "# a comment",
        "---",
        "gem: --no-document --quiet",
        "install: --no-document",
        ":verbose: false",
        ":backtrace: true",
        ":bulk_threshold: 1000",
    ] {
        assert!(inert_gemrc_line(line), "{line}");
    }
}

#[test]
fn a_gemrc_that_adds_a_source_or_a_write_keeps_the_review() {
    for line in [
        ":sources:",
        "  - https://example.invalid",
        ":update_sources: true",
        ":ssl_ca_cert: /tmp/ca.pem",
        ":gempath: /tmp/gems",
        "gem: --source https://example.invalid",
        "list: --update-sources",
        "search: -u",
        "gem: --config-file /tmp/gemrc",
        "custom_shebang: /tmp/ruby",
        "not a mapping",
    ] {
        assert!(!inert_gemrc_line(line), "{line}");
    }
}

#[test]
fn a_missing_gemrc_is_inert_and_a_written_one_is_read() {
    let home = tempfile::tempdir().expect("temp home");
    let path = home.path().join(".gemrc");
    assert!(gemrc_inert(&path));
    fs::write(&path, "gem: --no-document\n").expect("write gemrc");
    assert!(gemrc_inert(&path));
    fs::write(&path, "gem: --source https://example.invalid\n").expect("write gemrc");
    assert!(!gemrc_inert(&path));
}
