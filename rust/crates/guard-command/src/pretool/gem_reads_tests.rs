use super::safe_gem_arguments;

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
