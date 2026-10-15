use super::{literal_pattern, wildcard_matches};

#[test]
fn matcher_covers_every_name_a_shell_could_expand() {
    for (pattern, name) in [
        ("*.json", "commands.json"),
        ("*.json", "COMMANDS.JSON"),
        ("*.json", ".hidden.json"),
        ("*.json", "*.json"),
        ("v?.md", "v1.md"),
        ("*", "anything"),
        ("a*b*c", "abc"),
    ] {
        assert!(
            wildcard_matches(pattern.as_bytes(), name.as_bytes()),
            "{pattern} {name}"
        );
    }
    for (pattern, name) in [
        ("*.json", "commands.jsonl"),
        ("v?.md", "v10.md"),
        ("a*b*c", "acb"),
    ] {
        assert!(
            !wildcard_matches(pattern.as_bytes(), name.as_bytes()),
            "{pattern} {name}"
        );
    }
}

#[test]
fn only_plain_last_component_patterns_are_modelled() {
    for pattern in ["*.json", "*.rs", "schema-?.json", "v1.*", "*"] {
        assert!(literal_pattern(pattern), "{pattern}");
    }
    for pattern in [
        "",
        "commands.json",
        "**",
        "**.json",
        ".*",
        ".env*",
        "[a-z]*.json",
        "{a,b}.json",
        "*.json~",
        "*(x)",
        "!(*.json)",
        "^*.json",
        "*#",
        "*\\.json",
        "* .json",
        "*$HOME",
        "*`id`",
    ] {
        assert!(!literal_pattern(pattern), "{pattern}");
    }
}
