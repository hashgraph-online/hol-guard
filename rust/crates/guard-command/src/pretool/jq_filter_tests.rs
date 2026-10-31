use super::{safe_filter, variables_bound};

#[test]
fn admits_projection_and_reshaping_pipelines() {
    for filter in [
        ".scripts",
        ".scripts | keys | length",
        ".dependencies|keys_unsorted|sort",
        ".items[0] | .name",
        ".[] | type",
        ".queries | keys[]",
        ".queries | to_entries[] | .key",
        ".items | keys[0]",
        ".queries | has(\"auth_attempts\")",
        ".queries | keys | join(\"\\n\")",
        ".name | split(\"/\") | .[0]",
        ".list | has(0)",
        ".name | startswith(\"a|b\")",
        "keys",
        "length",
        "keys[]",
        "to_entries | length",
        "{\"a\": .queries|has(\"x\"), \"b\": .queries|has(\"y\")}",
        "{name: .name, count: .items | length}",
        "{\"a b\": {inner: .x | keys}}",
        ".queries | {\"q x\": has(\"a:b,c\")}",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn admits_selection_and_mapping_over_the_value_read() {
    for filter in [
        "select(.draft)",
        ".[] | select(.number)",
        "map(.number)",
        "map(.number) | length",
        "map_values(.name)",
        "with_entries(select(.value))",
        "del(.meta)",
        "any(.flag)",
        "all(.flag)",
        "first(.items[])",
        "sort_by(.name)",
        "group_by(.kind) | map(length)",
        "unique_by(.id) | length",
        "min_by(.rank)",
        "max_by(.rank) | .name",
        ".[] | select(.name | startswith(\"fix\"))",
        "map(select(.state)) | length",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn admits_comparisons_against_a_filter_or_a_literal() {
    for filter in [
        ".number == 1",
        ".name != \"main\"",
        ".count > 0",
        ".count >= 10",
        ".count < 100",
        ".count <= 100",
        ".draft == false",
        ".parent == null",
        ".left == .right",
        "length > 0",
        ".[] | select(.conclusion != \"SUCCESS\")",
        "map(select(.number > 100)) | length",
        "select(.state == \"open\" and .draft == false)",
        "select(.state == \"open\" or .state == \"merged\")",
        ".items | select(length > 2)",
        ".score >= 1.5",
        ".score < -1",
        ".score == -1.5",
        ".score > .5",
        ".score == 1e-2",
        "select(.score >= 1.5)",
        "select(.score < -1)",
        "map(select(.ratio >= 0.5)) | length",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn admits_arrays_groups_and_fallbacks() {
    for filter in [
        "[.[] | .name]",
        "[.[] | select(.draft == false)] | length",
        "[.items[] | .id] | unique",
        "(.a)",
        "(.a // .b) | length",
        ".body // \"\"",
        ".title // .name // \"untitled\"",
        ".count // 0",
        "{names: [.[] | .name]}",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

/// `and` and `or` are split on the spaced keyword, so a field or builtin that
/// merely contains those letters is never cut in two.
#[test]
fn admits_names_that_contain_a_boolean_keyword() {
    for filter in [
        ".order",
        ".order | keys",
        ".candidate | length",
        ".dependencies | keys_unsorted",
        ".android",
        "{order: .order, candidate: .candidate}",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn rejects_environment_input_and_module_access() {
    for filter in [
        "env",
        ".a | env",
        ".a | $ENV",
        ".a | input",
        ".a | inputs",
        ".a | input_filename",
        ".a | debug",
        ".a | halt_error",
        ".a | @sh",
        "input",
        "inputs",
        "$__loc__",
        "input_filename",
        "select(env)",
        "map(input)",
        "[env]",
        "(env)",
        ".a // env",
        ".a == env",
        "{a: [env]}",
        "import \"x\"",
        "include \"x\"",
        "def f: env; f",
        "reduce .[] as $x (0; .)",
        "foreach .[] as $x (0; .)",
        "limit(1; .[])",
        "range(1; 2)",
        "getpath([\"a\"]) | input",
        "$x",
        ".a | has(\"\\(env)\")",
        "{\"\\(env)\": .x}",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

#[test]
fn rejects_builtins_outside_the_lists() {
    for filter in [
        ".a | test(\"x\")",
        ".a | keys()",
        ".a | tostring(1)",
        ".a | env[]",
        ".a | input[]",
        "walk(.a)",
        "setpath([\"a\"]; 1)",
        "ltrimstr(.a)",
        ".a | has(.b)",
        ".a | has($x)",
        ".a | has(\"x\", \"y\")",
        ".a | has(\"x\")(\"y\")",
        "select(.a; .b)",
        "map(.a; .b)",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

/// Only the two-character comparison spellings are read as operators, so an
/// assignment — which writes back into the value — never parses.
#[test]
fn rejects_assignment_and_arithmetic() {
    for filter in [
        ".a = 1",
        ".a |= 1",
        ".a += 1",
        ".a //= 1",
        ".a |= .b",
        ".a + 1",
        ".a - 1",
        ".a * 2",
        ".a / 2",
        ".a % 2",
        ".a == 1 == 2",
        ".a < 1 < 2",
        ".a ==",
        "== .a",
        ".a == +1",
        ".a == 1e",
        ".a == 1e+",
        ".a == -",
        ".a == --1",
        ".a == 1.2.3",
        ".a and",
        ".a or",
        "and .a",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

#[test]
fn rejects_unbalanced_or_empty_constructions() {
    for filter in [
        "[.a",
        ".a]",
        "(.a",
        ".a)",
        "[]",
        "()",
        "{}",
        "{a: .x",
        "a: .x}",
        "{a: .x}{b: .y}",
        "[.a][0]",
        "(.a)(.b)",
        ".a | has(\"x)",
        ".a | has(\"\\\"\")",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

/// A plain literal is an operand, never a stage: a filter may compare against
/// `"x"` or fall back to it, but a stage still has to read the value.
#[test]
fn rejects_a_bare_literal_as_a_stage() {
    for filter in [
        ".a | \"x\"",
        ".a | keys[] | \"x\"",
        "\"x\"",
        "select(\"x\")",
        "map(1)",
        "[\"x\"]",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

#[test]
fn rejects_malformed_and_oversized_pipelines() {
    for filter in [
        ".a : .b",
        ".a |",
        ".a | | length",
        ". | keys | keys | keys | keys | keys | keys | keys | keys",
        "{$ENV}",
        "{a,}",
        "{a, .b}",
        "{@tsv}",
        "{(.a): .b}",
        "{a: env}",
        "{a: input}",
        "{a: .x, .y}",
        "{a: .x: .y}",
        "{a-b: .x}",
        "{a: .x | @sh}",
        "{a: .x | tostring(1)}",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

#[test]
fn admits_bare_rendering_formats_and_shorthand_keys() {
    for filter in [
        ".[] | @tsv",
        ".workflow_runs[] | [.id, .name] | @tsv",
        "select(.a) | @base64",
        "map(.a | @text)",
        ".items | @json",
        ".[] | [.a, .b] | @csv",
        ".name | @uri",
        ".blob | @base64d",
        "{a}",
        "{number,title,state}",
        "{\"a b\", count: .items | length}",
        ".[] | {number, title}",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn rejects_shell_and_templated_formats() {
    for filter in [
        "@sh",
        ".[] | @sh",
        "@sh \"rm \\(.a)\"",
        "@tsv \"x\"",
        "@text \"\\(env)\"",
        "@tsvx",
        "@",
        "@ tsv",
        ".a@tsv",
        "@tsv@csv",
        "@format(\"tsv\")",
        "{a: @sh}",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

#[test]
fn rejects_a_filter_longer_than_the_bound() {
    let filter = format!(".{}", "a".repeat(300));
    assert!(!safe_filter(&filter));
}

#[test]
fn admits_variables_the_filter_binds_itself() {
    for filter in [
        "empty",
        ".[] | empty",
        ". as $x | $x",
        ".[] | select((.conclusion // .state // \"\") as $s | ($s != \"SUCCESS\" and $s != \"SKIPPED\"))",
        ".items as $items | $items[0]",
        ".check as $check | {name: $check.name}",
        ".[] | .name as $name | $name | length",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn rejects_variables_from_outside_the_filter() {
    for filter in [
        // Named outside the filter, bound or not.
        ". as $ENV | $ENV",
        ". as $__loc__ | $__loc__",
        "$ENV.HOME",
        // A `--arg` value, or a name bound by a form this grammar does not read.
        ".a as $a | $b",
        ". as [$a] | $a",
        "{a: $a}",
        // `as` binds tighter than `//`, so only `.b` is bound here.
        ".a // .b as $s | $s",
        // A binding needs a body, and a `$` needs a name.
        ".a as $s",
        ".a | $",
        ". as $1 | $1",
        // Interpolated text is code, so its names are read too.
        ". as $x | \"\\($ENV)\"",
        // A binding reaches the end of its own group, and no earlier.
        "map(. as $x | .) | $x",
        "(.a as $x | .b) | $x",
        "$x | . as $x | $x",
        // `as $x` written in string text binds nothing.
        "\"as $x \\(.foo)\" | $x",
        "\"as $x\" | $x",
    ] {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

/// The `gh --jq` path checks bindings alone, without the read grammar, so the
/// scope rules hold on their own.
#[test]
fn a_binding_is_read_only_inside_its_scope() {
    for filter in [
        ". as $x | $x",
        ".[] | select((.state // \"\") as $s | ($s != \"OPEN\"))",
        ".a as $x | {b: [$x]}",
        "\"\\(.a)\" as $x | $x",
        "\"$x is text\"",
        "\"#\" as $x | $x",
    ] {
        assert!(variables_bound(filter), "expected bound: {filter}");
    }
    for filter in [
        "map(. as $x | .) | $x",
        "[.[] | . as $x | $x] | $x",
        "$x | . as $x | $x",
        "\"as $x \\(.foo)\" | $x",
        "\"\\(. as $x | $x)\" | $x",
        "(. as $x | $x",
        ". as $x | $x)",
        "\"open",
        ". # \"\n| $ENV # \"",
        ". as $x | $x # \"\n| $y # \"",
    ] {
        assert!(!variables_bound(filter), "expected unbound: {filter}");
    }
}

#[test]
fn admits_sequences_slices_and_optional_projections() {
    for filter in [
        ".number, .title",
        ".[] | .headBranch, .headSha",
        ".[] | [.headBranch, .headSha[0:12], .databaseId]",
        ".a, .b, .c | length",
        ".headSha[0:12]",
        ".items[1:]",
        ".items[:3]",
        ".items[-2:]",
        ".items[-2:-1]",
        ".items[:]",
        ".name[0:4] | ascii_downcase",
        ".[]?",
        ".a?",
        ".a?.b",
        ".items[]? | .name",
        "map(.a)?",
        "(.a // .b)?",
        "select(.draft)? | .number",
        ".[] | select(.a == 1), .b",
    ] {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

#[test]
fn rejects_malformed_sequences_slices_and_optionals() {
    for filter in [
        ".a,",
        ",",
        ".a, env",
        ".items[-]",
        ".items[1:2:3]",
        ".items[a:1]",
        ".items[1:b]",
        ".a ? .b",
        "?",
        ".a[0:12]x",
        "? .a",
    ] {
        assert!(!safe_filter(filter), "expected refused: {filter}");
    }
}
