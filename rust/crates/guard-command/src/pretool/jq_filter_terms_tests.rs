use super::super::safe_filter;

fn admitted(filters: &[&str]) {
    for filter in filters {
        assert!(safe_filter(filter), "expected admitted: {filter}");
    }
}

fn refused(filters: &[&str]) {
    for filter in filters {
        assert!(!safe_filter(filter), "expected rejected: {filter}");
    }
}

/// Arithmetic only combines values its operands already read, so it reaches
/// no further than they do.
#[test]
fn admits_arithmetic_over_the_value_read() {
    admitted(&[
        ".a + 1",
        ".a - 1",
        ".a * 2",
        ".a / 2",
        ".a % 2",
        ".cost * 1000 | round / 1000",
        ".name + \" \" + .state",
        "sort_by(-.number)",
        ".a | -.b",
        ".a - -.b",
        "-1",
        ".a == -1",
        "1e-2 + .a",
        "map(.size) | add / length",
    ]);
}

#[test]
fn rejects_arithmetic_over_a_refused_operand() {
    refused(&[
        ".a + env",
        "env * 2",
        "-env",
        "sort_by(-$ENV)",
        ".a + input",
        "--1",
        "-+1",
        "-",
        ".a +",
        "+ .a",
        ".a + + .b",
    ]);
}

/// An assignment rewrites jq's in-memory copy of the value read; it writes
/// nothing back to the file or the stream jq read from.
#[test]
fn admits_assignment_to_the_value_read() {
    admitted(&[
        ".a = 1",
        ".a |= 1",
        ".a += 1",
        ".a //= 1",
        ".a |= .b",
        ".items[] |= (.name |= ascii_downcase)",
        ".build.sources[0] = .x",
    ]);
}

#[test]
fn rejects_assignment_from_a_refused_filter() {
    refused(&[
        ".a = env",
        ".a |= input",
        ".a += $ENV.HOME",
        "env = 1",
        ".a = ",
        "= .a",
    ]);
}

#[test]
fn admits_conditionals_reductions_and_value_builtins() {
    admitted(&[
        "if .a then 1 else 2 end",
        "if .a == 1 then \"one\" elif .a == 2 then \"two\" else \"many\" end",
        "reduce .[] as $x (0; . + $x)",
        "reduce .[] as $x (0; .)",
        "foreach .[] as $x (0; . + 1)",
        "limit(1; .[])",
        "range(1; 2)",
        ".a | test(\"x\")",
        ".a | test(\"x\"; \"i\")",
        "map(select(.a | test(\"^v\")))",
        "walk(.a)",
        "setpath([\"a\"]; 1)",
        "ltrimstr(.a)",
        ".a | has(.b)",
        ".a | has(\"x\", \"y\")",
        ".a | has(\"\\\"\")",
        "capture(\"(?<p>x)\")?.p",
        "try .a catch \"none\"",
        ". | keys | keys | keys | keys | keys | keys | keys | keys",
    ]);
}

#[test]
fn rejects_refused_filters_inside_new_forms() {
    refused(&[
        "if env then 1 else 2 end",
        "if .a then input else 2 end",
        "if .a then 1 else $ENV end",
        "if .a then 1",
        ".a | end",
        "reduce .[] as $x (0; env)",
        "reduce env as $x (0; .)",
        "foreach .[] as $x (0; input)",
        "limit(1; inputs)",
        "test(env)",
        "walk(env)",
        "capture(\"x\")?.p | env",
        "try env catch 1",
        ".a | $x",
        "reduce .[] as $x (0; .) | $x",
    ]);
}

/// A literal reads nothing, so a filter that only produces one reaches no
/// further than the value read.
#[test]
fn admits_literals_and_constructions() {
    admitted(&[
        "\"x\"",
        ".a | \"x\"",
        ".a | keys[] | \"x\"",
        "select(\"x\")",
        "map(1)",
        "[\"x\"]",
        "[]",
        "{}",
        "[.a][0]",
        "{(.a): .b}",
        ".a | has(\"\\(.b)\")",
        ".a | join(\"\\(.b)\")",
    ]);
    refused(&["{$__loc__}", "{(env): .b}", "{(.a): input}", "\"\\(env)\""]);
}

/// A zero-arity definition is replaced by its body where it is used, which
/// is what jq runs, so the filter is read as it executes.
#[test]
fn admits_zero_arity_definitions() {
    admitted(&[
        "def internal: .login == \"bot\"; map(select(internal | not))",
        "def regen: (.headRefName | startswith(\"regen/\")); map(select(regen))",
        "def name: (.name // \"\"); map(name)",
        "def a: .x; def b: a + 1; .[] | b",
        "def a: .x;\nmap(a)",
        "def a: .x; \"\\(a)\"",
    ]);
}

#[test]
fn rejects_definitions_this_grammar_does_not_read() {
    refused(&[
        "def f: env; f",
        "def f: f; .",
        "def f: \"\\(f)\"; f",
        "def f(x): x; f(.)",
        "def f: .a; f(1)",
        "def f: $x; f",
        "def if: .a; .",
        "def f: .a;",
        "def f: .a; def g: env; f",
        ".a | def f: .b; f",
        "def f: .a; def f2: input; .",
    ]);
}

#[test]
fn rejects_comments_and_stray_separators() {
    refused(&[".a # env", ".a;", ".a; .b", "(.a; .b)", "\"\\(.a; .b)\""]);
}
