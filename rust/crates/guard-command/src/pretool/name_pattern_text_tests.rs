use crate::pretool::search_pattern_text::command_sensitive;

fn sensitive(command: &str) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .expect("the command parses");
    command_sensitive(&model, command, None)
}

/// A `find` name test and a `pytest -k` expression only choose among names
/// the command already walks or collects. A credential word there selects
/// tests or prints file names; it opens nothing.
#[test]
fn a_name_pattern_is_not_a_sensitive_target() {
    for command in [
        "pytest -k password -v",
        "pytest tests/test_options.py -k password -v",
        "python -m pytest tests/ -k password -v",
        "python3 -m pytest -k \"password and not slow\"",
        "find examples -name \"*password*\" -o -name \"*prompt*\" | head -10",
        "find . -iname '*secret*'",
        "find src -path '*credentials*' -type f | wc -l",
        "find . -name '*token*' | grep -v node_modules | head -n 20",
        "find src -name '*password*' | head",
        "find src -name '*password*' | wc -l",
    ] {
        assert!(!sensitive(command), "{command} still reads as sensitive");
    }
}

/// The pattern is set aside only while nothing can open what it selects.
/// Names handed to a program that reads them, a `find` action, shell text
/// inside the pattern, and a credential path outside it all keep the screen.
#[test]
fn a_pattern_that_can_reach_a_file_keeps_its_screen() {
    for command in [
        "find . -name \"*password*\" | xargs cat",
        "find . -name \"*password*\" -exec cat {} \\;",
        "find . -name '*secret*' -fprint out.txt",
        "find . -name '*secret*' | head -5 | xargs cat",
        "find . -name '*secret*' | tail -f",
        "find . -name '*secret*' | wc -c 5",
        "find . -name '*secret*' | head .env",
        "pytest -k password .env",
        "pytest -k password -- -k secret",
        "cat .env | head",
    ] {
        assert!(sensitive(command), "{command} lost a signal to the mask");
    }
}

/// A Vitest or Jest test-name filter selects among collected test titles.
/// A credential word there names a test, not a file the run opens.
#[test]
fn a_runner_test_name_filter_is_not_a_sensitive_target() {
    for command in [
        "npx vitest run -t \"masks the secret field\"",
        "npx vitest run src/form.test.ts -t \"rejects a short password\"",
        "node ./node_modules/vitest/vitest.mjs run -t \"keeps the secret hidden\"",
        "./node_modules/.bin/vitest run --testNamePattern \"password reset\"",
        "npx vitest run --testNamePattern=secret",
        "npx jest -t \"stores the token hash\"",
        "npx vitest run -t secret | tail -20",
    ] {
        assert!(!sensitive(command), "{command} still reads as sensitive");
    }
}

/// The filter is set aside only while it cannot name a file. A path-shaped
/// value, a credential operand beside it, shell text, or a runner the
/// contained lane does not know all keep the screen.
#[test]
fn a_runner_filter_that_can_name_a_file_keeps_its_screen() {
    for command in [
        "npx vitest run -t .env",
        "npx vitest run -t secrets/key.pem",
        "npx vitest run -t ~/.aws/credentials",
        "npx vitest run -t password .env",
        "npx vitest run -t \"password $(cat .env)\"",
        "npx vitest run -t secret | xargs cat",
        "npx vitest run -- -t secret",
        "npx mocha -g secret",
        "cat .env && npx vitest run -t secret",
    ] {
        assert!(sensitive(command), "{command} lost a signal to the mask");
    }
}
