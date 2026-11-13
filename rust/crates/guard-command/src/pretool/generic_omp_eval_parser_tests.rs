use super::{parse_program, parse_python};

#[test]
fn python_read_lines_are_parsed_as_reads() {
    let calls =
        parse_python("print(read('calc.py'))\ndisplay(read(\"a.ts\"))\nread('b')\n").unwrap();
    assert_eq!(calls.len(), 3);
    for code in [
        "import os",
        "print(read('a'));import os",
        "  print(read('a'))",
        "print(read(r'a'))",
        "print(read('a', 1, 5))",
        "print(read('~/.ssh/id_rsa'))",
        "print(read('a'))  # note",
        "print(read('a'))\rimport os",
        "print(read(\n'a'))",
        "x = read('a')",
        "",
        "print(read('a\\b'))",
        "print(read('a`b'))",
        "read(`a`)",
    ] {
        assert!(parse_python(code).is_none(), "{code:?}");
    }
}

#[test]
fn literal_read_helper_is_parsed_as_one_read() {
    let calls = parse_program("display(await read('README.md'))").unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool, "read");
}

/// The JavaScript prelude sets `globalThis.print = consoleBridge.log`, so an
/// agent that prints what a tool returned only shows it, as `display` does.
#[test]
fn print_shows_a_tool_result_like_display() {
    for code in [
        "const content = await tool.read({path: \"notes/SKILL.md\"}); print(content);",
        "const content = await tool.read({path: \"notes/SKILL.md\"}); display(content);",
        "print(await read('README.md'))",
    ] {
        let calls = parse_program(code).unwrap_or_else(|| panic!("{code}"));
        assert_eq!(calls.len(), 1, "{code}");
        assert_eq!(calls[0].tool, "read", "{code}");
    }
    // `print` stays the prelude's: a program may not rebind it.
    assert!(parse_program("const print = 1; print(await read('README.md'))").is_none());
}

/// The host shows a final top-level `return value;` as the cell's result, so
/// returning what a tool read only shows it. A `return` before other
/// statements would stop the cell early and is refused.
#[test]
fn a_final_return_shows_a_tool_result() {
    for code in [
        "const content = await tool.read({path: \"notes/SKILL.md\"}); return content;",
        "return await read('README.md');",
        "const content = await tool.read({path: \"notes/SKILL.md\"}); content;",
        "const content = await read('README.md');\nreturn content;",
        "return await read(\n'README.md');",
    ] {
        let calls = parse_program(code).unwrap_or_else(|| panic!("{code}"));
        assert_eq!(calls.len(), 1, "{code}");
        assert_eq!(calls[0].tool, "read", "{code}");
    }
    for code in [
        "const a = await read('README.md'); return a; const b = await read('notes/x.md');",
        "return;",
        "const a = await read('README.md'); return a display(a)",
        // A line break after `return` ends the statement, so nothing is shown.
        "return\nawait read('README.md');",
        "return\r\nawait read('README.md');",
        "const a = await read('README.md'); return\n  a;",
    ] {
        assert!(parse_program(code).is_none(), "{code}");
    }
}

/// Showing part of what a tool read, such as its first line, only computes a
/// new string. Callbacks, computed keys and unlisted methods stay outside the
/// grammar.
#[test]
fn pure_string_methods_on_a_tool_result_only_show_it() {
    for code in [
        "const text = await read('notes/SKILL.md'); print(text.split('\\n')[0]);",
        "const text = await read('notes/SKILL.md'); display(text.trim().split('\\n').slice(0, 5).join('\\n'));",
        "const c = await tool.read({path: \"notes/SKILL.md\"}); return c.text.split('\\n').at(0);",
        "const text = await read('notes/SKILL.md'); log(text.includes('name'), text.length);",
    ] {
        let calls = parse_program(code).unwrap_or_else(|| panic!("{code}"));
        assert_eq!(calls.len(), 1, "{code}");
        assert_eq!(calls[0].tool, "read", "{code}");
    }
    for code in [
        "const text = await read('notes/SKILL.md'); print(text['constructor']);",
        "const text = await read('notes/SKILL.md'); print(text.constructor('x'));",
        "const text = await read('notes/SKILL.md'); print(text.split('\\n').map(line => line));",
        "const text = await read('notes/SKILL.md'); print(text.replace('a', 'b'));",
        "const text = await read('notes/SKILL.md'); print(text.split);",
        "const text = await read('notes/SKILL.md'); print(text[x]);",
    ] {
        assert!(parse_program(code).is_none(), "{code}");
    }
}
