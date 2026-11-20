use super::{parse_program, parse_python, uses_earlier_cell_draft};

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

/// The prelude's `sh(command)` is modelled only for one string literal: the
/// command judged is then the command the bridge runs.
#[test]
fn literal_sh_is_parsed_as_one_shell_call() {
    for code in [
        "await sh('git status')",
        "await sh(\"git status\");",
        "await sh(`git status`)",
        "await sh`git status`",
        "console.log(await sh('git status'))",
        "const out = await sh('git status'); display(out);",
    ] {
        let calls = parse_program(code).unwrap_or_else(|| panic!("{code}"));
        assert_eq!(calls.len(), 1, "{code}");
        assert_eq!(calls[0].tool, "bash", "{code}");
        assert!(calls[0].shell_helper, "{code}");
    }
    for code in [
        "await sh('git status', { cwd: 'sub' })",
        "await sh('git status', {})",
        "await sh(`git ${'status'}`)",
        "await sh`git ${'status'}`",
        "await sh`git status\\n`",
        "await sh('git ' + 'status')",
        "await sh()",
        "await sh('   ')",
        "const c = 'git status'; await sh(c)",
        "const sh = 'x'; await sh('git status')",
        "await sh.call(null, 'git status')",
    ] {
        assert!(parse_program(code).is_none(), "{code}");
    }
    let calls = parse_program("await tool.bash({command: 'git status'})").unwrap();
    assert!(!calls[0].shell_helper);
}

#[test]
fn a_commit_draft_is_one_commit_call_in_its_repository() {
    let calls = parse_program(
        "const d = await commit.draft({ agents: 'self', repo: '../report' }); await d.take(['a.js']); print(d); return await d.commit('Add report', {body: ['x'], fixes: 3});",
    )
    .unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool, "commit");
    assert_eq!(
        calls[0].args,
        vec![("cwd".to_owned(), super::Lit::Str("../report".to_owned()))]
    );
    assert!(
        parse_program("const d = await commit.draft(); return await d;")
            .unwrap()
            .iter()
            .all(|call| call.args.is_empty())
    );
    for code in [
        // `amend` rewrites a commit that already exists.
        "const d = await commit.draft(); await d.commit('x', {amend: true});",
        "const d = await commit.draft(); await d.commit('x', {amend: false});",
        // Arguments are literals only.
        "const p = 'a'; const d = await commit.draft(); await d.take(p);",
        "const d = await commit.draft({ repo: `../${'x'}` });",
        "const d = await commit.draft({ repo: '' });",
        "const d = await commit.draft({ repo: '..', repo: '/' });",
        "const d = await commit.draft('..');",
        // Only the documented methods, on a name bound to an awaited draft.
        "const d = await commit.draft(); await d.reset();",
        "const d = await commit.draft(); await d['commit']('x');",
        "const d = commit.draft();",
        "await commit.draft().commit('x');",
        "const d = await commit.draft(); const d2 = d.take; await d2();",
        // A name bound again stops being the draft.
        "let d = await commit.draft(); let d = 1; await d.take('a');",
        "const commit = 1;",
    ] {
        assert!(parse_program(code).is_none(), "{code}");
    }
}

#[test]
fn draft_methods_on_an_unbound_name_are_an_earlier_cell_draft() {
    for code in [
        "await d.show();",
        "await d.take('docs/a.md'); print(d);",
        "await draft.commit('docs: x', ['- y']);",
        "return typeof d.commit;",
    ] {
        assert!(parse_program(code).is_none(), "{code}");
        assert!(uses_earlier_cell_draft(code), "{code}");
    }
    for code in [
        "const d = await commit.draft(); await d.show();",
        "const d = {show() {}}; await d.show();",
        "let d = 1; await d.show();",
        "await d.push('x');",
        "await d.commit('x', {amend: true});",
        "await d.show(); sh(`rm -rf ${x}`);",
        "await commit.show();",
        "await a.b.show();",
        "",
    ] {
        assert!(!uses_earlier_cell_draft(code), "{code}");
    }
}
