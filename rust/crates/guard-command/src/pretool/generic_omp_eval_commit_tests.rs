use super::parse_commit_program;
use super::Lit;

fn commands(code: &str) -> Option<Vec<(String, Option<String>)>> {
    let calls = parse_commit_program(code)?;
    Some(
        calls
            .into_iter()
            .map(|call| {
                assert_eq!(call.tool, "bash");
                assert!(call.shell_helper);
                let text = |name: &str| {
                    call.args.iter().find_map(|(key, lit)| match lit {
                        Lit::Str(text) if key == name => Some(text.clone()),
                        _ => None,
                    })
                };
                (text("command").unwrap(), text("cwd"))
            })
            .collect(),
    )
}

const STATUS: &str = "git status --short";
const COMMIT: &str = "git add -A && git commit -q -m commit";

#[test]
fn drafts_and_commits_map_to_git_commands() {
    let observed = [
        "const d = await commit.draft(); return await d.commit('Fix sum', ['Start at index 0.']);",
        "const d = await commit.draft({ agents: 'self' }); await d.take('src/sum.js'); await d.take(['a.js', 'b.js']); return await d.commit('Fix sum', {body: ['- Start at index 0.']});",
        "const d=await commit.draft(); for (const p of ['index.html','game.js']) await d.take(p); return await d.commit('Build game',['Canvas game.']);",
        "const d = await commit.draft(); print(d); await d.take(\"src/config.js\"); print(await d.commit(\"Raise timeout\", [\"Document it.\"]));",
        "const d = await commit.draft(); await d.take('**'); return await d.commit('Add CLI', {body:['Implement it.']});",
    ];
    for code in observed {
        let commands = commands(code).unwrap_or_else(|| panic!("rejected: {code}"));
        assert_eq!(commands.first().unwrap().0, STATUS, "{code}");
        assert_eq!(commands.last().unwrap().0, COMMIT, "{code}");
        assert!(commands.iter().all(|(_, cwd)| cwd.is_none()), "{code}");
    }
}

#[test]
fn draft_repository_becomes_the_command_directory() {
    let commands = commands(
        "const d = await commit.draft({ repo: '../weekly-report' }); await d.take('reports/**'); await d.commit('Add weekly report');",
    )
    .unwrap();
    assert_eq!(commands.len(), 3);
    assert!(commands
        .iter()
        .all(|(_, cwd)| cwd.as_deref() == Some("../weekly-report")));
}

#[test]
fn amend_and_skipped_hooks_reach_the_judged_command() {
    let commands = commands(
        "const d = await commit.draft(); await d.commit('Fix', {amend: true, noVerify: true});",
    )
    .unwrap();
    assert_eq!(
        commands.last().unwrap().0,
        format!("{COMMIT} --amend --no-verify")
    );
}

#[test]
fn documentation_read_runs_nothing() {
    assert_eq!(
        commands("return await read('xd://eval/commit');"),
        Some(vec![])
    );
    assert_eq!(commands("await read('xd://eval/commit');"), Some(vec![]));
}

#[test]
fn programs_outside_the_grammar_are_rejected() {
    for code in [
        // A draft from an earlier cell can be anything that cell bound.
        "return await d.take();",
        "const d = await commit.draft(); const s = 'x'; return await d.commit(s);",
        "const d = await commit.draft(); await sh('rm -rf src'); return await d.commit('x');",
        "const d = await commit.draft({ repo: '~/other' }); await d.commit('x');",
        "const d = await commit.draft({ repo: '$HOME' }); await d.commit('x');",
        "const d = await commit.draft({ cwd: '/' }); await d.commit('x');",
        "const d = await commit.draft(); await d.commit('');",
        "const d = await commit.draft(); await d.commit('x', {message: 'y'});",
        "const d = await commit.draft(); await d.push();",
        "const d = await commit.draft(); d.take = 1;",
        "const commit = 1;",
        "return await read('xd://other/commit');",
        "return await read('xd://eval/../../etc');",
        "const mod = await import('xd://eval/commit');",
        "const d = await commit.draft(); for (const p of [x]) await d.take(p);",
        "const d = await commit.draft();\nreturn\nawait d.commit('x');",
        "const d = await commit.draft(); return await d.commit('x'); await d.take('y');",
        "",
        "   ",
        // Text normalized before the repository opens can name another one.
        "const d = await commit.draft({ repo: 'scratch/../project' }); await d.commit('x');",
        // `show` needs a plain relative path inside the draft.
        "const d = await commit.draft(); return await d.show();",
        "const d = await commit.draft(); return await d.show('../outside.txt');",
        "const d = await commit.draft(); return await d.show('-p');",
        // An empty loop and one that outruns the call budget.
        "const d = await commit.draft(); for (const p of []) await d.take(p);",
        "const d = await commit.draft(); for (const p of ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y']) await d.take(p);",
    ] {
        assert_eq!(commands(code), None, "{code}");
    }
}

#[test]
fn diff_reads_are_judged_as_the_diff_they_print() {
    let commands = commands(
        "const d = await commit.draft(); print(await d.diff()); return await d.show('src/sum.js');",
    )
    .unwrap();
    let texts: Vec<&str> = commands.iter().map(|(text, _)| text.as_str()).collect();
    assert_eq!(
        texts,
        [STATUS, "git diff HEAD", "git diff HEAD -- src/sum.js"]
    );
}

#[test]
fn a_loop_counts_one_call_per_item() {
    let commands = commands(
        "const d = await commit.draft(); for (const p of ['a.js', 'b.js', 'c.js']) await d.take(p);",
    )
    .unwrap();
    assert_eq!(commands.len(), 2);
}
