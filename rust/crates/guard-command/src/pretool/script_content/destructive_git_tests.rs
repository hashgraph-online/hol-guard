use super::spells_destructive_git;

#[test]
fn programs_that_run_work_destroying_git_are_found() {
    for code in [
        r#"import subprocess as s; s.run(["git","reset","--hard","origin/main"])"#,
        r#"import os; os.system("git clean -fdx")"#,
        r#"require('child_process').execSync('git reset --hard')"#,
        r#"require('child_process').spawnSync('git', ['checkout', '--', '.'])"#,
        r#"system(*%w[git checkout -- .]) or abort"#,
        r#"system("git", "-C", "app", "restore", "src")"#,
        r#"subprocess.run("cd app && git stash clear", shell=True)"#,
        r#"subprocess.check_call(['git', 'branch', '-D', 'feature'])"#,
        r#"os.system('git clean --force -d')"#,
        r#"require('fs').rmSync('.git', {recursive: true, force: true})"#,
        r#"import shutil; shutil.rmtree('repo/.git')"#,
        r#"os.system("rm -rf .git")"#,
        r#"os.system("git -C 'my repo' reset --hard")"#,
    ] {
        assert!(spells_destructive_git(code), "{code}");
    }
}

#[test]
fn programs_that_read_git_or_only_mention_a_command_are_not() {
    for code in [
        r#"import subprocess as s; print(s.run(["git","status","--short"]).stdout)"#,
        r#"require('child_process').execSync('git log --oneline -5')"#,
        r#"os.system("git clean -n -d")"#,
        r#"subprocess.run(["git", "restore", "--staged", "app.py"])"#,
        r#"subprocess.run(["git", "checkout", "-b", "feature"])"#,
        r#"subprocess.run(["git", "stash", "list"])"#,
        r#"print("run git reset --hard to undo the change")"#,
        r#"import shutil; shutil.rmtree('build')"#,
        r#"print(open('.gitignore').read())"#,
        "print(1 + 1)",
    ] {
        assert!(!spells_destructive_git(code), "{code}");
    }
}

#[test]
fn a_program_fed_on_a_heredoc_or_given_to_ruby_is_read() {
    let home = std::env::temp_dir();
    let home = home.to_str().unwrap();
    let context = crate::pretool::PathContext {
        home_dir: Some(home),
        cwd: Some(home),
        ..Default::default()
    };
    let fed = "python3 - <<'PYEOF'\nimport os\nos.system('git reset --hard HEAD~3')\nPYEOF";
    assert!(super::text_spells_destructive_git(fed, context));
    let ruby = "ruby -e 'system(*%w[git checkout -- .]) or abort'";
    assert!(super::text_spells_destructive_git(ruby, context));
    let reads = "python3 -c 'import subprocess as s; s.run([\"git\",\"status\"])'";
    assert!(!super::text_spells_destructive_git(reads, context));
}

#[test]
fn assembled_forced_and_path_checkouts_are_found() {
    for code in [
        r#"import os; os.system("git " + "reset --hard")"#,
        r#"import os; os.system("git reset " "--hard")"#,
        r#"system('git ' . 'clean -fdx');"#,
        r#"import os; os.system("git checkout HEAD file.txt")"#,
        r#"subprocess.run(["git", "checkout", "HEAD~1", "src/app.py"])"#,
        r#"subprocess.run(["git", "switch", "--discard-changes", "feature"])"#,
        r#"require('child_process').execSync('git switch -f main')"#,
        r#"subprocess.run(["git", "checkout", "src/app.py"])"#,
        r#"import os; os.system("git checkout :/README")"#,
    ] {
        assert!(spells_destructive_git(code), "{code}");
    }
    for code in [
        r#"subprocess.run(["git", "checkout", "main"])"#,
        r#"subprocess.run(["git", "checkout", "develop"])"#,
        r#"subprocess.run(["git", "checkout", "-b", "feature", "origin/main"])"#,
        r#"subprocess.run(["git", "switch", "-c", "feature"])"#,
        r#"print("git " + "status")"#,
    ] {
        assert!(!spells_destructive_git(code), "{code}");
    }
}

#[test]
fn a_comment_marker_inside_a_string_does_not_hide_the_command() {
    let source = "import os\nos.system(\"git reset --hard # cleanup\")";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        source
    )));
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Node,
        source
    )));
    let node = "require('child_process').execSync('git clean -fdx // all') /* c */";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Node,
        node
    )));
    let commented = "# os.system(\"git reset --hard\")\nprint('ok')";
    assert!(!spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        commented
    )));
    let block = "/* execSync('git reset --hard') */\nconsole.log('ok')";
    assert!(!spells_destructive_git(&super::without_comments(
        super::super::Language::Node,
        block
    )));
}

#[test]
fn a_command_run_inside_a_template_interpolation_is_read() {
    for node in [
        "console.log(`${require('child_process').execSync('git reset --hard')}`)",
        "const s = `a ${ {k: 1}.k } b ${require('child_process').execSync('git clean -fdx')} c`",
        "const s = `outer ${`inner ${require('child_process').execSync('git reset --hard')}`}`",
    ] {
        assert!(
            spells_destructive_git(&super::without_comments(super::super::Language::Node, node)),
            "{node}"
        );
    }
    let quoted = "console.log(`run git reset --hard ${name} later`) // not run";
    let read = super::without_comments(super::super::Language::Node, quoted);
    assert!(read.contains("+(name)+"), "{read}");
}

#[test]
fn a_clean_reads_only_its_options_before_the_pathspec_separator() {
    for code in [
        r#"os.system("git clean -fd -- -notes")"#,
        r#"os.system("git clean -fd -e -n")"#,
        r#"os.system("git clean -fd --exclude -n")"#,
        r#"os.system("git clean -fden")"#,
        r#"os.system("git clean -fde -n")"#,
        r#"os.system("git clean -fdn --no-dry-run")"#,
        r#"os.system("git clean --dry-run -fd --no-dry-run")"#,
    ] {
        assert!(spells_destructive_git(code), "{code}");
    }
    for code in [
        r#"os.system("git clean -fdn -- notes")"#,
        r#"os.system("git clean -fd -e build -n")"#,
        r#"os.system("git clean -fd --dry-run")"#,
        r#"os.system("git clean --no-dry-run -fdn")"#,
    ] {
        assert!(!spells_destructive_git(code), "{code}");
    }
}

#[test]
fn a_command_run_inside_a_python_f_string_field_is_read() {
    for python in [
        r#"print(f"{__import__('os').system('git reset --hard')}")"#,
        r#"s = f'x {__import__("os").system("git clean -fdx")} y'"#,
        r#"s = rf"{ {'k': 1}['k'] } {__import__('os').system('git reset --hard')}""#,
        "s = f\"\"\"\n{__import__('os').system('git reset --hard')}\n\"\"\"",
        r#"s = f"{__import__('os').system("git reset --hard")}""#,
        r#"print(rf"\{__import__('os').system('git reset --hard')}")"#,
        r#"print(f"\{__import__('os').system('git reset --hard')}")"#,
        r#"print(f"{1:#>{__import__('os').system('git reset --hard')}}")"#,
        r#"print(f"{x:#>{w}} {__import__('os').system('git reset --hard')}")"#,
        r#"print(f"{x!r:#^10} {__import__('os').system('git clean -fdx')}")"#,
    ] {
        assert!(
            spells_destructive_git(&super::without_comments(
                super::super::Language::Python,
                python
            )),
            "{python}"
        );
    }
    for python in [
        r#"print(f"run git reset --hard on {branch} to undo")"#,
        r#"print(f"{{os.system('git reset --hard')}}")"#,
        r#"print(elf"{x}")"#,
    ] {
        assert!(
            !spells_destructive_git(&super::without_comments(
                super::super::Language::Python,
                python
            )),
            "{python}"
        );
    }
}

#[test]
fn each_language_keeps_the_other_languages_comment_markers() {
    // `//` is integer division in Python and `#` starts a private field in
    // Node, so neither may cut the other language's source.
    let python = "n = 7 // 2; import os; os.system(\"git reset --hard\")";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        python
    )));
    let node = "class A { #x = 1 }; require('child_process').execSync('git clean -fdx')";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Node,
        node
    )));
}

#[test]
fn a_marker_inside_a_string_that_spans_lines_does_not_hide_the_command() {
    let python = "s = \"\"\"\n#\"\"\"; import os; os.system(\"git reset --hard\")";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        python
    )));
    let python_single = "s = '''\n#'''; import os; os.system(\"git reset --hard\")";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        python_single
    )));
    let continued = "s = \"a\\\n#\"; import os; os.system(\"git reset --hard\")";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        continued
    )));
    let node = "const s = `\n //`; require('child_process').execSync('git clean -fdx')";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Node,
        node
    )));
    // A closed one-line string does not leak into the next line's comment.
    let commented = "print('ok')\n# os.system(\"git reset --hard\")";
    assert!(!spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        commented
    )));
    // A command written over several lines of one string is still read.
    let script =
        "import subprocess\nsubprocess.run(\"\"\"git fetch\ngit reset --hard\"\"\", shell=True)";
    assert!(spells_destructive_git(&super::without_comments(
        super::super::Language::Python,
        script
    )));
}
