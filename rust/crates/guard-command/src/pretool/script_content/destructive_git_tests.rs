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
