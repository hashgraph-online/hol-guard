use super::split;

fn parts(text: &str) -> Option<(String, String)> {
    split(text)
}

fn pair(checks: &str, publish: &str) -> Option<(String, String)> {
    Some((checks.to_owned(), publish.to_owned()))
}

#[test]
fn splits_before_the_final_run_of_git_steps() {
    assert_eq!(
        parts("npm test && git add -A && git commit -m 'fix: a b' && git push"),
        pair(
            "npm test",
            "git add -A && git commit -m 'fix: a b' && git push"
        )
    );
    assert_eq!(
        parts(concat!(
            "node --input-type=module -e \"import('./src/widget.js').then(m => console.log(m))\" && ",
            "git checkout -b add-guide && git add CONTRIBUTING.md && ",
            "git commit -m \"Add guide\" && git push -u origin add-guide",
        )),
        pair(
            "node --input-type=module -e \"import('./src/widget.js').then(m => console.log(m))\"",
            concat!(
                "git checkout -b add-guide && git add CONTRIBUTING.md && ",
                "git commit -m \"Add guide\" && git push -u origin add-guide",
            ),
        )
    );
    // Git before the checks stays with the checks.
    assert_eq!(
        parts("git status && npm test && git add . && git push origin main"),
        pair(
            "git status && npm test",
            "git add . && git push origin main"
        )
    );
    assert_eq!(
        parts("npm test 2>&1 | tail -3 && git add . && gh pr create --title T --body B"),
        pair(
            "npm test 2>&1 | tail -3",
            "git add . && gh pr create --title T --body B"
        )
    );
    assert_eq!(
        parts("  npm test && git push origin main\n"),
        pair("npm test", "git push origin main")
    );
}

#[test]
fn leaves_other_shapes_whole() {
    for text in [
        // Nothing to split.
        "npm test",
        "git add . && git commit -m x && git push origin main",
        "npm test && git push origin main | tail -1",
        // Only `&&` joins the checks to the Git steps and the steps to each other.
        "npm test || git push origin main",
        "npm test; git push origin main",
        "npm test & git push origin main",
        "npm test && git add . ; git push origin main",
        "npm test && git add . || git push origin main",
        // Shell state the checks change would not reach the Git steps.
        "cd app && npm test && git push origin main",
        "export GIT_DIR=x && npm test && git push origin main",
        "NAME=x && git push origin \"$NAME\"",
        // Unparsed shapes stay whole.
        "npm test && git push origin main 'unterminated",
    ] {
        assert_eq!(parts(text), None, "{text}");
    }
}
