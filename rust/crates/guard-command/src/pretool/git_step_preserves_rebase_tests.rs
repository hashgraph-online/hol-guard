use super::{config_stable_step, preserves_configuration};

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_rebase_that_runs_no_command_keeps_the_configuration() {
    for text in [
        "origin/main",
        "-q origin/main",
        "--onto main feature~2 feature",
        "--abort",
        "--quit",
        "--autostash -q origin/main",
        "-X theirs origin/main",
    ] {
        assert!(config_stable_step("rebase", &words(text)), "{text}");
    }
    assert!(preserves_configuration(&words("rebase -q origin/main")));
}

#[test]
fn a_rebase_that_can_run_commands_keeps_the_review() {
    for text in [
        "--exec make origin/main",
        "--exec=make origin/main",
        "--exe=make origin/main",
        "-x make origin/main",
        "-xmake origin/main",
        "-qx make origin/main",
        "-i origin/main",
        "-qi origin/main",
        "--interactive origin/main",
        "--inter origin/main",
        "--edit-todo",
        "--continue",
        "--cont",
        "--skip",
        "--ski",
        "--strategy=ours origin/main",
        "--strat=ours origin/main",
        "-s ours origin/main",
        "-qs ours origin/main",
    ] {
        assert!(!config_stable_step("rebase", &words(text)), "{text}");
    }
    assert!(!preserves_configuration(&words("rebase -i origin/main")));
}
