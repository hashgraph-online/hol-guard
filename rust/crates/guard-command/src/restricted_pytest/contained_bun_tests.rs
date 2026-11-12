use super::*;
use crate::contained_argv::{bun_test_invocation, bun_test_script_invocation, inline_eval};

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn a_sink_asks_about_a_planned_bun_run_as_the_caller_spelled_it() {
    let bun = "/opt/homebrew/bin/bun";
    for caller in [
        argv(&[bun, "-e", "console.log(1)"]),
        argv(&[bun, "--print", "1"]),
        argv(&[bun, "test"]),
        argv(&[bun, "calc.test.ts"]),
    ] {
        let planned = contained_command(Path::new(bun), &caller[1..]);
        assert_ne!(planned, caller);
        assert_eq!(planned_route_argv(&planned), caller);
    }
    // The resident routes the caller's spelling; the planned argv with the
    // flag in front is not a route it would grant, so a sink that asked about
    // it would refuse every contained Bun run.
    let eval = argv(&[bun, "-e", "1"]);
    assert!(inline_eval(&eval).unwrap());
    assert!(!inline_eval(&contained_command(Path::new(bun), &eval[1..])).unwrap_or(false));
    let test = argv(&[bun, "test"]);
    assert!(bun_test_invocation(&test));
    assert!(!bun_test_invocation(&contained_command(
        Path::new(bun),
        &test[1..]
    )));
    let file = argv(&[bun, "calc.test.ts"]);
    assert!(bun_test_script_invocation(&file));
    assert_eq!(
        planned_route_argv(&contained_command(Path::new(bun), &file[1..])),
        file
    );
}

#[test]
fn any_other_planned_argv_is_asked_about_unchanged() {
    for command in [
        argv(&["/usr/bin/node", "--no-env-file", "-e", "1"]),
        argv(&["/opt/homebrew/bin/bun", "-e", "--no-env-file"]),
        argv(&["/opt/homebrew/bin/bunx", "--no-env-file", "test"]),
        argv(&["/opt/homebrew/bin/bun"]),
        argv(&[]),
    ] {
        assert_eq!(planned_route_argv(&command), command);
    }
}
