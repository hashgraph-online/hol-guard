//! A scheduling prefix names its programs the way the bare command does.
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// `timeout 30 npm test` models exactly. The same clock written with its
/// kill-after option left a wrapper the parser does not model, and so did
/// every `nice` and `stdbuf` spelling, which turned an ordinary long build
/// into an outright block with no approval left to give it.
#[test]
fn a_scheduling_prefix_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nice cargo build",
        "nice -n 10 cargo build",
        "nice -n 19 npm run build",
        "stdbuf -oL npm test",
        "stdbuf -o0 -e0 cargo test",
        "setsid npm run dev",
        "timeout -k 5 30 npm test",
        "timeout -s KILL 30 cargo build",
        "timeout --preserve-status 5m npm run build",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// The prefix opens no file, so the only thing it can stand in front of is an
/// interpreter, and that interpreter is a word in the same text. A prefix that
/// changes who runs the program, or what it inherits, is not one of these.
#[test]
fn a_prefix_hiding_an_interpreter_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nice -n 10 sh -c 'npm run build'",
        "timeout -k 5 30 bash -lc 'pwd'",
        "stdbuf -oL python3 deploy.py",
        "setsid node server.js",
        "nice -n 10 xargs rm -f",
        "sudo -E npm install -g pnpm",
        "sh -c 'npm run build'",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
    // An `env` carrying a live assignment reaches the installer's own owner,
    // which reviews it. Reading the prefixes must not turn that into an allow.
    assert_eq!(decision(&controls, "env FOO=1 npm run build").0, "review");
}

/// A launcher runs the program it is handed directly, so a script file behind
/// one is a file whose own text names the programs it runs. Nothing here has
/// read it, and `nice ./deploy.sh` must not be a way to run it unread. The
/// clock is spelled with its kill-after option because the parser models
/// `timeout 30 ./run.sh` on its own, so that spelling never reaches here.
#[test]
fn a_script_file_behind_a_prefix_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nice ./deploy.sh",
        "nice -n 10 ../tools/build.sh",
        "nohup ./scripts/release.sh",
        "timeout -k 5 30 ./run.sh",
        "setsid /usr/local/bin/deploy",
        "stdbuf -oL release.py",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// The launcher's own options are counted through its documented grammar. An
/// option that grammar does not cover, or a duration that is not one, leaves
/// the program somewhere this scan cannot point to, so the failure stays.
#[test]
fn an_uncounted_option_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nice --cpu-shares 512 cargo build",
        "nice -q cargo build",
        "timeout --signal-name TERM 30 npm test",
        "timeout thirty npm test",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// Reading the prefix does not read the command past it: a destructive program
/// the text names still reaches its own owner, whose floor blocks. Prefixing
/// `nice` must not be a way around that.
#[test]
fn a_prefix_does_not_soften_the_program_it_names() {
    let controls = controls(github("enabled", None), false);
    for command in ["nice -n 10 rm -rf /", "stdbuf -oL shred ~/.ssh/id_ed25519"] {
        assert_eq!(decision(&controls, command).0, "block", "{command}");
    }
}

/// `nohup` is a shell prefix and a launcher at once. Read only as a prefix it
/// is stepped over, which hands the script behind it to the scan as the
/// program itself and loses the file nobody read; read as a launcher it keeps
/// its own grammar, so the script behind it still refuses.
#[test]
fn a_launcher_that_is_also_a_shell_prefix_keeps_its_grammar() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nohup ./deploy.sh",
        "nohup ../tools/build.sh",
        "nohup release.py",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
    let (action, code) = decision(&controls, "nohup cargo build");
    assert_ne!(code, FAILED, "nohup cargo build");
    assert_eq!(action, "review", "nohup cargo build: {code}");
}
