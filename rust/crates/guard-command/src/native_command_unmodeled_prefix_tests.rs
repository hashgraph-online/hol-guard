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
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
    // Without a prefix, a shell carrying its whole script hides nothing: the
    // script's own words name the program, which reaches its own owner.
    assert_eq!(decision(&controls, "sh -c 'npm run build'").0, "review");
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

/// `exec npm test` runs what `npm test` runs: the shell replaces itself with
/// the program this text already names, as this user and in this directory.
/// The parser reads `exec` as a nested executor, so every one of these reached
/// an evaluation failure and blocked outright, with no approval left to give
/// it.
#[test]
fn exec_replacing_the_shell_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "exec npm test",
        "exec npm run build",
        "exec cargo build",
        "exec make -j4",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// An `exec` leaves the program unknown as soon as it carries an option of its
/// own: `-a` renames the process, `-c` empties its environment and `-l` makes
/// it a login shell. A bare `exec` names no program at all, and an interpreter
/// behind one reads a file this scan never opened.
#[test]
fn an_exec_without_a_named_program_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "exec",
        "exec -a worker npm test",
        "exec -c npm test",
        "exec -l bash",
        "exec bash -lc 'npm run build'",
        "exec python3 deploy.py",
        "exec node server.js",
        "exec xargs rm -f",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// `exec env CI=1 npm test` runs what `exec npm test` runs, with one name
/// decided in front of it. The parser already reads the bare `env CI=1 npm
/// test` that way, and the contained-launcher sink peels the same prefix;
/// only this scan still read the word `env` as a program it never saw, so an
/// ordinary test run behind a launcher blocked outright while the same run
/// without the names went through. `exec env npm test` decides no name at
/// all, so it is that same run spelled twice over and settles where `npm
/// test` settles. A local script behind the same prefix lands here too: the
/// projection hands the scan `./deploy.sh`, which this repository reviews on
/// its own terms, so the launcher stops being the reason the command is
/// refused.
#[test]
fn a_transparent_env_behind_a_launcher_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "exec env CI=1 npm test",
        "exec env npm test",
        "exec env CI=1 FOO=bar cargo build",
        "exec env CI=1 ./deploy.sh",
        "exec /usr/bin/env CI=1 npm test",
        "exec env -u LANG npm test",
        "stdbuf -oL env CI=1 cargo build",
        "nice -n 10 env RUST_LOG=info cargo build",
        "timeout -k 5 30 env CI=1 npm test",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
    // A name that loads code is not inert, so the bare spelling earns its
    // review from the reviewed environment projection rather than from this
    // scan. Removing `NODE_OPTIONS` is a setting that projection reads.
    let (bare, code) = decision(&controls, "env -u NODE_OPTIONS npm test");
    assert_eq!(bare, "review", "env -u NODE_OPTIONS npm test: {code}");
    // Whatever floor the bare spelling settles on, putting a launcher in
    // front of it never buys the command something the bare spelling lacks.
    // `env_prefix_projection::strip_prefixes` reads past an option-less
    // `exec` in front of an `env` wrapper, so the launcher no longer leaves
    // the command unprojected and the two spellings reach the same floor.
    // `-u PATH` is the shape the projection refuses outright, so they agree
    // there too. The ladder is what this asserts either way: it holds
    // whether or not the projection reads a given spelling.
    for command in ["env -u NODE_OPTIONS npm test", "env -u PATH npm test"] {
        let (bare, _) = decision(&controls, command);
        let (behind, _) = decision(&controls, &format!("exec {command}"));
        assert!(
            strictness(&behind) >= strictness(&bare),
            "exec {command}: {behind} is weaker than {bare}"
        );
    }
}

/// How strict a minimum action is, so a launcher can be shown never to
/// soften one. An action this ladder does not name is treated as the
/// strictest rather than as a pass.
fn strictness(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}

/// An `env` that is anything other than a list of ordinary names keeps the
/// failure. `-i` empties the environment the program starts with, `-S`
/// carries a whole shell line in its own value, `-C` moves the directory, and
/// a bare `env prog` is the spelling the extension floors key on. Walking the
/// names also does not read past the program they are decided for: an
/// interpreter or a script file behind them is still one nothing here opened.
///
/// A name the prefix writes that steers lookup, loading, configuration,
/// credentials, the trust anchor or the endpoint keeps the failure too. The
/// walk drops the names it read, and nothing further along this path asks
/// what they were, so letting one through would hand `pytest` its owner floor
/// while the parser still reviews the same hook written without a launcher.
#[test]
fn an_env_that_is_not_a_name_list_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "exec env -i npm test",
        "exec env -S'sh -c id'",
        "exec env -C /tmp npm test",
        "exec env CI=1 bash -lc 'npm run build'",
        "stdbuf -oL env CI=1 python3 deploy.py",
        "nice -n 10 env CI=1 xargs rm -f",
        "exec env LD_PRELOAD=/tmp/x.so pytest -q",
        "exec env NODE_OPTIONS=--require=/tmp/hook.js npm test",
        "exec env PATH=. npm test",
        "exec env GIT_SSH_COMMAND=/tmp/ssh git fetch",
        "nice -n 10 env PYTHONPATH=/tmp pytest -q",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// A launcher in front of a written loader hook never buys the command what
/// the hook written on its own is refused. The names an `env` prefix decides
/// are dropped by the walk, so the only thing that can keep them read is
/// refusing the walk itself.
#[test]
fn a_written_loader_hook_is_no_weaker_behind_a_launcher() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "env LD_PRELOAD=/tmp/x.so pytest -q",
        "env NODE_OPTIONS=--require=/tmp/hook.js npm test",
        "env PATH=. npm test",
    ] {
        let (bare, _) = decision(&controls, command);
        let (behind, _) = decision(&controls, &format!("exec {command}"));
        assert!(
            strictness(&behind) >= strictness(&bare),
            "exec {command}: {behind} is weaker than {bare}"
        );
    }
}
