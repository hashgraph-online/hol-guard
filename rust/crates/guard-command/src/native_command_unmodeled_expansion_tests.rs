//! An unquoted `${NAME}` names its programs the way `$NAME` does.
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// `$NAME` and `"${NAME}"` model exactly and reach their owner's floor. The
/// unquoted braced spelling of the same value reached an evaluation failure
/// instead, so one way of writing a path blocked an ordinary build outright
/// while the other two let it through.
#[test]
fn an_unquoted_braced_expansion_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "echo ${HOME}",
        "ls ${HOME}/projects",
        "cd ${HOME}/app && npm run build",
        "npm run build --prefix ${PWD}/web",
        "python3 -m pytest tests -k ${CASE}",
        "git clone ${REPO}",
        "docker run --rm ${IMAGE}",
        // A default or an alternate value is still a value, not a command.
        "git log --oneline -5 ${BRANCH:-main}",
        "cargo build ${PROFILE:+--release}",
        // The length and the suffix forms expand to text as well.
        "echo ${#PATH}",
        "tar -czf out.tgz ${DIR%/}",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// Splitting an expansion makes operands, never operators, so a `${...}` can
/// hide a program only by standing where the program stands, by holding a
/// substitution that runs one, or by using one of the brace forms the shell
/// evaluates rather than substitutes. All of them keep the evaluation
/// failure.
#[test]
fn an_expansion_that_could_name_the_program_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "${CMD} --force",
        "${HOME}/bin/deploy --now",
        "FOO=1 ${CMD}",
        "npm run build; ${CMD}",
        // Bash runs the commands inside `${ ...; }` and `${| ...; }`.
        "${ gh pr merge 17 --squash; }",
        "${| gh pr merge 17 --squash; }",
        // A substitution inside the expansion still runs its own program.
        "git log --oneline -5 ${BRANCH:-$(gh pr view --json headRefName -q .headRefName)}",
        "echo ${X:-`gh pr merge 17`}",
        // `@P` expands the value as a prompt string, which substitutes
        // commands, and `printf -v` loads that value without an assignment
        // the text shows.
        "printf -v X '$(gh pr merge 17)'; echo ${X@P}",
        "echo ${X@P}",
        "echo ${X@A}",
        // An offset, a subscript and an indirection evaluate arithmetic,
        // which substitutes commands as well.
        "echo ${HOME:I}",
        "echo ${HOME:1:2}",
        "echo ${ARRAY[I]}",
        "echo ${ARRAY[@]:I}",
        "echo ${!NAME}",
        // An assignment inside the expansion changes shell state, and a
        // `PATH` it sets decides which program a later word finds.
        "echo ${PATH:=/tmp/tools}; ls",
        "echo ${PATH=/tmp/tools}; ls",
        // The replacement word is expanded where it stands.
        "echo ${NAME/a/$(gh pr merge 17)}",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// The expansion changes nothing about the proofs the other uncertainty
/// reasons carry: a redirect to a path the text does not spell, or an
/// interpreter fed the expansion, stays unreadable.
#[test]
fn an_expansion_beside_an_unproven_redirect_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "gh pr list > ${OUT}",
        "sh -c ${SCRIPT}",
        "bash ${SCRIPT}",
        "eval ${CMD}",
        "xargs ${CMD} < list.txt",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// An expansion glued to the characters beside it spells a word the text does
/// not hold: `${X}er` runs docker when `X` is `dock`, and no floor can read a
/// program nothing names. Reading the brace must not become a way to write a
/// program name the text never spells.
#[test]
fn an_expansion_glued_into_a_word_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "for X in dock; do find . -exec ${X}er ps {} +; done",
        "${X}er ps",
        "dock${X} ps",
        "${A}${B} ps",
        "npm run ${TASK}-build",
        // A quote or a backslash joins the word just as a letter does.
        "find . -exec \"dock\"${X} ps {} +",
        "find . -exec ${X}\"er\" ps {} +",
        "find . -exec \"${X}\"er ps {} +",
        "'dock'${X} ps",
        "${X}\\er ps",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}
