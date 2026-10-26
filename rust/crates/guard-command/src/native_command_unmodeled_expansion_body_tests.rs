use super::expansions_are_inert;

/// Forms that substitute a value and nothing else.
#[test]
fn value_forms_are_inert() {
    for text in [
        "echo ${NAME}",
        "echo ${NAME:-fallback}",
        "echo ${NAME:+set}",
        "echo ${NAME:?missing}",
        "echo ${NAME-fallback}",
        "echo ${NAME+set}",
        "echo ${#NAME}",
        "echo ${NAME#prefix}",
        "echo ${NAME##*/}",
        "echo ${NAME%suffix}",
        "echo ${NAME%%.*}",
        "ls ${DIR}/src ${OTHER}",
        "echo plain",
    ] {
        assert!(expansions_are_inert(text), "{text}");
    }
}

/// Forms whose bodies the shell evaluates, or that change shell state.
#[test]
fn evaluating_forms_are_not_inert() {
    for text in [
        // `@P` expands the value as a prompt, which substitutes commands.
        "echo ${X@P}",
        "echo ${X@A}",
        // Offsets and subscripts are arithmetic contexts.
        "echo ${HOME:I}",
        "echo ${NAME:1:2}",
        "echo ${ARRAY[INDEX]}",
        "echo ${ARRAY[@]:I}",
        // Indirection names a second variable.
        "echo ${!NAME}",
        // Assignment changes shell state, PATH included.
        "echo ${PATH:=/tmp/tools}",
        "echo ${PATH=/tmp/tools}",
        // Replacement expands its replacement word.
        "echo ${NAME/a/b}",
        // A word that still holds an expansion runs it there.
        "echo ${NAME:-$(id)}",
        "echo ${NAME:-`id`}",
        // Bash's command form, and an unterminated brace.
        "echo ${ id; }",
        "echo ${NAME",
        // A later expansion is reached too.
        "echo ${NAME} ${X@P}",
    ] {
        assert!(!expansions_are_inert(text), "{text}");
    }
}
