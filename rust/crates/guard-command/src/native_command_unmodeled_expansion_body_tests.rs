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
        // A literal index reads a value the shell already holds.
        "test ${PIPESTATUS[0]} -eq 0",
        "echo ${ITEMS[12]}",
        "echo ${ITEMS[@]} ${ITEMS[*]}",
        "echo ${#ITEMS[@]}",
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
        "echo ${ARRAY[$(id)]}",
        "echo ${ARRAY[1+I]}",
        "echo ${ARRAY[]}",
        "echo ${ARRAY[0]/a/b}",
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

#[test]
fn a_literal_subscript_reads_as_the_plain_name() {
    use super::without_literal_subscripts;
    assert_eq!(
        without_literal_subscripts("test ${PIPESTATUS[0]} -eq 0 || true"),
        "test ${PIPESTATUS} -eq 0 || true"
    );
    assert_eq!(
        without_literal_subscripts("echo ${#ITEMS[@]} ${ITEMS[*]} ${X}"),
        "echo ${#ITEMS} ${ITEMS} ${X}"
    );
    for kept in [
        "${ARRAY[$(id)]}",
        "${ARRAY[1+I]}",
        "${ARRAY[0]/a/b}",
        "${OPEN",
    ] {
        assert_eq!(without_literal_subscripts(kept), kept);
    }
}
