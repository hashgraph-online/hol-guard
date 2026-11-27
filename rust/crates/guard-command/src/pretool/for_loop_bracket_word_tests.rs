//! A quoted loop word holding square brackets, such as the `"[slug]"` of a
//! route directory, is that text and no pattern.

use super::for_loop_unroll::unroll;

#[test]
fn a_quoted_bracket_word_is_written_back_inside_the_body_quotes() {
    for (looped, unrolled) in [
        (
            "for d in items \"[slug]\"; do ls \"app/items/$d\"; done",
            "ls \"app/items/items\"; ls \"app/items/[slug]\"",
        ),
        (
            "for f in \"app/items/[slug]/page.tsx\" README.md; do head -5 \"$f\"; done",
            "head -5 \"app/items/[slug]/page.tsx\"; head -5 \"README.md\"",
        ),
        (
            "for d in '[...slug]' '[id]'; do ls \"app/$d\"; done",
            "ls \"app/[...slug]\"; ls \"app/[id]\"",
        ),
    ] {
        assert_eq!(unroll(looped).as_deref(), Some(unrolled), "{looped}");
    }
}

#[test]
fn a_quoted_bracket_word_the_shell_would_expand_keeps_its_review() {
    for looped in [
        // A bare reference hands the shell the brackets as a pattern again.
        "for d in \"[slug]\"; do ls app/items/$d; done",
        "for d in \"[slug]\" a; do ls \"app/$d\" $d; done",
        // A real pattern beside it needs the body's quotes off.
        "for d in \"[slug]\" src/*.ts; do ls \"$d\"; done",
        // Only the characters of a plain word and the brackets are taken.
        "for d in \"[a*]\"; do ls \"$d\"; done",
        "for d in \"[$HOME]\"; do ls \"$d\"; done",
        "for d in \"[x]/../..\"; do ls \"$d\"; done",
        "for d in \"-[x]\"; do ls \"$d\"; done",
        "for d in \"[x\"; do ls \"$d\"; done",
        // Brackets outside the quotes are still a pattern the shell expands:
        // `.en[v]""` names `.env`.
        "for f in .en[v]\"\"; do cat \"$f\"; done",
        "for f in \"\".en[v]; do cat \"$f\"; done",
        "for f in \"src/\"[ab].ts; do cat \"$f\"; done",
        "for f in \"[x]\"*; do cat \"$f\"; done",
    ] {
        assert_eq!(unroll(looped), None, "{looped}");
    }
}
