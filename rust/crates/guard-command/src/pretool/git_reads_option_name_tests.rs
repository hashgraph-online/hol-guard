//! Which option words a change listing refuses by name.
//!
//! Git resolves an unambiguous prefix of a long option, so the screen that
//! refuses `--textconv`, `--ext-diff` and `--output` has to refuse their
//! abbreviations too, without refusing a word another verb spells in full.

use super::names_refused_option;

/// Git takes any unambiguous prefix of a long option, so a read that
/// disables both helpers in full can turn one back on in an abbreviation
/// the screen never compared against.
#[test]
fn an_abbreviated_helper_names_the_option_it_resolves_to() {
    for word in [
        "--textconv",
        "--textcon",
        "--textc",
        "--ext-diff",
        "--ext-d",
        "--output",
        "--outp",
        "--output=/tmp/changed.patch",
        "-o",
    ] {
        assert!(names_refused_option(word), "{word}");
    }
}

/// `--text` is the comparison verbs' own "treat the file as text", and
/// Git answers an exact spelling with the option that owns it, so reading
/// it as a prefix of `--textconv` would refuse an ordinary read.
#[test]
fn a_word_a_verb_spells_in_full_is_not_an_abbreviation() {
    for word in [
        "--text",
        "--no-textconv",
        "--no-ext-diff",
        "--oneline",
        "--topo-order",
        "--",
        "-O",
        "HEAD",
    ] {
        assert!(!names_refused_option(word), "{word}");
    }
}
