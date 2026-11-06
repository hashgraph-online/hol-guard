use super::{glob_can_select_sensitive_path, literal_glob_names_sensitive_path};

/// Both forms read the glob's own text the same way. They part over the
/// wider question a path operand answers: whether some longer string the
/// glob could match would hold a credential marker. Every regex that
/// joins two words with `.*` could, so a pattern is read on its text
/// alone.
#[test]
fn a_regex_wildcard_names_no_credential_on_its_own_text() {
    for selecting in [".env*", ".ssh/*", "*secret*", "id_*", "*.pem"] {
        assert!(literal_glob_names_sensitive_path(selecting), "{selecting}");
        assert!(glob_can_select_sensitive_path(selecting), "{selecting}");
    }
    // A credential marker joined to a second word with `.*` is still a
    // regex. A path operand spelled the same way is refused, because it
    // is a glob some credential file could sit under.
    for regex in [
        "cookie.*name",
        "a.*b",
        "auth_token.*=",
        "delegate.*=>",
        "auth.*provider",
        "token.*expired",
        "credentials.*load",
        "auth.*header",
    ] {
        assert!(!literal_glob_names_sensitive_path(regex), "{regex}");
    }
    for operand in ["auth.*provider", "token.*expired", "credentials.*load"] {
        assert!(glob_can_select_sensitive_path(operand), "{operand}");
    }
}

/// A brace with nothing to close it expands to nothing, so the word is
/// the text it was written as. Searches carry regex braces constantly --
/// `json({ error:` and `\d{2` among them -- and reading one as a glob no
/// proof could expand sent every such search to review.
#[test]
fn an_unbalanced_brace_is_literal_text() {
    for literal in ["json({ error: 'not found', path", "a{b", ".en{v", "\\d{2"] {
        assert!(!glob_can_select_sensitive_path(literal), "{literal}");
        assert!(!literal_glob_names_sensitive_path(literal), "{literal}");
    }
    // A brace that does close still opens its alternatives, wherever the
    // unbalanced one sits.
    for selecting in ["a{b c{.env,x}", "{.env,x} y{z"] {
        assert!(glob_can_select_sensitive_path(selecting), "{selecting}");
    }
    // A path operand is still refused on the wider question: `{.env`
    // holds the marker's own text, and another proof can clear it.
    assert!(glob_can_select_sensitive_path("{.env"));
    assert!(!literal_glob_names_sensitive_path("{.env"));
}

/// Bash closes a `}` against the nearest `{` to its left, so an opening
/// brace with nothing to close it is skipped and the pair after it still
/// expands. `{x/{.gnupg,b}` reaches the tool as `{x/.gnupg` and `{x/b`, and
/// the first names the credential directory outright.
#[test]
fn an_unbalanced_brace_does_not_hide_the_pair_behind_it() {
    for selecting in [
        "{x/{.gnupg,b}",
        "{a/{.ssh,b}/id_rsa",
        "x{/{.aws,b}/credentials",
    ] {
        assert!(glob_can_select_sensitive_path(selecting), "{selecting}");
        assert!(literal_glob_names_sensitive_path(selecting), "{selecting}");
    }
}

#[test]
fn brace_sequences_still_select_sensitive_names() {
    // Git's brace suffixes and Go template fields are one literal alternative.
    for literal in [
        "head^{commit}",
        "4dc51cdaa1^{tree}",
        "head@{0}",
        "@{u}",
        "{{.server.version}}",
    ] {
        assert!(!glob_can_select_sensitive_path(literal), "{literal}");
    }
    // Bash expands a `..` sequence: `.en{v..v}` is `.env`.
    for selecting in [
        ".en{v..v}",
        ".npmr{c..c}",
        "config/.en{v..v}",
        ".en{v..v..1}",
        "{.env}",
        "{{.env}}",
        "{.env,readme.md}",
    ] {
        assert!(glob_can_select_sensitive_path(selecting), "{selecting}");
    }
}
