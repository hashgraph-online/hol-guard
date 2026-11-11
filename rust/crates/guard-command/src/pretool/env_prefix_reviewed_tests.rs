//! Which removed settings count as data the read-only launchers drop.
//!
//! A read-only profile's launcher filters the environment through the
//! restricted allowlist, so a setting it drops never reaches the run and the
//! profile chosen for the command without it is the profile for what runs.
//! The screen below decides that, and a shell applies neither field splitting
//! nor pathname expansion to an assignment's value, so a pattern in one is
//! the text the program would have read and nothing more.

#[cfg(unix)]
use super::plain_data;

/// `DEBUG=app:*` is how the `debug` package's own namespaces are written, and
/// the five characters are what the program reads. Refusing them left the
/// contained verdict for `npx jest --ci` downgraded to a review the caller
/// could not clear, so the pattern characters are data here.
#[cfg(unix)]
#[test]
fn a_pattern_in_a_value_is_data_the_launcher_drops() {
    for value in [
        "app:*",
        "app:*,db:*",
        "app:{http,db}",
        "app:[ab]",
        "app:?",
        "*",
        "app:*,-app:verbose",
    ] {
        assert!(plain_data("DEBUG", value), "DEBUG={value}");
    }
}

/// Everything a shell would act on, or that would reach the run as more than
/// text, stays outside the screen, so the command keeps its review.
#[cfg(unix)]
#[test]
fn a_value_the_shell_or_the_run_would_act_on_is_not_data() {
    for value in [
        "$(id)", "`id`", "$HOME", "${HOME}", "a;id", "a&&id", "a|id", "a>out", "a<in", "a b",
        "a'b", "a\"b", "a\\*", "~/app", "a!b", "(id)",
    ] {
        assert!(!plain_data("DEBUG", value), "DEBUG={value}");
    }
}

/// The names the screen refuses whatever their value holds: a module search
/// path, the temporary directory the profile sets itself, and a credential
/// route. A pattern in one of those values changes nothing about that.
#[cfg(unix)]
#[test]
fn a_name_the_screen_refuses_stays_refused_with_a_pattern() {
    for name in ["NODE_PATH", "TMPDIR", "TMP", "TEMP"] {
        assert!(!plain_data(name, "app:*"), "{name}");
    }
}

/// An option leader still fails the screen, and the value stays bounded.
#[cfg(unix)]
#[test]
fn an_option_leader_or_an_overlong_value_is_not_data() {
    assert!(!plain_data("DEBUG", "-app:*"));
    assert!(!plain_data("DEBUG", &"a".repeat(super::MAX_DATA_CHARS + 1)));
}

/// A port number a run may carry is data the contained launcher drops; any
/// other value under an endpoint-steering name decides whose server answers,
/// so it keeps its review however plain its characters look.
#[cfg(unix)]
#[test]
fn only_a_real_port_number_is_data_under_an_endpoint_name() {
    assert!(plain_data("PORT", "3000"));
    assert!(plain_data("POSTGRES_PORT", "55477"));
    assert!(!plain_data("PORT", "99999"));
    assert!(!plain_data("PORT", "db.example.test:5432"));
    assert!(!plain_data("PGHOST", "db.example.test"));
    assert!(!plain_data("NPM_CONFIG_REGISTRY", "https:"));
}
