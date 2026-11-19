//! A bounded hook bridge handler carries its Python in a config field, not as
//! an isolated client command: `<runtime> bounded-hook-bridge '<config>'`.
//! The runtime starts that interpreter to recover the daemon, so a config
//! naming another install's Python reaches a client the resident no longer
//! serves, exactly as a foreign isolated client does.

use std::sync::OnceLock;

use regex::Regex;

use super::{is_other_interpreter, posix};

const COMMAND: &str = "bounded-hook-bridge";

/// Whether `command` runs the bounded bridge for this Guard home with a
/// config whose `python_executable` is not the current interpreter.
pub(super) fn names_foreign_interpreter(command: &str, current: Option<&str>, home: &str) -> bool {
    if !command.contains(COMMAND) || !posix(command).contains(home) {
        return false;
    }
    static FIELD: OnceLock<Regex> = OnceLock::new();
    let field = FIELD.get_or_init(|| {
        Regex::new(r#""python_executable"\s*:\s*("(?:[^"\\]|\\.)*")"#)
            .expect("bounded config interpreter pattern")
    });
    field.captures_iter(command).any(|found| {
        found
            .get(1)
            .and_then(|quoted| serde_json::from_str::<String>(quoted.as_str()).ok())
            .is_some_and(|python| is_other_interpreter(&python, current))
    })
}

#[cfg(test)]
mod tests {
    use super::names_foreign_interpreter;

    fn command(python: &str) -> String {
        format!(
            "/g/native-runtime/hol-guard-runtime bounded-hook-bridge '{{\"guard_home\":\"/g\",\"python_executable\":\"{python}\"}}'"
        )
    }

    #[test]
    fn another_installs_python_in_the_config_is_foreign() {
        let current = Some("/venv/bin/python");
        assert!(!names_foreign_interpreter(
            &command("/venv/bin/python"),
            current,
            "/g"
        ));
        assert!(names_foreign_interpreter(
            &command("/other/bin/python"),
            current,
            "/g"
        ));
        assert!(!names_foreign_interpreter(
            &command("/other/bin/python"),
            current,
            "/elsewhere"
        ));
        assert!(!names_foreign_interpreter(
            &command("python"),
            current,
            "/g"
        ));
        let user_hook =
            "/usr/bin/tool '{\"python_executable\":\"/other/bin/python\",\"g\":\"/g\"}'";
        assert!(!names_foreign_interpreter(user_hook, current, "/g"));
    }
}
