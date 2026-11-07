//! Whether a package-manager launch turns `package.json` lifecycle scripts off.

/// Mirrors how npm's option parser settles a boolean flag: the last spelling
/// wins, and a bare `true`/`false` after the flag is its value. Any other
/// `=` value, or `--no-ignore-scripts`, leaves scripts enabled.
pub fn lifecycle_scripts_disabled(tokens: &[String]) -> bool {
    let mut disabled = false;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            break;
        }
        if token == "--ignore-scripts" {
            match tokens.get(index + 1).map(String::as_str) {
                Some("false") => {
                    disabled = false;
                    index += 1;
                }
                Some("true") => {
                    disabled = true;
                    index += 1;
                }
                _ => disabled = true,
            }
        } else if token == "--ignore-scripts=true" {
            disabled = true;
        } else if token.starts_with("--ignore-scripts=") || token.starts_with("--no-ignore-scripts")
        {
            disabled = false;
        }
        index += 1;
    }
    disabled
}
