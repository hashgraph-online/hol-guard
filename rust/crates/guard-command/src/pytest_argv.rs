//! The one reading of a Python interpreter's argv that decides whether the
//! command runs pytest as a module.
//!
//! `restricted_pytest` is a Unix module, and the Windows read-only planner in
//! `guard-runtime` asks the same question about the same argv. Keeping the
//! reading here lets both read it rather than each carrying a copy that can
//! drift apart on the platform the other does not compile for.

/// `_python_args_target_pytest` (:171-194).
///
/// Options end at the first argument that is not one: in `python evil.py -m
/// pytest` the interpreter runs `evil.py`, and the `-m` after it belongs to
/// that script. A short option that takes a value swallows the rest of its
/// cluster, so the `c` in `-Ic` starts a `-c` command exactly as a bare `-c`
/// does, and `-W` or `-X` takes the next argument when nothing follows it in
/// the cluster.
pub fn python_args_target_pytest(args: &[String]) -> bool {
    let mut index = 0usize;
    while index < args.len() {
        let item = args[index].as_str();
        // `-` reads the program from standard input; anything else without a
        // leading dash is the script to run, and the options ended before it.
        if item == "--" || item == "-" || !item.starts_with('-') {
            return false;
        }
        if let Some(long) = item.strip_prefix("--") {
            if long == "command" || long.starts_with("command=") {
                return false;
            }
            index += if long == "check-hash-based-pycs" {
                2
            } else {
                1
            };
            continue;
        }
        let mut characters = item[1..].chars();
        let mut consumed = 1usize;
        while let Some(character) = characters.next() {
            let rest = characters.as_str();
            match character {
                'c' => return false,
                'm' => {
                    let module = if rest.is_empty() {
                        args.get(index + 1).map(String::as_str)
                    } else {
                        Some(rest)
                    };
                    return module.is_some_and(|module| module.split('.').next() == Some("pytest"));
                }
                'W' | 'X' => {
                    if rest.is_empty() {
                        consumed = 2;
                    }
                    break;
                }
                _ => continue,
            }
        }
        index += consumed;
    }
    false
}
