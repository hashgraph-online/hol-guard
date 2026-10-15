//! Settings that choose where a toolchain finds its modules or its own
//! install (`PYTHONPATH=src pytest`, `JAVA_HOME=/opt/jdk ./gradlew build`).
//! They load code, so they never pass as inert. In front of a program that
//! already runs the workspace's code with that same toolchain, a literal path
//! only picks which of that code runs, so a human can review the command. In
//! front of any other program (`PYTHONPATH=. aws s3 ls`) it would hand an
//! unrelated tool foreign modules, and the command keeps failing closed.
//! Loader, shell and wrapper hooks (`LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`,
//! `RUSTC_WRAPPER`) have no reviewable form here.

/// Each setting and the programs it may prefix.
const SEARCH_PATH_SETTINGS: [(&str, &[&str]); 3] = [
    (
        "JAVA_HOME",
        &["gradle", "gradlew", "java", "javac", "mvn", "mvnw", "sbt"],
    ),
    ("NODE_PATH", &["bun", "node", "npm", "npx", "pnpm", "yarn"]),
    ("PYTHONPATH", &["py.test", "pytest", "python", "python3"]),
];

const MAX_VALUE_CHARS: usize = 512;

/// The programs `name` may prefix when `value` is a plain path list, or
/// `None` when the setting has no reviewable form.
pub(super) fn programs(name: &str, value: &str) -> Option<&'static [&'static str]> {
    let (_, programs) = SEARCH_PATH_SETTINGS
        .iter()
        .find(|(known, _)| *known == name)?;
    (value.len() <= MAX_VALUE_CHARS
        && value.split(':').all(|entry| {
            !entry.is_empty()
                && !entry.starts_with('-')
                && entry.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "/._-+@".contains(character)
                })
        }))
    .then_some(*programs)
}

/// Whether `executable` is in every list of `required`.
pub(super) fn admits(required: &[&'static [&'static str]], executable: &str) -> bool {
    let name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    let name = match name.strip_prefix("python3.") {
        Some(minor) if !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit()) => {
            "python3"
        }
        _ => name,
    };
    required.iter().all(|programs| programs.contains(&name))
}

/// Record a setting that is not inert for the reviewed projection; `None`
/// when no program may run with it unreviewed by the extension controls.
pub(super) fn review(
    setting: Option<&mut Option<String>>,
    required: &mut Vec<&'static [&'static str]>,
    name: &str,
    value: &str,
    context: super::PathContext<'_>,
) -> Option<()> {
    let first = setting?;
    if !super::reviewable_assignment(name, value, context) {
        required.push(programs(name, value)?);
    }
    first.get_or_insert_with(|| name.to_owned());
    Some(())
}
