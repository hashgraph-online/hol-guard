//! Credential locations, the words that name them, and the project files whose
//! names only read like one.
//!
//! A name qualifies as a project file only as an operand the command opens or
//! writes, and only by what the whole word shows: a relative path in ordinary
//! path characters whose last component ends in the extension of a file that
//! holds program text. A directory in front of a name is no evidence of what
//! it holds, a variable or prose that merely contains the same characters is
//! not the name, and text a command prints is not a file it opens.

const SENSITIVE_PATHS: [&str; 9] = [
    ".aws/",
    ".ssh/",
    ".docker/",
    ".kube/",
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
];

/// Words that name a credential wherever they appear, including inside prose.
const SENSITIVE_WORDS: [&str; 7] = [
    "credential",
    "secret",
    "password",
    "api_key",
    "api-key",
    "token",
    "private_key",
];

/// Extensions of files that hold program text rather than a credential, so a
/// name such as `tokenizer.rs` or `password-reset-email.tsx` reads as source.
const SOURCE_EXTENSIONS: [&str; 26] = [
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "rs", "go", "py", "rb", "java", "kt", "swift", "c",
    "h", "cc", "cpp", "hpp", "cs", "php", "css", "scss", "less", "vue", "svelte", "md",
];

/// A credential location named anywhere in the value, even inside prose.
pub(super) fn sensitive_path(value: &str) -> bool {
    let value = value.to_ascii_lowercase().replace('\\', "/");
    // A dotted read of a port variable (`process.env.PORT`) names no `.env` file.
    let value = crate::environment_secret_dump::without_node_port_reads(&value);
    SENSITIVE_PATHS.iter().any(|needle| value.contains(needle))
}

pub(super) fn sensitive(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    sensitive_path(value)
        || SENSITIVE_WORDS
            .iter()
            .any(|needle| lowered.contains(needle))
}

/// Commands whose operands are text to print, not files to open. A name
/// among them is data, so only a redirect target can be a file there.
const DATA_COMMANDS: [&str; 2] = ["echo", "printf"];

/// Whether every credential word in `text` comes from a project file the
/// command names, such as `src/tokenizer.ts`. A write to such a file is the
/// edit the agent was asked to make: the name describes what the code is
/// about, and no credential location, variable or prose carries the word.
///
/// The decision is made per token, never by editing the text: a token that
/// carries a credential word has to be a file operand and a source file name
/// itself, so the same characters inside a variable (`$TOKEN.ts`), a path that
/// leaves the workspace (`../src/token.ts`) or a quoted sentence cannot be
/// hidden by another operand that is one. Words the tokens do not account for,
/// such as a comment, keep the review.
pub(super) fn only_source_file_names(text: &str, tokens: &[String], executable: &str) -> bool {
    if !sensitive(text) {
        return true;
    }
    if sensitive_path(text) {
        return false;
    }
    let operands = file_operands(tokens, executable);
    let mut accounted = 0;
    for (token, operand) in tokens.iter().zip(operands) {
        if !sensitive(token) {
            continue;
        }
        if !operand || !source_file_name(token) {
            return false;
        }
        accounted += credential_words(token);
    }
    credential_words(text) <= accounted
}

/// How many credential words `value` holds.
fn credential_words(value: &str) -> usize {
    let lowered = value.to_ascii_lowercase();
    SENSITIVE_WORDS
        .iter()
        .map(|word| lowered.matches(word).count())
        .sum()
}

/// Which tokens stand where the command takes a file: the targets of a
/// redirect, and the arguments that are not options after the program itself,
/// unless the program prints its arguments. Anything before the program is an
/// assignment, and the program is no operand of itself.
fn file_operands(tokens: &[String], executable: &str) -> Vec<bool> {
    let program = tokens.iter().position(|token| {
        let name = token.rsplit(['/', '\\']).next().unwrap_or(token);
        name.eq_ignore_ascii_case(executable)
    });
    let prints = DATA_COMMANDS.contains(&executable);
    let mut ended_options = false;
    let mut redirected = false;
    tokens
        .iter()
        .enumerate()
        .map(|(index, token)| {
            if redirected {
                redirected = false;
                return true;
            }
            if redirect_operator(token) {
                redirected = true;
                return false;
            }
            if program.is_none_or(|program| index <= program) {
                return false;
            }
            if token == "--" {
                ended_options = true;
                return false;
            }
            !prints && (ended_options || !token.starts_with('-'))
        })
        .collect()
}

/// A token that is only a redirect operator, such as `>`, `>>` or `2>`.
fn redirect_operator(token: &str) -> bool {
    token.contains(['<', '>'])
        && token
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '<' | '>' | '&' | '|'))
}

/// Whether the word is a project file this workspace holds: a relative path
/// written in ordinary path characters, naming no credential location, whose
/// last component ends in the extension of a file holding program text.
fn source_file_name(word: &str) -> bool {
    if word.is_empty()
        || word.len() > 256
        || word.starts_with('-')
        || word.starts_with('/')
        || word.starts_with('~')
        || word.contains("..")
        || sensitive_path(word)
        || !word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
    {
        return false;
    }
    source_extension(word.rsplit('/').next().unwrap_or(word))
}

fn source_extension(file: &str) -> bool {
    let Some((stem, extension)) = file.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && SOURCE_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn only(text: &str) -> bool {
        let tokens = words(text);
        let executable = tokens.first().map(String::as_str).unwrap_or_default();
        only_source_file_names(text, &tokens, executable)
    }

    #[test]
    fn a_command_naming_no_credential_word_needs_no_name() {
        assert!(only("cp src/index.ts dist/index.ts"));
    }

    #[test]
    fn source_files_whose_names_read_like_credentials_are_project_files() {
        assert!(only("touch src/auth/token-store.ts"));
        assert!(only("cp src/password-reset-email.tsx dist/"));
        assert!(only("sed -i s/a/b/ crates/parser/src/tokenizer.rs"));
        assert!(only("cp ui/design-tokens.scss build/"));
        assert!(only("mv docs/credentials.md docs/auth.md"));
        assert!(only("cp src/tokens.css src/api-key-form.tsx build/"));
    }

    #[test]
    fn a_directory_is_no_evidence_of_what_a_file_holds() {
        assert!(!only("cp app/secrets/readme build/"));
        assert!(!only("touch app/secrets/password"));
        assert!(!only("cp config/credentials.json backup/credentials.json"));
        assert!(!only("cp src/token/store build/"));
        assert!(!only("cp keys/private_key.pem dist/"));
        assert!(!only("cat secrets/api_token > backup/x"));
    }

    #[test]
    fn a_directory_that_only_leads_to_a_source_file_is_still_a_project_file() {
        assert!(only("touch app/secrets/password-form.tsx"));
    }

    #[test]
    fn credential_locations_keep_the_word() {
        assert!(!only("cp src/token.ts ~/.ssh/token.ts"));
        assert!(!only("cp src/token.ts ../../.aws/credentials"));
        assert!(!only("echo API_KEY=x > .env"));
        assert!(!only("cp src/token.ts /etc/app/token.ts"));
    }

    #[test]
    fn a_path_that_leaves_the_workspace_keeps_the_word() {
        assert!(!only("cp src/token-store.ts ../src/token-store.ts"));
        assert!(!only("cp ../token.ts build/"));
    }

    #[test]
    fn a_variable_or_literal_keeps_the_word() {
        assert!(!only("echo $GITHUB_TOKEN > src/token.ts"));
        assert!(!only("echo secret123 > src/token.ts"));
        assert!(!only("cp src/token.ts build/ --password=hunter2"));
    }

    #[test]
    fn a_name_inside_a_variable_is_not_the_name() {
        assert!(!only("echo $GITHUB_TOKEN.ts > GITHUB_TOKEN.ts"));
        assert!(!only("cp $TOKEN.ts build/"));
        assert!(!only("cp src/$TOKEN.ts build/"));
        assert!(!only("printf %s $API_TOKEN/a > API_TOKEN/a"));
        assert!(!only("touch $token.ts token.ts"));
    }

    #[test]
    fn the_name_of_a_file_a_command_prints_is_text_not_a_file() {
        assert!(!only("echo src/token.ts"));
        assert!(!only("echo credential/rotation > notes.txt"));
        assert!(!only("printf %s src/token.ts"));
    }

    #[test]
    fn the_target_of_a_redirect_is_a_file_even_for_a_command_that_prints() {
        assert!(only("echo hello > src/token.ts"));
        assert!(only("printf done >> src/password-form.tsx"));
        assert!(!only("echo hello > src/token"));
    }

    #[test]
    fn a_credential_word_beside_a_source_file_keeps_the_word() {
        assert!(!only("cp src/token.ts build/ --note=token"));
        assert!(!only("cp src/token.ts build/ # rotate the token"));
        assert!(!only("cp src/token.ts build/token-notes.txt"));
    }

    #[test]
    fn prose_keeps_the_word() {
        assert!(!only_source_file_names(
            "gh pr comment 1 --body \"credential rotation\" > src/token.ts",
            &[
                "gh".to_owned(),
                "pr".to_owned(),
                "comment".to_owned(),
                "1".to_owned(),
                "--body".to_owned(),
                "credential rotation".to_owned(),
                ">".to_owned(),
                "src/token.ts".to_owned(),
            ],
            "gh",
        ));
    }

    #[test]
    fn a_bare_name_without_a_directory_or_source_extension_keeps_the_word() {
        assert!(!only("cp tokens.json build/tokens.json.bak"));
        assert!(!only("touch secret.txt"));
        assert!(!only("cp mytoken build/"));
    }

    #[test]
    fn a_glob_or_substitution_keeps_the_word() {
        assert!(!only("cp src/*token* build/"));
        assert!(!only("cp src/$NAME/token.ts build/"));
    }
}
