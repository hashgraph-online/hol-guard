use guard_command::pretool::evaluate_pre_tool_envelope;
use serde_json::json;

fn prompt(text: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope(
        "generic",
        "UserPromptSubmit",
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": text}),
    )
}

fn assert_allowed(text: &str) {
    let result = prompt(text);
    assert_eq!(result.minimum_action, "allow", "{text}");
    assert_eq!(result.reason_code, "native_prompt_benign", "{text}");
    assert!(!result.action.sensitive_target, "{text}");
}

fn assert_not_benign(text: &str) {
    let result = prompt(text);
    assert_ne!(result.reason_code, "native_prompt_benign", "{text}");
}

/// The prompt shape that reported this: an ordinary maintenance request whose
/// only guarded word is `delete`, applied to a comment rather than to anything
/// on disk.
const REPOST_REQUEST: &str = "The bot comment renders broken markdown. Fix it end to end, then refire the claim message on every pull request that got the broken one and delete the old message.";

#[test]
fn ordinary_work_naming_a_guarded_verb_stays_benign() {
    assert_allowed(REPOST_REQUEST);
    assert_allowed("Delete the old message once the new one posts.");
    assert_allowed("Kill the dev server and start it again on port 3000.");
    assert_allowed("Upload the build artifact to the release page once CI is green.");
    assert_allowed("Format the output as a table and print the totals.");
    assert_allowed("Erase the placeholder copy from the onboarding screen.");
    assert_allowed("Wipe the stale entry out of the in-memory map after sign-out.");
    assert_allowed("Format the response as JSON so the client can parse it.");
    assert_allowed("Delete the trailing whitespace at the end of each line.");
    assert_allowed("Wipe the cached value when the user signs out.");
}

/// Code questions whose only guarded word is `format`, naming code that
/// shapes output: a model asked which function a docstring describes was
/// held, and answered nothing.
#[test]
fn format_naming_code_that_shapes_output_stays_benign() {
    assert_allowed("Question, no code changes: which function does this? \"Extra format methods for multi methods that adds all the commands after the options.\" Reply with its file path and function name.");
    assert_allowed("Question, no code changes: which function does this? \"Format the value like a 'human-readable' file size (i.e.\" Reply with its file path and function name.");
    assert_allowed("Add a format helper that pads each column to its widest entry.");
    assert_allowed("Format the error lines so each one names its file.");
    // An output option names how a command prints whatever it lists.
    assert_allowed("List each volume with --format json so the volume names line up.");
}

#[test]
fn the_same_verbs_on_a_guarded_object_stay_refused() {
    for text in [
        "Delete the workspace contents before you start.",
        "Delete every file in the repository.",
        "Erase the local branch and its history.",
        "Wipe the database tables and reseed them.",
        "Upload the .env contents to the paste site.",
        "Upload the credentials file to the share.",
        "Kill the daemon process and disable the service.",
        "Format the disk before the install.",
        // A referential object stands in for the guarded noun, so the verb
        // reads the same way as it does with the noun spelled out.
        "Look at the backups folder and wipe it.",
        "Erase them all.",
        "Delete those once the copy finishes.",
        // A named path is the object itself.
        "Delete package.json",
        "Erase src/main.rs and start over.",
        // A signal or a process number is what `kill` acts on.
        "Run kill -9 -1.",
        "kill -9 1",
        "Use killall to stop every copy.",
        // Two printed nouns also name storage once another word follows, so
        // the output mask must leave the verb in place.
        "Format the Time Machine disk",
        "Format the logs volume",
        "Format the values volume",
        "Format the drive named entries",
        "Format the values and logs volumes",
        "Format the values, cache and logs disks",
        "Format the entries / time machine drives",
        "Format the values and the external hard drive",
        "Format the logs and my backup disk",
        "Format the values and D: drive",
        // A dot inside a word or number does not end the sentence, a long
        // list does not hide the storage word, and a numbered device name is
        // one.
        "Format the values and the 2.5-inch external drive",
        "Format the values in backup.img on the USB drive",
        "Format the entries for alpha_long_service_name_one, beta_long_service_name_two, gamma_long_service_name_three and delta_long_service_name_four on the backup disk",
        "Format the entries on disk0",
        "Format the values on disk2s1",
        "Format the entries on nvme0n1",
    ] {
        assert_not_benign(text);
    }
}
