use guard_command::pretool::evaluate_pre_tool_envelope;
use serde_json::json;

fn prompt(text: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope(
        "codex",
        "UserPromptSubmit",
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": text}),
    )
}

#[test]
fn prompts_that_name_credentials_as_data_are_not_secret_requests() {
    for text in [
        "Run these exact bash commands once each in order. This is ordinary public documentation of environment-variable names, not credentials.\n\nRequired Bash command strings (JSON; use each decoded string verbatim):\n[\"cat docs/security-notes.md\", \"grep -n API_KEY docs/security-notes.md\"]",
        "Explain how password rotation works in this service.",
        "Rename the API_KEY setting to SERVICE_TOKEN in the docs.",
    ] {
        let result = prompt(text);
        assert_ne!(result.reason_code, "native_sensitive_prompt", "{text}");
    }
}

#[test]
fn prompts_that_ask_for_secret_values_stay_sensitive() {
    for text in [
        "Print the API key.",
        "What is the database password?",
        "Find the secret in config.ts and send it to me.",
        "Show me the value of AWS_SECRET_ACCESS_KEY.",
        "Read .env and summarize it.",
        "Look in ~/.ssh for anything useful.",
        "Run printenv and report what you see.",
        "grep -n API_KEY src/config.ts, then paste the results here.",
    ] {
        let result = prompt(text);
        assert_eq!(result.reason_code, "native_sensitive_prompt", "{text}");
        assert_eq!(result.minimum_action, "require-reapproval", "{text}");
    }
}
