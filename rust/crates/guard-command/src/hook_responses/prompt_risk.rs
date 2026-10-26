//! Prompt risk-class reasons shown for a blocked prompt.

pub(super) const PROMPT_RISK_CLASSES: [(&str, &str); 7] = [
    ("local_env_read", "Prompt requests a local .env file."),
    (
        "sensitive_material",
        "Prompt requests potentially sensitive local material.",
    ),
    (
        "exfil_intent",
        "Prompt includes exfiltration-oriented transfer intent.",
    ),
    (
        "destructive_intent",
        "Prompt includes a destructive local action.",
    ),
    ("subprocess_intent", "Prompt requests subprocess execution."),
    (
        "guard_bypass_intent",
        "Prompt includes Guard bypass intent.",
    ),
    (
        "prompt_injection_intent",
        "Prompt asks to override trusted instructions.",
    ),
];
