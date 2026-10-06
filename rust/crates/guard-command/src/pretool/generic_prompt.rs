use super::sensitive_command;
use regex::Regex;
use std::sync::OnceLock;

const BYPASS_PATTERNS: [&str; 10] = [
    "disable hol-guard",
    "hol-guard disable",
    "hol-guard off",
    "hol-guard uninstall",
    "disable guard",
    "turn off guard",
    "uninstall guard",
    "use another mcp server",
    "guard-bypass",
    "guard_bypass",
];

fn authentication_requirement_pattern() -> &'static Regex {
    static AUTH_REQUIREMENT: OnceLock<Regex> = OnceLock::new();
    AUTH_REQUIREMENT.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:needs?|requires?)\s+(?:their|your|the user's|the operator's)\s+password\b",
        )
        .expect("bounded human authentication requirement")
    })
}

pub(super) fn prompt_sensitive_text(value: &str) -> bool {
    static AUTH_CONTEXT: OnceLock<Regex> = OnceLock::new();
    static REFERENTIAL_ACCESS: OnceLock<Regex> = OnceLock::new();
    let requirement = authentication_requirement_pattern();
    if !requirement.is_match(value) {
        return sensitive_command(value);
    }
    let context = AUTH_CONTEXT.get_or_init(|| {
        Regex::new(r"(?i)\b(?:authentication|authenticate|login|log\s+in|sign\s+in|recovery|recover-authority|terminal)\b")
            .expect("bounded human authentication context")
    });
    for (index, matched) in requirement.find_iter(value).enumerate() {
        if index >= 16 {
            return true;
        }
        let start = value[..matched.start()]
            .rfind(['.', '!', '?', ';', '\n'])
            .map_or(0, |offset| offset + 1);
        let end = value[matched.end()..]
            .find(['.', '!', '?', ';', '\n'])
            .map_or(value.len(), |offset| matched.end() + offset);
        if !context.is_match(&value[start..end]) {
            return true;
        }
    }
    // Authentication requirements are not requests to obtain the credential.
    // Keep explicit targets and referential follow-up reads on the guarded path.
    let followup = REFERENTIAL_ACCESS.get_or_init(|| {
        Regex::new(r"(?i)\b(?:read|open|print|show|display|disclose|reveal|echo|cat|output|write|type|paste|post|email|forward|share|give|hand|provide|tell|return|summari[sz]e|dump|copy|retrieve|fetch|obtain|extract|capture|store|save|log|include|grab|access|upload|send|transfer)\s+(?:(?:the\s+)?(?:full\s+)?(?:contents?|value|text|data)\s+(?:of|from)\s+)?(?:it|them|those|these|that|this|me|us)\b|\bhand\s+over\s+(?:it|them|those|these|that|this|me|us)\b|\b(?:do|perform|execute|run|use)\s+(?:it|that|this|them)\s+(?:anyway|regardless)\b")
            .expect("bounded credential referential follow-up")
    });
    if followup.is_match(value) {
        return true;
    }
    sensitive_command(&requirement.replace_all(value, "human authentication"))
}

pub(super) fn guard_bypass_prompt(values: &[String]) -> bool {
    static PROHIBITION: OnceLock<Regex> = OnceLock::new();
    static LIST_PROHIBITION: OnceLock<Regex> = OnceLock::new();
    static GUARDRAIL_ITEM: OnceLock<Regex> = OnceLock::new();
    static LIST_CONNECTOR: OnceLock<Regex> = OnceLock::new();
    static REVERSAL: OnceLock<Regex> = OnceLock::new();
    static FOLLOWUP: OnceLock<Regex> = OnceLock::new();
    static TEST_RETRY: OnceLock<Regex> = OnceLock::new();
    values.iter().any(|value| {
        let lowered = value.to_ascii_lowercase();
        let normalized = lowered.split_whitespace().collect::<Vec<_>>().join(" ");
        BYPASS_PATTERNS
        .iter()
        .any(|pattern| {
            normalized.match_indices(pattern).any(|(offset, _)| {
                let start = normalized[..offset]
                    .rfind(['.', '!', '?', ';'])
                    .map_or(0, |index| index + 1);
                let prefix = &normalized[start..offset];
                let prohibition = PROHIBITION.get_or_init(|| {
                    Regex::new(r"(?i)\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not)\s+$")
                        .expect("bounded guard bypass prohibition")
                });
                let list_prohibition = LIST_PROHIBITION.get_or_init(|| {
                    Regex::new(r"(?i)\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not)\s+((?:[a-z0-9_ -]{1,80},\s*)+)$")
                        .expect("bounded comma-listed guard bypass prohibition")
                });
                let list_connector = LIST_CONNECTOR.get_or_init(|| {
                    Regex::new(r"(?i)^\s*,\s*(?:or|and)\b")
                        .expect("bounded comma-listed guard bypass connector")
                });
                let reversal = REVERSAL.get_or_init(|| {
                    Regex::new(r"(?i)\b(?:except|unless|until|without|if|then|anyway|regardless)\b|\b(?:do|perform|execute|run|use)\s+(?:it|that|this|them|so)\b")
                        .expect("bounded guard bypass reversal")
                });
                // Mask only an unconditional prohibition, not a later bypass
                // instruction or a conditional exception to the prohibition.
                let tail = &normalized[offset + pattern.len()..];
                let clause = tail.split(['.', '!', '?', ';']).next().unwrap_or("");
                // Direct action references remain detectable anywhere in the tail.
                // "Use them" may instead refer to later test results, so require
                // an imperative clause for that ambiguous verb.
                let followup = FOLLOWUP.get_or_init(|| {
                    Regex::new(r"(?i)\b(?:do|perform|execute|run)\s+(?:(?:it|them|so)\b|(?:this|that)(?:\s+(?:anyway|regardless|now))?\s*(?:[.!?;]|$))|(?:^|[.!?;])\s*(?:(?:then|now|also|and|but|please)\s+)*use\s+(?:(?:it|them|so)\b|(?:this|that)(?:\s+(?:anyway|regardless|now))?\s*(?:[.!?;]|$))|(?:^|[.!?;])\s*(?:anyway|regardless)\s*(?:[.!?;]|$)")
                        .expect("bounded guard bypass referential follow-up")
                });
                let guardrail_item = GUARDRAIL_ITEM.get_or_init(|| {
                    Regex::new(r"(?i)^(?:(?:change|modify|alter|set|unset)\s+(?:node(?:[_-]|\s+)options|(?:hol[-_ ]guard|guard)\s+(?:hooks?|configuration|settings|policy)|policy\s+authority)|recover\s+policy\s+authority)$")
                        .expect("bounded protection-setting list item")
                });
                // A qualified retry of an intervening test action refers to that
                // action, not the earlier prohibition. Explicit reversals remain.
                let test_retry = TEST_RETRY.get_or_init(|| {
                    Regex::new(r"(?i)(?:^|[.!?;])\s*(?:run|rerun|retry|execute)\s+(?:the\s+)?(?:tests?|test\s+suite|typecheck|validation)\s*[.!?;]\s*(?:if\s+(?:they|it)\s+fails?,\s*)?(?:then\s+)?(?:do|perform|execute|run)\s+(?:it|them|so)\s+to\s+(?:investigate|debug|validate|check)\b")
                        .expect("bounded explicit test retry reference")
                });
                let followup_tail = test_retry.replace_all(tail, ". qualified test retry");
                let list_items_are_guardrails = list_prohibition.captures(prefix).is_some_and(|captures| {
                    captures.get(1).is_some_and(|body| {
                        body.as_str()
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .all(|item| BYPASS_PATTERNS.contains(&item)
                                || guardrail_item.is_match(item))
                    })
                });
                let unconditional = prohibition.is_match(prefix)
                    || (list_items_are_guardrails && list_connector.is_match(tail));
                !unconditional || reversal.is_match(prefix) || reversal.is_match(clause)
                    || followup.is_match(&followup_tail)
            })
        })
            || ["approval_policy=\"never\"", "approval_policy='never'"]
                .iter()
                .any(|pattern| normalized.replace(' ', "").contains(pattern))
    })
}

pub(super) fn prompt_injection_intent(values: &[String]) -> bool {
    static INJECTION: OnceLock<Regex> = OnceLock::new();
    let pattern = INJECTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?|ignore\s+(?:the\s+)?system\s+prompt|(?:do\s+not|don't)\s+(?:tell|notify|alert|inform)\s+(?:the\s+)?users?|hide\s+(?:this|it|the\s+(?:action|instruction|request))\s+from\s+(?:the\s+)?logs?|(?:reveal|print|show)\s+(?:the\s+)?(?:system\s+prompt|developer\s+instructions?)|(?:remove|strip)\s+(?:the\s+)?(?:guard\s+)?hooks?)\b")
            .expect("bounded prompt injection intent")
    });
    values.iter().any(|value| pattern.is_match(value))
}

pub(super) fn exfil_prompt_intent(values: &[String]) -> bool {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"(?i)\b(?:upload|exfiltrate|transfer|paste|gist|webhook)\b[^.!?;\n]{0,80}\b(?:contents?|data|payload|file|secret|token|key|credentials?|config|output)\b",
            r"(?i)\b(?:send|post|upload|transfer|paste|sync)\b[^.!?;\n]{0,120}(?:\.env\b|/\.ssh/|/\.aws/|\.npmrc\b|\.pypirc\b|\.authrc\b|\.envrc\b)[^.!?;\n]{0,80}\b(?:to|into|onto|via|through|over|at)\b[^.!?;\n]{0,80}(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)",
            r"(?i)\b(?:send|post|upload|transfer|paste|sync)\b[^.!?;\n]{0,80}\b(?:to|into|onto|via|through|over|at)\b[^.!?;\n]{0,40}\b(?:webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)\b",
            r"(?i)\b(?:send|post|upload|transfer|paste|sync)\b[^.!?;\n]{0,80}\b(?:contents?|data|payload|file|secret|token|key|credentials?|config|output)\b[^.!?;\n]{0,40}\b(?:to|into|onto|via|through|over|at)\b[^.!?;\n]{0,40}(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("bounded exfiltration prompt intent"))
        .collect()
    });
    values
        .iter()
        .any(|value| patterns.iter().any(|pattern| pattern.is_match(value)))
}

pub(super) fn destructive_prompt_intent(values: &[String]) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    static REFERENTIAL: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(r"(?i)(?:\brm\s+-[a-z]*[rf]\b|\b(?:delete|remove|overwrite|truncate|chmod|chown|mv)\b[^.!?;\n]{0,60}\b(?:file|directory|repo|workspace|contents?)\b)")
            .expect("bounded destructive prompt intent")
    });
    let referential = REFERENTIAL.get_or_init(|| {
        Regex::new(r"(?i)\b(?:delete|remove|overwrite|truncate|chmod|chown|mv)\s+(?:all\s+of\s+|everything\s+in\s+)?(?:(?:it|them|those|these)\b|(?:this|that)(?:\s*(?:[.!?;,]|$)|\s+(?:files?|director(?:y|ies)|repo(?:sitory)?|workspace|folder)\b))")
            .expect("bounded referential destructive prompt intent")
    });
    values.iter().any(|value| {
        pattern.is_match(&mask_destructive_prohibitions(value)) || referential.is_match(value)
    })
}

fn mask_destructive_prohibitions(value: &str) -> String {
    static PROHIBITION: OnceLock<Regex> = OnceLock::new();
    static EXCEPTION: OnceLock<Regex> = OnceLock::new();
    let prohibition = PROHIBITION
        .get_or_init(|| {
            Regex::new(r"(?i)\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not)\s+(?:delete|erase|wipe|format|kill|remove|overwrite|truncate|chmod|chown|mv)\b")
                .expect("bounded destructive action prohibition")
        });
    let exception = EXCEPTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:except|unless|until|without|if|but|besides|other\s+than|apart\s+from|aside\s+from|save\s+for|instead\s+of)\b")
            .expect("bounded conditional prohibition")
    });
    prohibition
        .replace_all(value, |captures: &regex::Captures<'_>| {
            let matched = captures.get(0).expect("matched prohibition");
            let tail = &value[matched.end()..];
            let clause = tail.split(['.', '!', '?', ';', '\n']).next().unwrap_or("");
            if exception.is_match(clause) {
                matched.as_str().to_owned()
            } else {
                "prohibited action".to_owned()
            }
        })
        .into_owned()
}

pub(super) fn subprocess_prompt_intent(values: &[String]) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:bash\s+-c\b|sh\s+-c\b|zsh\s+-c\b|powershell\b|cmd\s+/c\b|subprocess\b|exec\s*\(|spawn\s*\()")
            .expect("bounded subprocess prompt intent")
    });
    values.iter().any(|value| pattern.is_match(value))
}

pub(super) fn benign_prompt_text(text: &str) -> bool {
    static NEGATED_READ: OnceLock<Regex> = OnceLock::new();
    static DOCUMENTED_READ: OnceLock<Regex> = OnceLock::new();
    static DOCUMENTED_ENV: OnceLock<Regex> = OnceLock::new();
    static DOCUMENT_END: OnceLock<Regex> = OnceLock::new();
    static ENV_TEMPLATE: OnceLock<Regex> = OnceLock::new();
    static RISK_ACTION: OnceLock<Regex> = OnceLock::new();
    static REFERENTIAL_INSTRUCTION: OnceLock<Regex> = OnceLock::new();
    static REFERENT_ACTION: OnceLock<Regex> = OnceLock::new();

    let normalized = text.to_ascii_lowercase();
    let mut remainder = if prompt_sensitive_text(&normalized) {
        normalized.clone()
    } else {
        authentication_requirement_pattern()
            .replace_all(&normalized, "human authentication")
            .into_owned()
    };
    let sensitive_antecedent = sensitive_command(&remainder);
    // Mask only the prohibited verb, never its targets or later instructions.
    remainder = mask_destructive_prohibitions(&remainder);
    let documents = [
        "create ",
        "write ",
        "draft ",
        "document ",
        "generate ",
        "outline ",
    ]
    .iter()
    .any(|prefix| normalized.trim_start().starts_with(prefix))
        && ["markdown", "docs", "documentation", "checklist", "guide"]
            .iter()
            .any(|target| normalized.contains(target));
    if documents {
        let documented_end = DOCUMENT_END.get_or_init(|| {
            Regex::new(r"(?i)(?:must\s+stay\s+blocked|reads?\s+require\s+approval)\s*[.!?]?\s*$")
                .expect("bounded documented guardrail ending")
        });
        if sensitive_command(&normalized) && !documented_end.is_match(&normalized) {
            return false;
        }
        let documented_read = DOCUMENTED_READ.get_or_init(|| {
            Regex::new(
                r"(?i)`(?:cat|read|head|tail|grep|rg)\s+[^`]{0,512}`\s+must\s+stay\s+blocked",
            )
            .expect("bounded documented read expression")
        });
        remainder = documented_read.replace_all(&remainder, " ").into_owned();
        let documented_env = DOCUMENTED_ENV.get_or_init(|| {
            Regex::new(r"(?i)`\.env(?:\.[a-z0-9_.-]+)?`\s+reads?\s+require\s+approval")
                .expect("bounded documented environment reference")
        });
        remainder = documented_env.replace_all(&remainder, " ").into_owned();
    }
    let negated_read = NEGATED_READ.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not)\s+(?:read|open|print|show|dump|cat|inspect|copy|use|include|grab)\s+[`'"]?\.env(?:\.[a-z0-9_.-]+)?[`'"]?(?:\s+files?)?"#)
            .expect("bounded negated environment read")
    });
    let negated_suffix = negated_read
        .find_iter(&remainder)
        .last()
        .map(|matched| remainder[matched.end()..].to_owned());
    remainder = negated_read.replace_all(&remainder, " ").into_owned();
    if negated_suffix.is_some_and(|suffix| {
        REFERENT_ACTION
            .get_or_init(|| {
                Regex::new(r"(?i)\b(?:read|open|print|show|dump|copy|inspect|summari[sz]e|include|upload|send|transfer|use|grab|access|do(?:ing)?|perform|execute|run|follow|try)\b[^.!?;\n]{0,80}\b(?:it|them|those|these|its|their)\b")
                    .expect("bounded referential follow-up")
            })
            .is_match(&suffix)
    }) {
        return false;
    }
    let env_template = ENV_TEMPLATE
        .get_or_init(|| Regex::new(r"(?i)\.env\.example\b").expect("bounded template reference"));
    remainder = env_template.replace_all(&remainder, " ").into_owned();
    let risky_action = RISK_ACTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:rm\s+-[a-z]*[rf]\b|delete\b|erase\b|wipe\b|format\b|kill\b|upload\b|exfiltrat[a-z]*\b|transfer\b|curl\b|wget\b|sudo\b|bash\s+-c\b|sh\s+-c\b|powershell\b|cmd\s+/c\b|subprocess\b|spawn\s*\(|exec\s*\(|send\s+(?:data|payload|file|secret|token|credential)\b|post\s+(?:payload|data|file|secret)\b|sync\s+(?:output|data)\b|(?:send|post|sync|transfer)\s+(?:to|over|via|at)\s+(?:webhook|server|slack|discord|https?://)\b|then\s+(?:read|open|print|summari[sz]e|show|dump|include|use|grab|upload|send)\s+(?:it|them|those|files|secrets)\b)")
            .expect("bounded risky prompt action")
    });
    let referential = REFERENTIAL_INSTRUCTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:now|then|afterwards|also)\s+(?:do|perform|execute|follow|run|use)\s+(?:it|that|this|them|example)\b")
            .expect("bounded referential prompt instruction")
    });
    if referential.is_match(&remainder)
        && (sensitive_antecedent || risky_action.is_match(&normalized))
    {
        return false;
    }
    !sensitive_command(&remainder) && !risky_action.is_match(&remainder)
}
