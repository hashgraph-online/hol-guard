//! Rust port of `detect_skill_content_risk` / `has_skill_structure` from
//! `runtime/skill_protection.py` (skill identity helpers are not ported).
//!
//! Python `re` semantics come from [`crate::persistence_rules::py_regex`].
//! Known, documented divergence: the `skill.unicode-controls` technical
//! detail lists the distinct control characters in code-point order, while
//! Python iterates a `set` of `str` (hash-seed dependent order).

use std::sync::LazyLock;

use fancy_regex::Regex;
use guard_contracts::{
    RiskConfidenceLabel, RiskRedactionLevel, RiskSeverityLabel, RiskSignalCategory, RiskSignalV2,
};

use crate::detectors::SkillProtectionApi;
use crate::persistence_rules::{py_regex, re_search};

fn many(patterns: &[(&str, &str)]) -> Vec<Regex> {
    patterns.iter().map(|(p, f)| py_regex(p, f)).collect()
}

static FRONTMATTER: LazyLock<Regex> = LazyLock::new(|| py_regex(r"---\s.*?---", "s"));
static SHELL_COMMAND: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"```(?:bash|sh|shell|zsh)\s(.*?)```", "s"));

static SECRET_READ: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (r"\bcat\s+\.env\b", "i"),
        (
            r"\bcat\s+~?/[^\s]*(?:\.env|secret|credential|password|token|key)\b",
            "i",
        ),
        (
            r#"\breadFile\s*\(['"].*?(?:\.env|secret|credential|password|key)['"]"#,
            "i",
        ),
        (
            r#"\bopen\s*\(['"].*?(?:\.env|secret|credential|password|key)['"]"#,
            "i",
        ),
    ])
});
static EXFIL_SINK: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (r#"\bcurl\s+.*?https?://[^\s`"']+"#, "i"),
        (r#"\bwget\s+.*?https?://[^\s`"']+"#, "i"),
        (r#"\bfetch\s*\(\s*['"]https?://"#, "i"),
        (r#"\baxios\.[a-z]+\s*\(\s*['"]https?://"#, "i"),
    ])
});
static REMOTE_FETCH_EXEC: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (r"curl\s+.*?\|\s*(?:bash|sh|python|node|ruby)\b", "i"),
        (r"wget\s+.*?-O\s*-\s*\|\s*(?:bash|sh|python|node)\b", "i"),
        (r"\bnpx\s+[^\s]+@[^\s]+", "i"),
        (r"\beval\s*\(\s*(?:fetch|curl|wget)", "i"),
    ])
});
static PACKAGE_INSTALL: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[(
        r"\b(?:npm\s+(?:install|i|add|ci)|pnpm\s+(?:install|i|add)|yarn\s+add|bun\s+add|pip\s+install|uv\s+pip\s+install|pipx\s+install|poetry\s+add|cargo\s+install|go\s+install|gem\s+install|brew\s+install)\b",
        "i",
    )])
});
static GIT_HOOKS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (r"\.git/hooks/[a-z\-]+", "i"),
        (r"\bcore\.hooksPath\b", "i"),
    ])
});
static SHELL_PROFILE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (
            r"~?/\.(?:bashrc|bash_profile|zshrc|profile|zprofile|bash_login)\b",
            "",
        ),
        (r"\becho\b.*>>\s*~?/\.(?:bashrc|zshrc|profile)\b", "i"),
    ])
});
static LAUNCHAGENT: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (r"~/Library/LaunchAgents/", "i"),
        (r"\blaunchctl\s+(?:load|submit|start)\b", "i"),
    ])
});
static CRON: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (r"\bcrontab\s+-[el]\b", "i"),
        (r"/etc/cron\.", "i"),
        (r"/var/spool/cron/", "i"),
    ])
});
static GUARD_BYPASS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (
            r"\b(?:disable|uninstall|bypass|remove)\s+HOL\s+Guard\b",
            "i",
        ),
        (r"\b(?:delete|rm)\b.*?\.claude/settings\.local\.json", "i"),
        (r"\b(?:delete|rm)\b.*?\.codex/config\.toml", "i"),
        (
            r"\bpre-(?:push|commit)\s+hook\b.*?\b(?:remove|delete|disable)\b",
            "i",
        ),
    ])
});
static HIDE_ACTIONS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    many(&[
        (
            r"\b(?:do\s+not|don't)\s+(?:tell|notify|mention|show)\s+.*?(?:user|human)\b",
            "i",
        ),
        (
            r"\bhide\s+(?:this|these|the\s+action|your\s+actions?)\s+from\b",
            "i",
        ),
        (r"\bdo\s+this\s+(?:silently|without\s+notif)", "i"),
    ])
});
static BASE64_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b", ""));
static HEX_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"\b(?:[0-9a-fA-F]{2}){30,}\b", ""));
static SKILL_FRONTMATTER_GATE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"---[\r\n ]+\w+\s*:.*?---", "s"));
static SKILL_HEADING_GATE: LazyLock<Regex> = LazyLock::new(|| py_regex(r"^#+\s+\S", "m"));
static SKILL_NAME_FIELD_GATE: LazyLock<Regex> = LazyLock::new(|| py_regex(r"^name\s*:", "mi"));

const UNICODE_CONTROLS: [(char, &str); 16] = [
    ('\u{200b}', "ZERO WIDTH SPACE"),
    ('\u{200c}', "ZERO WIDTH NON-JOINER"),
    ('\u{200d}', "ZERO WIDTH JOINER"),
    ('\u{200e}', "LEFT-TO-RIGHT MARK"),
    ('\u{200f}', "RIGHT-TO-LEFT MARK"),
    ('\u{202a}', "LEFT-TO-RIGHT EMBEDDING"),
    ('\u{202b}', "RIGHT-TO-LEFT EMBEDDING"),
    ('\u{202c}', "POP DIRECTIONAL FORMATTING"),
    ('\u{202d}', "LEFT-TO-RIGHT OVERRIDE"),
    ('\u{202e}', "RIGHT-TO-LEFT OVERRIDE"),
    ('\u{2060}', "WORD JOINER"),
    ('\u{2061}', "FUNCTION APPLICATION"),
    ('\u{2062}', "INVISIBLE TIMES"),
    ('\u{2063}', "INVISIBLE SEPARATOR"),
    ('\u{2064}', "INVISIBLE PLUS"),
    ('\u{feff}', "ZERO WIDTH NO-BREAK SPACE"),
];

/// `has_skill_structure(content)`.
pub fn has_skill_structure(content: &str) -> bool {
    if content.contains("SKILL.md") || content.to_lowercase().contains("skill:") {
        return true;
    }
    if re_search(&SKILL_FRONTMATTER_GATE, content) {
        return true;
    }
    re_search(&SKILL_NAME_FIELD_GATE, content) && re_search(&SKILL_HEADING_GATE, content)
}

struct Sig {
    id: &'static str,
    category: RiskSignalCategory,
    severity: RiskSeverityLabel,
    confidence: RiskConfidenceLabel,
    title: &'static str,
    reason: &'static str,
    hint: Option<&'static str>,
}

fn skill_signal(sig: &Sig, technical_detail: String) -> RiskSignalV2 {
    RiskSignalV2 {
        signal_id: sig.id.to_string(),
        category: sig.category,
        severity: sig.severity,
        confidence: sig.confidence,
        detector: "skill.content".to_string(),
        title: sig.title.to_string(),
        plain_reason: sig.reason.to_string(),
        technical_detail: Some(technical_detail),
        evidence_ref: Some("skill_content".to_string()),
        redaction_level: RiskRedactionLevel::Summary,
        false_positive_hint: sig.hint.map(str::to_string),
        advisory_id: None,
    }
}

fn any_match(patterns: &[Regex], text: &str) -> bool {
    patterns.iter().any(|p| re_search(p, text))
}

/// Push `sig` when any pattern matches (the Python `_check_*` shape).
fn check(content: &str, patterns: &[Regex], sig: &Sig, detail: &str, out: &mut Vec<RiskSignalV2>) {
    if any_match(patterns, content) {
        out.push(skill_signal(sig, detail.to_string()));
    }
}

/// `base64.b64decode(candidate + padding)` (non-strict) -> bytes, or `None`
/// where Python raises `binascii.Error`. Candidates only contain the base64
/// alphabet plus up to two trailing `=`; the only failing shape is a data
/// character count that is 1 more than a multiple of 4.
fn b64decode_py(candidate: &str) -> Option<Vec<u8>> {
    let data: Vec<u8> = candidate.bytes().filter(|b| *b != b'=').collect();
    if data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in data {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn decoded_is_dangerous(decoded: &str) -> bool {
    any_match(&SECRET_READ, decoded)
        || any_match(&EXFIL_SINK, decoded)
        || any_match(&REMOTE_FETCH_EXEC, decoded)
}

fn truncated(candidate: &str) -> String {
    candidate.chars().take(40).collect()
}

fn check_encoded_payloads(content: &str, out: &mut Vec<RiskSignalV2>) {
    for m in BASE64_CANDIDATE.find_iter(content).flatten() {
        let candidate = m.as_str();
        let Some(bytes) = b64decode_py(candidate) else {
            continue;
        };
        let Ok(decoded) = String::from_utf8(bytes) else {
            continue;
        };
        if decoded_is_dangerous(&decoded) {
            out.push(skill_signal(
                &Sig {
                    id: "skill.encoded-payload",
                    category: RiskSignalCategory::Encoded,
                    severity: RiskSeverityLabel::Critical,
                    confidence: RiskConfidenceLabel::Strong,
                    title: "Skill contains an encoded malicious payload",
                    reason: "This skill includes a base64-encoded string that decodes to a dangerous command.",
                    hint: None,
                },
                format!("encoded payload: {}\u{2026}", truncated(candidate)),
            ));
            return;
        }
    }
    for m in HEX_CANDIDATE.find_iter(content).flatten() {
        let candidate = m.as_str();
        let Ok(bytes) = hex::decode(candidate) else {
            continue;
        };
        let Ok(decoded) = String::from_utf8(bytes) else {
            continue;
        };
        if decoded_is_dangerous(&decoded) {
            out.push(skill_signal(
                &Sig {
                    id: "skill.encoded-payload",
                    category: RiskSignalCategory::Encoded,
                    severity: RiskSeverityLabel::Critical,
                    confidence: RiskConfidenceLabel::Strong,
                    title: "Skill contains a hex-encoded malicious payload",
                    reason: "This skill includes a hex-encoded string that decodes to a dangerous command.",
                    hint: None,
                },
                format!("hex payload: {}\u{2026}", truncated(candidate)),
            ));
            return;
        }
    }
}

fn check_unicode_controls(content: &str, out: &mut Vec<RiskSignalV2>) {
    let names: Vec<&str> = UNICODE_CONTROLS
        .iter()
        .filter(|(ch, _)| content.contains(*ch))
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        return;
    }
    let joined: String = names.join(", ").chars().take(120).collect();
    out.push(skill_signal(
        &Sig {
            id: "skill.unicode-controls",
            category: RiskSignalCategory::Encoded,
            severity: RiskSeverityLabel::Medium,
            confidence: RiskConfidenceLabel::Likely,
            title: "Skill content contains Unicode control characters",
            reason: "Hidden Unicode characters may conceal instructions from human reviewers.",
            hint: Some("may be legitimate bidirectional text in multilingual content"),
        },
        format!("Unicode controls found: {joined}"),
    ));
}

fn check_shell_in_frontmatter(content: &str, out: &mut Vec<RiskSignalV2>) {
    let hit = FRONTMATTER
        .find_iter(content)
        .flatten()
        .any(|block| re_search(&SHELL_COMMAND, block.as_str()));
    if hit {
        out.push(skill_signal(
            &Sig {
                id: "skill.shell-in-frontmatter",
                category: RiskSignalCategory::Execution,
                severity: RiskSeverityLabel::High,
                confidence: RiskConfidenceLabel::Strong,
                title: "Skill YAML frontmatter contains shell code blocks",
                reason: "This skill embeds shell commands inside its YAML frontmatter section.",
                hint: None,
            },
            "shell code block found in frontmatter".to_string(),
        ));
    }
}

macro_rules! strong {
    ($id:literal, $cat:ident, $sev:ident, $title:literal, $reason:literal) => {
        Sig {
            id: $id,
            category: RiskSignalCategory::$cat,
            severity: RiskSeverityLabel::$sev,
            confidence: RiskConfidenceLabel::Strong,
            title: $title,
            reason: $reason,
            hint: None,
        }
    };
}

/// `detect_skill_content_risk(content)`.
pub fn detect_skill_content_risk(content: &str) -> Vec<RiskSignalV2> {
    let mut s = Vec::new();
    check_shell_in_frontmatter(content, &mut s);
    check(content, &SECRET_READ, &strong!("skill.secret-read", Secret, High, "Skill content reads local secret files", "This skill contains instructions to read secret files such as .env or credential stores."), "secret read pattern in skill content", &mut s);
    check(
        content,
        &EXFIL_SINK,
        &strong!(
            "skill.exfil-sink",
            Network,
            High,
            "Skill content sends data to a remote endpoint",
            "This skill contains HTTP upload or network exfiltration instructions."
        ),
        "outbound HTTP sink in skill content",
        &mut s,
    );
    check(
        content,
        &REMOTE_FETCH_EXEC,
        &strong!(
            "skill.remote-fetch-exec",
            Execution,
            Critical,
            "Skill fetches and executes remote code",
            "This skill pipes remote content into a shell or interpreter."
        ),
        "fetch-and-execute pattern in skill content",
        &mut s,
    );
    check(content, &PACKAGE_INSTALL, &strong!("skill.package-install", SupplyChain, Medium, "Skill instructs the agent to install packages before execution", "This skill contains package-manager install instructions that can change the local runtime."), "package install command in skill content", &mut s);
    check(
        content,
        &GIT_HOOKS,
        &strong!(
            "skill.git-hooks",
            Persistence,
            High,
            "Skill installs or modifies Git hooks",
            "This skill creates or modifies Git hooks, which persist across commits."
        ),
        "git hook reference in skill content",
        &mut s,
    );
    check(
        content,
        &SHELL_PROFILE,
        &strong!(
            "skill.shell-profile",
            Persistence,
            High,
            "Skill modifies shell profile for persistence",
            "This skill appends to shell profiles such as .bashrc or .zshrc."
        ),
        "shell profile modification in skill content",
        &mut s,
    );
    check(
        content,
        &LAUNCHAGENT,
        &strong!(
            "skill.launchagent",
            Persistence,
            Critical,
            "Skill installs a macOS LaunchAgent",
            "This skill writes or loads a macOS LaunchAgent for persistent execution."
        ),
        "LaunchAgent install pattern in skill content",
        &mut s,
    );
    check(
        content,
        &CRON,
        &strong!(
            "skill.cron",
            Persistence,
            High,
            "Skill installs a cron job",
            "This skill modifies crontab or system cron directories for persistent execution."
        ),
        "cron persistence pattern in skill content",
        &mut s,
    );
    check(
        content,
        &GUARD_BYPASS,
        &strong!(
            "skill.guard-bypass",
            Bypass,
            Critical,
            "Skill instructs agent to disable HOL Guard",
            "This skill contains instructions to remove, disable, or bypass HOL Guard protection."
        ),
        "guard bypass instruction in skill content",
        &mut s,
    );
    let hide = Sig {
        id: "skill.hide-actions",
        category: RiskSignalCategory::Bypass,
        severity: RiskSeverityLabel::High,
        confidence: RiskConfidenceLabel::Likely,
        title: "Skill instructs agent to hide its actions",
        reason: "This skill tells the agent to act silently without notifying the user.",
        hint: Some("may be documentation explaining what not to do"),
    };
    check(
        content,
        &HIDE_ACTIONS,
        &hide,
        "stealth instruction in skill content",
        &mut s,
    );
    check_encoded_payloads(content, &mut s);
    check_unicode_controls(content, &mut s);
    s
}

/// Native implementation of the `SkillProtectionApi` seam.
pub struct NativeSkillProtection;

impl SkillProtectionApi for NativeSkillProtection {
    fn has_skill_structure(&self, text: &str) -> bool {
        has_skill_structure(text)
    }

    fn detect_skill_content_risk(&self, text: &str) -> Vec<RiskSignalV2> {
        detect_skill_content_risk(text)
    }
}

#[cfg(test)]
#[path = "skill_content_risk_tests.rs"]
mod tests;
