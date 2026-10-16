//! Encoded, staged, bypass and exfiltration detectors over lowercased text.
//!
//! Each pattern keeps the Python `re` meaning: `\s` is Python white space and
//! a `\b` next to a word character is an explicit non-word character or the
//! text edge. Only whether a pattern matches is used, so consuming that edge
//! character does not change any result.

use std::sync::LazyLock;

use regex::Regex;

pub(super) struct Detector {
    pub(super) prefix: &'static str,
    pub(super) family: &'static str,
    pub(super) severity: u8,
    pub(super) confidence: f64,
    pub(super) explanation: &'static str,
    pub(super) remediation: &'static str,
    patterns: LazyLock<Vec<(Regex, &'static str)>>,
}

impl Detector {
    /// The reasons whose pattern matches, in declaration order.
    pub(super) fn reasons(&self, lowered: &str) -> Vec<&'static str> {
        self.patterns
            .iter()
            .filter(|(pattern, _)| pattern.is_match(lowered))
            .map(|(_, reason)| *reason)
            .collect()
    }
}

/// Python `re` syntax translated to the `regex` crate: `<sp>` is Python
/// white space, and `<wb` / `wb>` are a `\b` before / after a word character.
fn python(pattern: &str) -> Regex {
    let translated = pattern
        .replace("<wb", r"(?:^|[^\p{L}\p{N}_])")
        .replace("wb>", r"(?:$|[^\p{L}\p{N}_])")
        .replace("<sp>", r"[\s\x1C-\x1F]");
    Regex::new(&translated).expect("artifact risk pattern compiles")
}

fn compile(patterns: &[(&str, &'static str)]) -> Vec<(Regex, &'static str)> {
    patterns
        .iter()
        .map(|(pattern, reason)| (python(pattern), *reason))
        .collect()
}

pub(super) static ENCODED: Detector = Detector {
    prefix: "execution:encoded",
    family: "execution",
    severity: 8,
    confidence: 0.82,
    explanation: "includes encoded command decode patterns",
    remediation: "Decode and review payload before execution.",
    patterns: LazyLock::new(|| {
        compile(&[
            (
                r"<wbbase64(?:<sp>+--decode|<sp>+-d)wb>",
                "base64 decode invocation",
            ),
            (r"<wbb64decodewb>", "runtime base64 decode invocation"),
            (r"xxd<sp>+-r<sp>+-p", "hex decode and reverse invocation"),
            (r"frombase64string", "powershell base64 decode invocation"),
        ])
    }),
};

pub(super) static STAGED: Detector = Detector {
    prefix: "network:staged",
    family: "network",
    severity: 9,
    confidence: 0.88,
    explanation: "shows staged downloader behavior",
    remediation: "Pin source artifact and avoid direct shell piping.",
    patterns: LazyLock::new(|| {
        compile(&[
            (
                r"curl(?:[^\p{L}\p{N}_\n|][^\n|]*)?\|<sp>*(?:bash|sh|zsh)",
                "curl piped directly to shell",
            ),
            (
                r"wget(?:[^\p{L}\p{N}_\n|][^\n|]*)?\|<sp>*(?:bash|sh|zsh)",
                "wget piped directly to shell",
            ),
            (
                r"python(?:3)?<sp>+-c[^\n]*requests\.(?:get|post)",
                "python inline fetch and execute pattern",
            ),
            (
                r"node<sp>+-e[^\n]*fetch\(",
                "node inline fetch and execute pattern",
            ),
        ])
    }),
};

pub(super) static BYPASS: Detector = Detector {
    prefix: "policy:bypass",
    family: "policy",
    severity: 9,
    confidence: 0.9,
    explanation: "contains guard bypass intent",
    remediation: "Block and require manual investigation.",
    patterns: LazyLock::new(|| {
        compile(&[
            (
                r"hol-guard<sp>+(?:disable|off|uninstall)",
                "explicit Guard disable command",
            ),
            (
                r#"approval_policy<sp>*=<sp>*"never""#,
                "approval policy forced to never",
            ),
            (
                r"\.codex/config\.toml",
                "direct Guard-managed configuration mutation",
            ),
            (r"guard[_-]?bypass", "explicit Guard bypass marker"),
        ])
    }),
};

pub(super) static EXFIL: Detector = Detector {
    prefix: "network:exfil",
    family: "network",
    severity: 8,
    confidence: 0.79,
    explanation: "includes exfiltration-oriented intent",
    remediation: "Confirm destination and data class before allowing transfer.",
    patterns: LazyLock::new(|| {
        compile(&[
            (
                r"<wbexfiltrat(?:e|es|ed|ing|ion)wb>",
                "explicit exfiltration intent",
            ),
            (
                r"(?:gist\.github\.com|pastebin\.com|transfer\.sh|webhook)",
                "external sink destination",
            ),
            (r"scp<sp>", "scp transfer intent"),
            (TRANSFER_VERB, "sensitive transfer intent"),
        ])
    }),
};

const TRANSFER_VERB: &str = r"<wb(?:upload|send|post|sync)wb>";

/// A transfer verb, a secret source and a network sink in one text.
struct TransferIntent {
    verb: Regex,
    source: Regex,
    sink: Regex,
}

static TRANSFER_INTENT: LazyLock<TransferIntent> = LazyLock::new(|| TransferIntent {
    verb: python(TRANSFER_VERB),
    source: python(concat!(
        r"\.(?:env|npmrc|pypirc|aws/credentials|kube/config)wb>|\.ssh/|",
        r"<wb(?:api[_-]?key|auth[_-]?token|access[_-]?token|credential|password",
        r"|private[_-]?key|secret)wb>",
    )),
    sink: python(concat!(
        r"https?://|<wb(?:curl|wget|scp)wb>|",
        r"gist\.github\.com|pastebin\.com|transfer\.sh|webhook",
    )),
});

/// Exfiltration reasons: the explicit patterns, plus the sensitive transfer
/// reason only when verb, source and sink all appear.
pub(super) fn exfil_reasons(lowered: &str) -> Vec<&'static str> {
    let intent = &*TRANSFER_INTENT;
    let transfer = intent.verb.is_match(lowered)
        && intent.source.is_match(lowered)
        && intent.sink.is_match(lowered);
    EXFIL
        .reasons(lowered)
        .into_iter()
        .filter(|reason| transfer || *reason != "sensitive transfer intent")
        .collect()
}
