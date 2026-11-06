//! Claude `AskUserQuestion` answers to HOL Guard approval prompts.
//!
//! When Guard holds a sensitive Claude action it asks Claude to put one fixed
//! approval question to the user. The PostToolUse hook for that question
//! carries the question Claude actually asked and the user's answer. This
//! kind decides whether the asked question is exactly the pending prompt
//! (header, question text bound to the approval code, the three options) and
//! maps the chosen option to `allow` or `block`. Anything else is not an
//! approval: the caller persists nothing.

use guard_contracts::ClaudeGuardQuestionVerdictV1;
use serde_json::{Map, Value};

use crate::context_digest::{is_python_space, python_strip};

const HEADER: &str = "HOL Guard";
const DEFAULT_QUESTION: &str =
    "HOL Guard intercepted this sensitive action. What should Claude do?";
const OPTIONS: [&str; 3] = ["Allow once", "Allow during this session", "Keep blocked"];
const ANSWER_KEYS: [&str; 6] = [
    "answer",
    "selected_answer",
    "selected",
    "choice",
    "value",
    "label",
];

/// The hook fields the verdict reads, as the transport projected them.
pub(crate) struct Question<'a> {
    pub event: Option<&'a str>,
    pub tool_name: &'a Value,
    pub tool_input: &'a Value,
    pub tool_response: &'a Value,
    /// `tool_response.answers` as ordered `[question, answer]` pairs, so the
    /// first matching question wins as it did in hook order.
    pub response_answers: Option<&'a [Value]>,
    pub pending: &'a Value,
}

struct Contract {
    header: String,
    question: String,
    options: Vec<String>,
}

/// Case- and whitespace-insensitive form used for every comparison.
fn normalize(text: &str) -> String {
    python_lower(python_strip(text))
        .split(is_python_space)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Python `str.lower()`, including final sigma. This is not casefold:
/// `ß` stays `ß`, and `İ` still expands to `i` plus a combining dot.
pub(crate) fn python_lower(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut lowered = String::with_capacity(text.len());
    for (index, ch) in chars.iter().copied().enumerate() {
        if ch == '\u{03A3}' {
            lowered.push(if is_final_sigma(&chars, index) {
                '\u{03C2}'
            } else {
                '\u{03C3}'
            });
        } else {
            lowered.extend(ch.to_lowercase());
        }
    }
    lowered
}

/// Unicode Final_Sigma: a cased letter precedes `Σ` through case-ignorable
/// characters only, and no cased letter follows on those same terms.
fn is_final_sigma(chars: &[char], index: usize) -> bool {
    cased_before(chars, index) && !cased_after(chars, index)
}

fn cased_before(chars: &[char], index: usize) -> bool {
    for ch in chars[..index].iter().copied().rev() {
        if is_cased(ch) {
            return true;
        }
        if !is_case_ignorable(ch) {
            return false;
        }
    }
    false
}

fn cased_after(chars: &[char], index: usize) -> bool {
    for ch in chars[index + 1..].iter().copied() {
        if is_cased(ch) {
            return true;
        }
        if !is_case_ignorable(ch) {
            return false;
        }
    }
    false
}

fn is_cased(ch: char) -> bool {
    ch.is_uppercase()
        || ch.is_lowercase()
        || matches!(
            ch,
            '\u{01C5}'
                | '\u{01C8}'
                | '\u{01CB}'
                | '\u{01F2}'
                | '\u{1F88}'..='\u{1F8F}'
                | '\u{1F98}'..='\u{1F9F}'
                | '\u{1FA8}'..='\u{1FAF}'
                | '\u{1FBC}'
                | '\u{1FCC}'
                | '\u{1FFC}'
        )
}

fn is_case_ignorable(ch: char) -> bool {
    let code = u32::from(ch);
    CASE_IGNORABLE
        .binary_search_by(|&(start, end)| {
            if code < start {
                std::cmp::Ordering::Greater
            } else if code > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Unicode 15.0 `Case_Ignorable` (Python 3.12 `str.lower()`).
#[rustfmt::skip]
const CASE_IGNORABLE: &[(u32, u32)] = &[
    (0x0027, 0x0027), (0x002E, 0x002E), (0x003A, 0x003A), (0x005E, 0x005E),
    (0x0060, 0x0060), (0x00A8, 0x00A8), (0x00AD, 0x00AD), (0x00AF, 0x00AF),
    (0x00B4, 0x00B4), (0x00B7, 0x00B8), (0x02B0, 0x036F), (0x0374, 0x0375),
    (0x037A, 0x037A), (0x0384, 0x0385), (0x0387, 0x0387), (0x0483, 0x0489),
    (0x0559, 0x0559), (0x055F, 0x055F), (0x0591, 0x05BD), (0x05BF, 0x05BF),
    (0x05C1, 0x05C2), (0x05C4, 0x05C5), (0x05C7, 0x05C7), (0x05F4, 0x05F4),
    (0x0600, 0x0605), (0x0610, 0x061A), (0x061C, 0x061C), (0x0640, 0x0640),
    (0x064B, 0x065F), (0x0670, 0x0670), (0x06D6, 0x06DD), (0x06DF, 0x06E8),
    (0x06EA, 0x06ED), (0x070F, 0x070F), (0x0711, 0x0711), (0x0730, 0x074A),
    (0x07A6, 0x07B0), (0x07EB, 0x07F5), (0x07FA, 0x07FA), (0x07FD, 0x07FD),
    (0x0816, 0x082D), (0x0859, 0x085B), (0x0888, 0x0888), (0x0890, 0x0891),
    (0x0898, 0x089F), (0x08C9, 0x0902), (0x093A, 0x093A), (0x093C, 0x093C),
    (0x0941, 0x0948), (0x094D, 0x094D), (0x0951, 0x0957), (0x0962, 0x0963),
    (0x0971, 0x0971), (0x0981, 0x0981), (0x09BC, 0x09BC), (0x09C1, 0x09C4),
    (0x09CD, 0x09CD), (0x09E2, 0x09E3), (0x09FE, 0x09FE), (0x0A01, 0x0A02),
    (0x0A3C, 0x0A3C), (0x0A41, 0x0A42), (0x0A47, 0x0A48), (0x0A4B, 0x0A4D),
    (0x0A51, 0x0A51), (0x0A70, 0x0A71), (0x0A75, 0x0A75), (0x0A81, 0x0A82),
    (0x0ABC, 0x0ABC), (0x0AC1, 0x0AC5), (0x0AC7, 0x0AC8), (0x0ACD, 0x0ACD),
    (0x0AE2, 0x0AE3), (0x0AFA, 0x0AFF), (0x0B01, 0x0B01), (0x0B3C, 0x0B3C),
    (0x0B3F, 0x0B3F), (0x0B41, 0x0B44), (0x0B4D, 0x0B4D), (0x0B55, 0x0B56),
    (0x0B62, 0x0B63), (0x0B82, 0x0B82), (0x0BC0, 0x0BC0), (0x0BCD, 0x0BCD),
    (0x0C00, 0x0C00), (0x0C04, 0x0C04), (0x0C3C, 0x0C3C), (0x0C3E, 0x0C40),
    (0x0C46, 0x0C48), (0x0C4A, 0x0C4D), (0x0C55, 0x0C56), (0x0C62, 0x0C63),
    (0x0C81, 0x0C81), (0x0CBC, 0x0CBC), (0x0CBF, 0x0CBF), (0x0CC6, 0x0CC6),
    (0x0CCC, 0x0CCD), (0x0CE2, 0x0CE3), (0x0D00, 0x0D01), (0x0D3B, 0x0D3C),
    (0x0D41, 0x0D44), (0x0D4D, 0x0D4D), (0x0D62, 0x0D63), (0x0D81, 0x0D81),
    (0x0DCA, 0x0DCA), (0x0DD2, 0x0DD4), (0x0DD6, 0x0DD6), (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A), (0x0E46, 0x0E4E), (0x0EB1, 0x0EB1), (0x0EB4, 0x0EBC),
    (0x0EC6, 0x0EC6), (0x0EC8, 0x0ECE), (0x0F18, 0x0F19), (0x0F35, 0x0F35),
    (0x0F37, 0x0F37), (0x0F39, 0x0F39), (0x0F71, 0x0F7E), (0x0F80, 0x0F84),
    (0x0F86, 0x0F87), (0x0F8D, 0x0F97), (0x0F99, 0x0FBC), (0x0FC6, 0x0FC6),
    (0x102D, 0x1030), (0x1032, 0x1037), (0x1039, 0x103A), (0x103D, 0x103E),
    (0x1058, 0x1059), (0x105E, 0x1060), (0x1071, 0x1074), (0x1082, 0x1082),
    (0x1085, 0x1086), (0x108D, 0x108D), (0x109D, 0x109D), (0x10FC, 0x10FC),
    (0x135D, 0x135F), (0x1712, 0x1714), (0x1732, 0x1733), (0x1752, 0x1753),
    (0x1772, 0x1773), (0x17B4, 0x17B5), (0x17B7, 0x17BD), (0x17C6, 0x17C6),
    (0x17C9, 0x17D3), (0x17D7, 0x17D7), (0x17DD, 0x17DD), (0x180B, 0x180F),
    (0x1843, 0x1843), (0x1885, 0x1886), (0x18A9, 0x18A9), (0x1920, 0x1922),
    (0x1927, 0x1928), (0x1932, 0x1932), (0x1939, 0x193B), (0x1A17, 0x1A18),
    (0x1A1B, 0x1A1B), (0x1A56, 0x1A56), (0x1A58, 0x1A5E), (0x1A60, 0x1A60),
    (0x1A62, 0x1A62), (0x1A65, 0x1A6C), (0x1A73, 0x1A7C), (0x1A7F, 0x1A7F),
    (0x1AA7, 0x1AA7), (0x1AB0, 0x1ACE), (0x1B00, 0x1B03), (0x1B34, 0x1B34),
    (0x1B36, 0x1B3A), (0x1B3C, 0x1B3C), (0x1B42, 0x1B42), (0x1B6B, 0x1B73),
    (0x1B80, 0x1B81), (0x1BA2, 0x1BA5), (0x1BA8, 0x1BA9), (0x1BAB, 0x1BAD),
    (0x1BE6, 0x1BE6), (0x1BE8, 0x1BE9), (0x1BED, 0x1BED), (0x1BEF, 0x1BF1),
    (0x1C2C, 0x1C33), (0x1C36, 0x1C37), (0x1C78, 0x1C7D), (0x1CD0, 0x1CD2),
    (0x1CD4, 0x1CE0), (0x1CE2, 0x1CE8), (0x1CED, 0x1CED), (0x1CF4, 0x1CF4),
    (0x1CF8, 0x1CF9), (0x1D2C, 0x1D6A), (0x1D78, 0x1D78), (0x1D9B, 0x1DFF),
    (0x1FBD, 0x1FBD), (0x1FBF, 0x1FC1), (0x1FCD, 0x1FCF), (0x1FDD, 0x1FDF),
    (0x1FED, 0x1FEF), (0x1FFD, 0x1FFE), (0x200B, 0x200F), (0x2018, 0x2019),
    (0x2024, 0x2024), (0x2027, 0x2027), (0x202A, 0x202E), (0x2060, 0x2064),
    (0x2066, 0x206F), (0x2071, 0x2071), (0x207F, 0x207F), (0x2090, 0x209C),
    (0x20D0, 0x20F0), (0x2C7C, 0x2C7D), (0x2CEF, 0x2CF1), (0x2D6F, 0x2D6F),
    (0x2D7F, 0x2D7F), (0x2DE0, 0x2DFF), (0x2E2F, 0x2E2F), (0x3005, 0x3005),
    (0x302A, 0x302D), (0x3031, 0x3035), (0x303B, 0x303B), (0x3099, 0x309E),
    (0x30FC, 0x30FE), (0xA015, 0xA015), (0xA4F8, 0xA4FD), (0xA60C, 0xA60C),
    (0xA66F, 0xA672), (0xA674, 0xA67D), (0xA67F, 0xA67F), (0xA69C, 0xA69F),
    (0xA6F0, 0xA6F1), (0xA700, 0xA721), (0xA770, 0xA770), (0xA788, 0xA78A),
    (0xA7F2, 0xA7F4), (0xA7F8, 0xA7F9), (0xA802, 0xA802), (0xA806, 0xA806),
    (0xA80B, 0xA80B), (0xA825, 0xA826), (0xA82C, 0xA82C), (0xA8C4, 0xA8C5),
    (0xA8E0, 0xA8F1), (0xA8FF, 0xA8FF), (0xA926, 0xA92D), (0xA947, 0xA951),
    (0xA980, 0xA982), (0xA9B3, 0xA9B3), (0xA9B6, 0xA9B9), (0xA9BC, 0xA9BD),
    (0xA9CF, 0xA9CF), (0xA9E5, 0xA9E6), (0xAA29, 0xAA2E), (0xAA31, 0xAA32),
    (0xAA35, 0xAA36), (0xAA43, 0xAA43), (0xAA4C, 0xAA4C), (0xAA70, 0xAA70),
    (0xAA7C, 0xAA7C), (0xAAB0, 0xAAB0), (0xAAB2, 0xAAB4), (0xAAB7, 0xAAB8),
    (0xAABE, 0xAABF), (0xAAC1, 0xAAC1), (0xAADD, 0xAADD), (0xAAEC, 0xAAED),
    (0xAAF3, 0xAAF4), (0xAAF6, 0xAAF6), (0xAB5B, 0xAB5F), (0xAB69, 0xAB6B),
    (0xABE5, 0xABE5), (0xABE8, 0xABE8), (0xABED, 0xABED), (0xFB1E, 0xFB1E),
    (0xFBB2, 0xFBC2), (0xFE00, 0xFE0F), (0xFE13, 0xFE13), (0xFE20, 0xFE2F),
    (0xFE52, 0xFE52), (0xFE55, 0xFE55), (0xFEFF, 0xFEFF), (0xFF07, 0xFF07),
    (0xFF0E, 0xFF0E), (0xFF1A, 0xFF1A), (0xFF3E, 0xFF3E), (0xFF40, 0xFF40),
    (0xFF70, 0xFF70), (0xFF9E, 0xFF9F), (0xFFE3, 0xFFE3), (0xFFF9, 0xFFFB),
    (0x101FD, 0x101FD), (0x102E0, 0x102E0), (0x10376, 0x1037A), (0x10780, 0x10785),
    (0x10787, 0x107B0), (0x107B2, 0x107BA), (0x10A01, 0x10A03), (0x10A05, 0x10A06),
    (0x10A0C, 0x10A0F), (0x10A38, 0x10A3A), (0x10A3F, 0x10A3F), (0x10AE5, 0x10AE6),
    (0x10D24, 0x10D27), (0x10EAB, 0x10EAC), (0x10EFD, 0x10EFF), (0x10F46, 0x10F50),
    (0x10F82, 0x10F85), (0x11001, 0x11001), (0x11038, 0x11046), (0x11070, 0x11070),
    (0x11073, 0x11074), (0x1107F, 0x11081), (0x110B3, 0x110B6), (0x110B9, 0x110BA),
    (0x110BD, 0x110BD), (0x110C2, 0x110C2), (0x110CD, 0x110CD), (0x11100, 0x11102),
    (0x11127, 0x1112B), (0x1112D, 0x11134), (0x11173, 0x11173), (0x11180, 0x11181),
    (0x111B6, 0x111BE), (0x111C9, 0x111CC), (0x111CF, 0x111CF), (0x1122F, 0x11231),
    (0x11234, 0x11234), (0x11236, 0x11237), (0x1123E, 0x1123E), (0x11241, 0x11241),
    (0x112DF, 0x112DF), (0x112E3, 0x112EA), (0x11300, 0x11301), (0x1133B, 0x1133C),
    (0x11340, 0x11340), (0x11366, 0x1136C), (0x11370, 0x11374), (0x11438, 0x1143F),
    (0x11442, 0x11444), (0x11446, 0x11446), (0x1145E, 0x1145E), (0x114B3, 0x114B8),
    (0x114BA, 0x114BA), (0x114BF, 0x114C0), (0x114C2, 0x114C3), (0x115B2, 0x115B5),
    (0x115BC, 0x115BD), (0x115BF, 0x115C0), (0x115DC, 0x115DD), (0x11633, 0x1163A),
    (0x1163D, 0x1163D), (0x1163F, 0x11640), (0x116AB, 0x116AB), (0x116AD, 0x116AD),
    (0x116B0, 0x116B5), (0x116B7, 0x116B7), (0x1171D, 0x1171F), (0x11722, 0x11725),
    (0x11727, 0x1172B), (0x1182F, 0x11837), (0x11839, 0x1183A), (0x1193B, 0x1193C),
    (0x1193E, 0x1193E), (0x11943, 0x11943), (0x119D4, 0x119D7), (0x119DA, 0x119DB),
    (0x119E0, 0x119E0), (0x11A01, 0x11A0A), (0x11A33, 0x11A38), (0x11A3B, 0x11A3E),
    (0x11A47, 0x11A47), (0x11A51, 0x11A56), (0x11A59, 0x11A5B), (0x11A8A, 0x11A96),
    (0x11A98, 0x11A99), (0x11C30, 0x11C36), (0x11C38, 0x11C3D), (0x11C3F, 0x11C3F),
    (0x11C92, 0x11CA7), (0x11CAA, 0x11CB0), (0x11CB2, 0x11CB3), (0x11CB5, 0x11CB6),
    (0x11D31, 0x11D36), (0x11D3A, 0x11D3A), (0x11D3C, 0x11D3D), (0x11D3F, 0x11D45),
    (0x11D47, 0x11D47), (0x11D90, 0x11D91), (0x11D95, 0x11D95), (0x11D97, 0x11D97),
    (0x11EF3, 0x11EF4), (0x11F00, 0x11F01), (0x11F36, 0x11F3A), (0x11F40, 0x11F40),
    (0x11F42, 0x11F42), (0x13430, 0x13440), (0x13447, 0x13455), (0x16AF0, 0x16AF4),
    (0x16B30, 0x16B36), (0x16B40, 0x16B43), (0x16F4F, 0x16F4F), (0x16F8F, 0x16F9F),
    (0x16FE0, 0x16FE1), (0x16FE3, 0x16FE4), (0x1AFF0, 0x1AFF3), (0x1AFF5, 0x1AFFB),
    (0x1AFFD, 0x1AFFE), (0x1BC9D, 0x1BC9E), (0x1BCA0, 0x1BCA3), (0x1CF00, 0x1CF2D),
    (0x1CF30, 0x1CF46), (0x1D167, 0x1D169), (0x1D173, 0x1D182), (0x1D185, 0x1D18B),
    (0x1D1AA, 0x1D1AD), (0x1D242, 0x1D244), (0x1DA00, 0x1DA36), (0x1DA3B, 0x1DA6C),
    (0x1DA75, 0x1DA75), (0x1DA84, 0x1DA84), (0x1DA9B, 0x1DA9F), (0x1DAA1, 0x1DAAF),
    (0x1E000, 0x1E006), (0x1E008, 0x1E018), (0x1E01B, 0x1E021), (0x1E023, 0x1E024),
    (0x1E026, 0x1E02A), (0x1E030, 0x1E06D), (0x1E08F, 0x1E08F), (0x1E130, 0x1E13D),
    (0x1E2AE, 0x1E2AE), (0x1E2EC, 0x1E2EF), (0x1E4EB, 0x1E4EF), (0x1E8D0, 0x1E8D6),
    (0x1E944, 0x1E94B), (0x1F3FB, 0x1F3FF), (0xE0001, 0xE0001), (0xE0020, 0xE007F),
    (0xE0100, 0xE01EF),
];

fn optional_string(value: Option<&Value>) -> Option<String> {
    let text = python_strip(value?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// Option labels; any item without a label voids the whole list.
fn options(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut labels = Vec::with_capacity(items.len());
    for item in items {
        let label = match item {
            Value::Object(object) => optional_string(object.get("label")),
            Value::String(text) => Some(python_strip(text).to_owned()),
            _ => None,
        };
        match label {
            Some(label) => labels.push(label),
            None => return Vec::new(),
        }
    }
    labels
}

fn normalized_options(options: &[impl AsRef<str>]) -> Vec<String> {
    options
        .iter()
        .map(|option| normalize(option.as_ref()))
        .collect()
}

/// The prompt Guard asked Claude to show for this pending approval.
fn pending_contract(pending: &Map<String, Value>) -> Option<Contract> {
    let header = optional_string(pending.get("approval_header"));
    let question = optional_string(pending.get("approval_question"));
    let options = options(pending.get("approval_options"));
    let expected_question = match optional_string(pending.get("approval_code")) {
        None if header.is_none() && question.is_none() && options.is_empty() => {
            return Some(Contract {
                header: HEADER.to_owned(),
                question: DEFAULT_QUESTION.to_owned(),
                options: OPTIONS.iter().map(|option| (*option).to_owned()).collect(),
            });
        }
        None => DEFAULT_QUESTION.to_owned(),
        Some(code) => format!(
            "HOL Guard intercepted this sensitive action (approval code: {code}). What should Claude do?"
        ),
    };
    let (Some(header), Some(question)) = (header, question) else {
        return None;
    };
    if options.is_empty()
        || normalize(&question) != normalize(&expected_question)
        || normalized_options(&options) != normalized_options(&OPTIONS)
    {
        return None;
    }
    Some(Contract {
        header,
        question,
        options,
    })
}

/// The single question in an `AskUserQuestion` input or response.
fn asked_contract(section: &Value) -> Option<Contract> {
    let Value::Array(questions) = section.as_object()?.get("questions")? else {
        return None;
    };
    let [Value::Object(first)] = questions.as_slice() else {
        return None;
    };
    let contract = Contract {
        header: optional_string(first.get("header"))?,
        question: optional_string(first.get("question"))?,
        options: options(first.get("options")),
    };
    (!contract.options.is_empty()).then_some(contract)
}

fn contracts_match(expected: &Contract, actual: &Contract) -> bool {
    normalize(&actual.header) == normalize(&expected.header)
        && normalize(&actual.question) == normalize(&expected.question)
        && normalized_options(&actual.options) == normalized_options(&expected.options)
}

fn is_question(request: &Question<'_>, pending: &Map<String, Value>) -> bool {
    if request.event != Some("PostToolUse") {
        return false;
    }
    let tool_name = optional_string(Some(request.tool_name));
    if tool_name.map(|name| name.to_lowercase()).as_deref() != Some("askuserquestion") {
        return false;
    }
    let Some(expected) = pending_contract(pending) else {
        return false;
    };
    let Some(input) = asked_contract(request.tool_input) else {
        return false;
    };
    contracts_match(&expected, &input)
        && asked_contract(request.tool_response)
            .is_none_or(|response| contracts_match(&expected, &response))
}

fn answer_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if !python_strip(text).is_empty() => Some(text.clone()),
        Value::Object(object) => optional_string(object.get("label")),
        _ => None,
    }
}

fn action_for_answer(text: &str) -> Option<&'static str> {
    match normalize(text).as_str() {
        "keep blocked" => Some("block"),
        "allow once" | "allow during this session" => Some("allow"),
        _ => None,
    }
}

/// The answer the user chose, read from the shapes Claude has reported.
fn chosen_answer(request: &Question<'_>, expected_question: Option<&str>) -> Option<String> {
    let response = match request.tool_response {
        Value::String(text) if !python_strip(text).is_empty() => return Some(text.clone()),
        Value::Object(object) => object,
        _ => return None,
    };
    if let Some(pairs) = request.response_answers {
        let pair = |item: &'_ Value| -> Option<(String, Value)> {
            let [Value::String(question), answer] = item.as_array()?.as_slice() else {
                return None;
            };
            Some((question.clone(), answer.clone()))
        };
        if let Some(expected) = expected_question.map(normalize) {
            let matched = pairs
                .iter()
                .filter_map(pair)
                .filter(|(question, _)| normalize(question) == expected)
                .find_map(|(_, answer)| answer_text(Some(&answer)));
            if matched.is_some() {
                return matched;
            }
        }
        if let [only] = pairs {
            if let Some(text) = pair(only).and_then(|(_, answer)| answer_text(Some(&answer))) {
                return Some(text);
            }
        }
    }
    if let Some(text) = ANSWER_KEYS
        .iter()
        .find_map(|key| answer_text(response.get(*key)))
    {
        return Some(text);
    }
    if response.contains_key("questions") || response.contains_key("options") {
        return None;
    }
    match response.get("content") {
        Some(Value::String(text)) if !python_strip(text).is_empty() => Some(text.clone()),
        _ => None,
    }
}

/// Whether the hook answers the pending HOL Guard prompt, and with what.
pub(crate) fn verdict(request: &Question<'_>) -> ClaudeGuardQuestionVerdictV1 {
    let Some(pending) = request.pending.as_object() else {
        return ClaudeGuardQuestionVerdictV1 {
            is_question: false,
            action: None,
        };
    };
    if !is_question(request, pending) {
        return ClaudeGuardQuestionVerdictV1 {
            is_question: false,
            action: None,
        };
    }
    let expected_question = optional_string(pending.get("approval_question"));
    let action = chosen_answer(request, expected_question.as_deref())
        .and_then(|text| action_for_answer(&text))
        .map(str::to_owned);
    ClaudeGuardQuestionVerdictV1 {
        is_question: true,
        action,
    }
}

#[cfg(test)]
#[path = "claude_guard_question_tests.rs"]
mod tests;
