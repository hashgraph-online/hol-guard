//! A bare `echo` or `printf` that prints a US Social Security number.
//!
//! The literal-secret screen reviews a command that spells out a key or a
//! password, but a printed SSN passed: nothing in it is a program Guard
//! watches. The shape is kept to a single print with no pipe, redirect,
//! substitution or second command, so a test that feeds a sample number to a
//! redaction tool, or a search for one in a fixture, is never asked about.
//! Only numbers the Social Security Administration could have issued count:
//! area 001-899 except 666, group 01-99, serial 0001-9999.

use std::sync::LazyLock;

use regex::Regex;

// Do not consume neighboring bytes in the regex: adjacent candidates,
// including an invalid SSN followed by a valid one, need separate checks.
static SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([0-9]{3})-([0-9]{2})-([0-9]{4})").expect("ssn pattern"));

const PRINTERS: [&str; 2] = ["echo", "printf"];
// A print with extreme width/repetition must not allocate unbounded memory
// before the privacy check. Overflow is a conservative review, not an allow.
const MAX_RENDERED_PRINT_BYTES: usize = 65_536;

fn append_bounded(buffer: &mut String, part: &str) -> Option<()> {
    if part.len() > MAX_RENDERED_PRINT_BYTES.saturating_sub(buffer.len()) {
        return None;
    }
    buffer.push_str(part);
    Some(())
}

fn issuable(area: &str, group: &str, serial: &str) -> bool {
    let area_ok = area != "000" && area != "666" && !area.starts_with('9');
    area_ok && group != "00" && serial != "0000"
}

// Keep the original asymmetric boundaries: a period before the candidate
// can be part of a version, but trailing sentence punctuation is harmless.
fn attached_before(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':')
}

fn attached_after(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b':')
}

// Decode the printable escapes supported by shell printf format strings.
// Interpret only these escaped format bytes; echo (without -e) is untouched.
// Octal and hex forms must not conceal a printed SSN from the review floor.
fn decode_printf_escapes(text: &str, percent_b: bool) -> String {
    decode_printf_escapes_with_stop(text, percent_b).0
}

// In a Bash %b operand, \\c stops the entire printf before any later
// conversions or repeated formats. Format-string \\c remains literal.
fn decode_printf_escapes_with_stop(text: &str, percent_b: bool) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0c'),
            Some('v') => out.push('\x0b'),
            Some('e') => out.push('\x1b'),
            Some('\\') => out.push('\\'),
            Some('c') if percent_b => return (out, true),
            Some('x') => {
                let mut hex = String::new();
                while hex.len() < 2 && chars.peek().is_some_and(char::is_ascii_hexdigit) {
                    hex.push(chars.next().expect("peeked hexadecimal digit"));
                }
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    out.push(char::from(byte));
                } else {
                    out.push('\\');
                    out.push('x');
                }
            }
            Some(kind @ ('u' | 'U')) => {
                // Bash printf emits Unicode scalars for four- and eight-digit
                // escapes in both the format and %b operands. In particular,
                // U+002D is the ASCII hyphen used in an SSN.
                let limit = if kind == 'u' { 4 } else { 8 };
                let mut hex = String::new();
                while hex.len() < limit && chars.peek().is_some_and(char::is_ascii_hexdigit) {
                    hex.push(chars.next().expect("peeked Unicode hex digit"));
                }
                if let Ok(value) = u32::from_str_radix(&hex, 16) {
                    if let Some(scalar) = char::from_u32(value) {
                        out.push(scalar);
                        continue;
                    }
                }
                out.push('\\');
                out.push(kind);
                out.push_str(&hex);
            }
            Some(digit @ '0'..='7') => {
                let mut octal = digit.to_string();
                // Bash `%b` treats \0 plus up to three octal digits as one byte.
                // Format-string escapes keep their existing three-digit limit.
                let limit = if percent_b && digit == '0' { 4 } else { 3 };
                while octal.len() < limit && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                    octal.push(chars.next().expect("peeked octal digit"));
                }
                let byte = u16::from_str_radix(&octal, 8).expect("octal digits") as u8;
                out.push(char::from(byte));
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    (out, false)
}

// Render the simple Bash printf conversions this guard rule supports.
// Unlike concatenating operands with spaces, substitutions can form a number.
// Preserve literal backslashes in %s operands; only %b expands their escapes.
// Repeating the format handles extra operands, as Bash printf does.
// Bash printf interprets leading zero numbers as octal and 0x as hex.
// Use a bounded conversion so width/flag spellings cannot evade SSN review.
fn printf_decimal(raw: &str) -> String {
    let (negative, unsigned) = if let Some(tail) = raw.strip_prefix('-') {
        (true, tail)
    } else {
        (false, raw.strip_prefix('+').unwrap_or(raw))
    };
    let (base, digits) = if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        (16, hex)
    } else if unsigned.len() > 1 && unsigned.starts_with('0') {
        (8, &unsigned[1..])
    } else {
        (10, unsigned)
    };
    match u128::from_str_radix(digits, base) {
        Ok(value) if negative => format!("-{value}"),
        Ok(value) => value.to_string(),
        Err(_) => raw.to_string(),
    }
}

// Scan the RAW format. An escape-decoded percent sign is literal output,
// not the beginning of a conversion (e.g. \045%s).
fn render_printf(format: &str, args: &[String]) -> Option<String> {
    let mut printed = String::new();
    let mut next_arg = 0;
    loop {
        let previous_arg = next_arg;
        let mut chars = format.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let mut escape = String::from("\\");
                let Some(next) = chars.next() else {
                    append_bounded(&mut printed, "\\")?;
                    break;
                };
                escape.push(next);
                let extra = match next {
                    'x' | '0'..='7' => 2,
                    'u' => 4,
                    'U' => 8,
                    _ => 0,
                };
                for _ in 0..extra {
                    let valid = if matches!(next, 'x' | 'u' | 'U') {
                        chars.peek().is_some_and(char::is_ascii_hexdigit)
                    } else {
                        chars.peek().is_some_and(|c| ('0'..='7').contains(c))
                    };
                    if !valid {
                        break;
                    }
                    escape.push(chars.next().expect("peeked escape digit"));
                }
                append_bounded(&mut printed, &decode_printf_escapes(&escape, false))?;
                continue;
            }
            if ch != '%' {
                let mut utf8 = [0_u8; 4];
                append_bounded(&mut printed, ch.encode_utf8(&mut utf8))?;
                continue;
            }
            if chars.peek() == Some(&'%') {
                chars.next();
                append_bounded(&mut printed, "%")?;
                continue;
            }
            let mut flags = String::new();
            while chars.peek().is_some_and(|c| "-+ #0".contains(*c)) {
                flags.push(chars.next().expect("peeked printf flag"));
            }
            // Bash consumes a separate operand for dynamic width/precision.
            let width = if chars.peek() == Some(&'*') {
                chars.next();
                let raw = args.get(next_arg).map(String::as_str).unwrap_or("0");
                next_arg += 1;
                let value = raw.parse::<i64>().unwrap_or(0).clamp(-1024, 1024);
                if value < 0 {
                    flags.push('-');
                }
                value.unsigned_abs() as usize
            } else {
                let mut digits = String::new();
                while chars.peek().is_some_and(char::is_ascii_digit) {
                    digits.push(chars.next().expect("peeked printf width"));
                }
                digits.parse::<usize>().unwrap_or(0).min(1024)
            };
            let precision = if chars.peek() == Some(&'.') {
                chars.next();
                if chars.peek() == Some(&'*') {
                    chars.next();
                    let raw = args.get(next_arg).map(String::as_str).unwrap_or("-1");
                    next_arg += 1;
                    raw.parse::<i64>()
                        .ok()
                        .filter(|n| *n >= 0)
                        .map(|n| (n as usize).min(1024))
                } else {
                    let mut digits = String::new();
                    while chars.peek().is_some_and(char::is_ascii_digit) {
                        digits.push(chars.next().expect("peeked precision"));
                    }
                    Some(digits.parse::<usize>().unwrap_or(0).min(1024))
                }
            } else {
                None
            };
            while chars.peek().is_some_and(|c| "hlLqjzt".contains(*c)) {
                chars.next();
            }
            let Some(spec) = chars.next() else {
                append_bounded(&mut printed, "%")?;
                break;
            };
            let operand = args.get(next_arg).map(String::as_str).unwrap_or("");
            next_arg += 1;
            let numeric = matches!(spec, 'd' | 'i' | 'u' | 'x' | 'X' | 'o');
            let mut stop_after_percent_b = false;
            let mut rendered = match spec {
                's' => operand.to_string(),
                'b' => {
                    let (prefix, stopped) = decode_printf_escapes_with_stop(operand, true);
                    stop_after_percent_b = stopped;
                    prefix
                }
                'd' | 'i' | 'u' => printf_decimal(operand),
                'x' | 'X' | 'o' => {
                    let decimal = printf_decimal(operand);
                    if let Ok(value) = decimal.parse::<u128>() {
                        match spec {
                            'x' => format!("{value:x}"),
                            'X' => format!("{value:X}"),
                            'o' => format!("{value:o}"),
                            _ => unreachable!("numeric conversion"),
                        }
                    } else {
                        operand.to_string()
                    }
                }
                'c' => operand.chars().take(1).collect(),
                // For unsupported conversions, conservatively include the
                // operand: the SSN protection must not be evaded by syntax.
                _ => operand.to_string(),
            };
            if flags.contains('#') {
                if spec == 'x' && rendered != "0" {
                    rendered = format!("0x{rendered}");
                } else if spec == 'X' && rendered != "0" {
                    rendered = format!("0X{rendered}");
                } else if spec == 'o' && !rendered.starts_with('0') {
                    rendered = format!("0{rendered}");
                }
            }
            if let Some(limit) = precision {
                if spec == 's' || spec == 'b' {
                    rendered = rendered.chars().take(limit).collect();
                } else if numeric {
                    let (sign, digits) = if let Some(digits) = rendered.strip_prefix('-') {
                        ("-", digits)
                    } else {
                        ("", rendered.as_str())
                    };
                    rendered = format!(
                        "{sign}{}{digits}",
                        "0".repeat(limit.saturating_sub(digits.len()))
                    );
                }
            }
            let pad = width.saturating_sub(rendered.chars().count());
            if pad > 0 {
                if flags.contains('-') {
                    rendered.push_str(&" ".repeat(pad));
                } else if numeric && flags.contains('0') && precision.is_none() {
                    if let Some(rest) = rendered.strip_prefix('-') {
                        rendered = format!("-{}{rest}", "0".repeat(pad));
                    } else {
                        rendered = format!("{}{rendered}", "0".repeat(pad));
                    }
                } else {
                    rendered = format!("{}{rendered}", " ".repeat(pad));
                }
            }
            append_bounded(&mut printed, &rendered)?;
            if stop_after_percent_b {
                // Bash applies this %b conversion's width and precision to
                // the emitted prefix before stopping all later conversions.
                return Some(printed);
            }
        }
        if next_arg >= args.len() || next_arg == previous_arg {
            break;
        }
    }
    Some(printed)
}

// Parse only a single literal print. Shell quote removal can join fragments:
// 123-45-67"89" prints 123-45-6789, while '123-45-6789'0 is attached.
// A comment starts at an unquoted, unescaped word boundary, so syntax after
// it is not executable. Reject substitutions, operators and multiline input.
// Preserve shell-word boundaries while removing only literal quoting.
// In printf, backslash escapes are expanded by the *format*, not by a
// regular %s argument. Flattening these words before decoding would review
// a printed literal such as 123\05545\0556789 as though it were an SSN.
fn literal_print_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut word_start = true;
    let mut started = false;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    word.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '$' | '\x60' | '\n' | '\r' => return None,
                '\\' => {
                    let escaped = chars.next()?;
                    match escaped {
                        '$' | '\x60' | '"' | '\\' => word.push(escaped),
                        '\n' | '\r' => return None,
                        _ => {
                            word.push('\\');
                            word.push(escaped);
                        }
                    }
                }
                _ => word.push(ch),
            },
            _ => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                    word_start = false;
                }
                ' ' | '\t' => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                    word_start = true;
                }
                '#' if word_start => break,
                '\\' => {
                    let escaped = chars.next()?;
                    if matches!(escaped, '\n' | '\r') {
                        return None;
                    }
                    word.push(escaped);
                    started = true;
                    word_start = false;
                }
                '|' | ';' | '&' | '<' | '>' | '$' | '\x60' | '\n' | '\r' | '(' | ')' => {
                    return None;
                }
                _ => {
                    word.push(ch);
                    started = true;
                    word_start = false;
                }
            },
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

/// Whether command is a single echo/printf that prints a plausible US SSN.
pub(super) fn echoes_ssn(command: &str) -> bool {
    let trimmed = command.trim();
    let program = trimmed.split_whitespace().next().unwrap_or("");
    if !PRINTERS.contains(&program) {
        return false;
    }
    let Some(words) = literal_print_words(trimmed) else {
        return false;
    };
    let decoded = if program == "printf" {
        // Bash printf accepts `--` before its format string. Treating it as
        // the format skips a real, escape-encoded SSN in the next word.
        let format_index = if words.get(1).map(String::as_str) == Some("--") {
            2
        } else {
            1
        };
        let Some(format) = words.get(format_index) else {
            return false;
        };
        // If rendering exceeds the fixed budget, fail closed to review.
        // An unbounded reconstruction would let large repeated formats
        // exhaust resources before the SSN protection can inspect them.
        let Some(rendered) = render_printf(format, &words[format_index + 1..]) else {
            return true;
        };
        rendered
    } else {
        words.join(" ")
    };
    let bytes = decoded.as_bytes();
    SSN.captures_iter(&decoded).any(|found| {
        let span = found.get(0).expect("SSN capture");
        (span.start() == 0 || !attached_before(bytes[span.start() - 1]))
            && (span.end() == bytes.len() || !attached_after(bytes[span.end()]))
            && issuable(&found[1], &found[2], &found[3])
    })
}

#[cfg(test)]
#[path = "literal_ssn_echo_tests.rs"]
mod tests;
