//! `$'…'`, the ANSI-C quoted word, read as the text it spells.
//!
//! The word runs nothing: it is single-quoted text whose escapes are written
//! out. A shell that does not spell words this way never reaches here, so the
//! caller asks only for the shells that do.

/// The word `$'…'` spells and the position of its closing quote, read from
/// its `$`. A shell that keeps an unquoted backslash literal spells no such
/// word — there `\$'x\'` is a literal `$` and then a plain single-quoted
/// word — so that shell is refused rather than read a second way.
pub(super) fn word(
    chars: &[char],
    dollar: usize,
    preserve_backslash: bool,
) -> Result<(String, usize), &'static str> {
    if preserve_backslash {
        return Err("non_posix_quoting_not_yet_supported");
    }
    ansi_c_literal(chars, dollar + 2).ok_or("non_posix_quoting_not_yet_supported")
}

/// Reads an ANSI-C quoted word, `$'…'`, from the character after its opening
/// quote, and answers with the word it spells and the position of its closing
/// quote. The escapes are every one the shell writes a character with, and an
/// escape this reader cannot decode leaves the whole command uncertain rather
/// than a word spelled differently than the shell spells it.
fn ansi_c_literal(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut literal = String::new();
    let mut index = start;
    while index < chars.len() {
        match chars[index] {
            '\'' => return Some((literal, index)),
            '\\' => {
                let (character, next) = ansi_c_escape(chars, index + 1)?;
                literal.push(character);
                index = next;
            }
            // A word cannot carry a NUL, written out or spelled as an
            // escape, so neither spelling is decoded.
            '\0' => return None,
            character => {
                literal.push(character);
                index += 1;
            }
        }
    }
    None
}

/// Decodes one escape, from the character after its backslash, and answers
/// with it and the position after it.
fn ansi_c_escape(chars: &[char], index: usize) -> Option<(char, usize)> {
    let current = *chars.get(index)?;
    let simple = match current {
        'a' => Some('\u{7}'),
        'b' => Some('\u{8}'),
        'e' | 'E' => Some('\u{1b}'),
        'f' => Some('\u{c}'),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'v' => Some('\u{b}'),
        '\\' | '\'' | '"' | '?' => Some(current),
        _ => None,
    };
    if let Some(character) = simple {
        return Some((character, index + 1));
    }
    if current == 'x' {
        return ansi_c_number(chars, index + 1, 16, 2);
    }
    if current.is_digit(8) {
        return ansi_c_number(chars, index, 8, 3);
    }
    // `\u2713` and `\U0001F600` spell one character each, the same way the
    // character itself does when it is written into the word unescaped. A word
    // already carries those characters directly, so reading the escape adds no
    // spelling the rest of this reader does not already hand on; refusing it
    // left `echo $'done \u2714'` with no owner and no approval at all.
    if current == 'u' {
        return ansi_c_scalar(chars, index + 1, 4);
    }
    if current == 'U' {
        return ansi_c_scalar(chars, index + 1, 8);
    }
    // `\cG` is the control character whose letter is `G`: the shell takes the
    // low five bits, and `\c?` is the delete character.
    if current == 'c' {
        return ansi_c_control(chars, index + 1);
    }
    None
}

/// Reads up to `digits` hexadecimal digits and answers with the character
/// whose code point they spell. A surrogate half is no character, and a NUL
/// cannot be part of a word, so neither is decoded.
fn ansi_c_scalar(chars: &[char], start: usize, digits: usize) -> Option<(char, usize)> {
    let mut value = 0u32;
    let mut index = start;
    while index < chars.len() && index - start < digits {
        let Some(digit) = chars[index].to_digit(16) else {
            break;
        };
        value = value * 16 + digit;
        index += 1;
    }
    if index == start || value == 0 {
        return None;
    }
    Some((char::from_u32(value)?, index))
}

/// Reads the letter a `\c` escape names and answers with the control
/// character it spells. The letter itself is left undecoded when the character
/// it names is a NUL, which no word can carry.
///
/// Two letters are refused outright, because the shell settles where the word
/// ends before it decodes anything inside it. A quote ends the word there and
/// never reaches `\c` as its letter, so reading `$'\c'` as a bell would carry
/// this reader past the end of the word and swallow whatever runs behind it. A
/// backslash is the other: the shell reads `\c\` as the pair it is, so taking
/// one of them leaves the second to spell a quote that is not one.
fn ansi_c_control(chars: &[char], index: usize) -> Option<(char, usize)> {
    let named = *chars.get(index)?;
    if named == '\'' || named == '\\' {
        return None;
    }
    if named == '?' {
        return Some(('\u{7f}', index + 1));
    }
    if !named.is_ascii() {
        return None;
    }
    let value = u32::from(named.to_ascii_uppercase()) & 0x1f;
    if value == 0 {
        return None;
    }
    Some((char::from_u32(value)?, index + 1))
}

/// Reads up to `digits` digits in `radix` and answers with the character they
/// spell. A byte past ASCII is a byte, not a character, and a NUL cannot be
/// part of a word, so neither is decoded.
fn ansi_c_number(chars: &[char], start: usize, radix: u32, digits: usize) -> Option<(char, usize)> {
    let mut value = 0u32;
    let mut index = start;
    while index < chars.len() && index - start < digits {
        let Some(digit) = chars[index].to_digit(radix) else {
            break;
        };
        value = value * radix + digit;
        index += 1;
    }
    if index == start || value == 0 || value > 0x7f {
        return None;
    }
    Some((char::from_u32(value)?, index))
}
