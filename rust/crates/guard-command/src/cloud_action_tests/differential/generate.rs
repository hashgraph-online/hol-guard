//! Seeded argument documents, equivalent spellings of them, and the
//! shrinker that reduces a failing document to a minimal case.

use serde_json::{json, Value};

pub(super) const SPELLINGS: usize = 4;

pub(super) const ALPHABET: [char; 14] = [
    'a', 'Z', '0', ' ', '"', '\\', '/', '\n', '\u{1}', 'é', '\u{7f}', '\u{2028}', '\u{ffff}', '😀',
];

/// xorshift64*: small, seedable and the same on every platform.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(super) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn text(rng: &mut Rng, max: usize) -> String {
    (0..rng.below(max + 1))
        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
        .collect()
}

fn value(rng: &mut Rng, depth: usize) -> Value {
    let leaf_only = depth == 0;
    match rng.below(if leaf_only { 4 } else { 6 }) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 1),
        2 => {
            const SAFE: i64 = 9_007_199_254_740_991;
            json!([0, -1, SAFE, -SAFE, (rng.next() % 1_000_000) as i64][rng.below(5)])
        }
        3 => Value::String(text(rng, 6)),
        4 => Value::Array((0..rng.below(4)).map(|_| value(rng, depth - 1)).collect()),
        _ => object(rng, depth - 1),
    }
}

pub(super) fn object(rng: &mut Rng, depth: usize) -> Value {
    Value::Object(
        (0..rng.below(5))
            .map(|_| (text(rng, 4), value(rng, depth)))
            .collect(),
    )
}

/// JSON whitespace, sometimes none.
fn gap(rng: &mut Rng) -> &'static str {
    ["", "", " ", "\n", "\t ", "\r\n"][rng.below(6)]
}

fn spell_string(rng: &mut Rng, text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        let mut units = [0u16; 2];
        let escaped: String = ch
            .encode_utf16(&mut units)
            .iter()
            .map(|unit| format!("\\u{unit:04x}"))
            .collect();
        let short = match ch {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '/' => Some("\\/"),
            '\n' => Some("\\n"),
            _ => None,
        };
        let must_escape = ch == '"' || ch == '\\' || ch < ' ';
        match rng.below(3) {
            0 if short.is_some() => out.push_str(short.unwrap()),
            1 if !must_escape => out.push(ch),
            _ if rng.below(2) == 0 => out.push_str(&escaped.to_uppercase().replace("\\U", "\\u")),
            _ => out.push_str(&escaped),
        }
    }
    out.push('"');
}

/// One equivalent JSON text for `value`: shuffled keys, random whitespace,
/// random escape forms.
fn spell(rng: &mut Rng, value: &Value, out: &mut String) {
    match value {
        Value::String(text) => spell_string(rng, text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                out.push_str(gap(rng));
                if index > 0 {
                    out.push(',');
                    out.push_str(gap(rng));
                }
                spell(rng, item, out);
            }
            out.push_str(gap(rng));
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            for index in (1..entries.len()).rev() {
                entries.swap(index, rng.below(index + 1));
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                out.push_str(gap(rng));
                if index > 0 {
                    out.push(',');
                    out.push_str(gap(rng));
                }
                spell_string(rng, key, out);
                out.push_str(gap(rng));
                out.push(':');
                out.push_str(gap(rng));
                spell(rng, item, out);
            }
            out.push_str(gap(rng));
            out.push('}');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub(super) fn spellings(seed: u64, value: &Value) -> Vec<String> {
    let mut rng = Rng::new(seed ^ 0x5eed);
    let mut texts = vec![value.to_string()];
    for _ in 0..SPELLINGS {
        let mut out = String::new();
        spell(&mut rng, value, &mut out);
        texts.push(out);
    }
    texts
}

/// Remove keys and items, and flatten subtrees, while `fails` still holds.
pub(super) fn shrink(mut value: Value, fails: &dyn Fn(&Value) -> bool) -> Value {
    loop {
        let smaller = candidates(&value)
            .into_iter()
            .find(|candidate| fails(candidate));
        match smaller {
            Some(candidate) => value = candidate,
            None => return value,
        }
    }
}

fn candidates(value: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                let mut without = map.clone();
                without.remove(key);
                out.push(Value::Object(without));
                for smaller in candidates(item) {
                    let mut replaced = map.clone();
                    replaced.insert(key.clone(), smaller);
                    out.push(Value::Object(replaced));
                }
            }
        }
        Value::Array(items) => {
            for index in 0..items.len() {
                let mut without = items.clone();
                without.remove(index);
                out.push(Value::Array(without));
                for smaller in candidates(&items[index]) {
                    let mut replaced = items.clone();
                    replaced[index] = smaller;
                    out.push(Value::Array(replaced));
                }
            }
        }
        Value::String(text) if !text.is_empty() => {
            let mut chars: Vec<char> = text.chars().collect();
            chars.pop();
            out.push(Value::String(chars.into_iter().collect()));
            out.push(Value::Null);
        }
        Value::Null => {}
        _ => out.push(Value::Null),
    }
    out
}

/// Every leaf path of `value`, as object keys and array indices.
pub(super) fn leaves(value: &Value, path: &mut Vec<Value>, out: &mut Vec<Vec<Value>>) {
    match value {
        Value::Object(map) if !map.is_empty() => map.iter().for_each(|(key, item)| {
            path.push(key.clone().into());
            leaves(item, path, out);
            path.pop();
        }),
        Value::Array(items) if !items.is_empty() => {
            items.iter().enumerate().for_each(|(index, item)| {
                path.push(index.into());
                leaves(item, path, out);
                path.pop();
            })
        }
        _ => out.push(path.clone()),
    }
}

pub(super) fn changed(leaf: &Value) -> Value {
    match leaf {
        Value::Null => json!(false),
        Value::Bool(flag) => json!(!flag),
        Value::Number(number) => json!(if number.as_i64() == Some(0) { 1 } else { 0 }),
        Value::String(text) => json!(format!("{text}a")),
        Value::Array(_) => json!([null]),
        Value::Object(_) => json!({"": null}),
    }
}
