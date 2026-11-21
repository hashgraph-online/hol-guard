//! A JSON settings object that keeps lone surrogate escapes and the
//! user's formatting through a rewrite.

use super::{render, Doc, Step};
use crate::pyjson::PyVal;

/// A JSON object read with each lone surrogate escape mapped, so a rewrite
/// keeps it the way CPython's `json.loads`/`json.dumps` round trip does.
#[derive(Default)]
pub(crate) struct Object {
    pub(crate) entries: Vec<(String, PyVal)>,
    mapped: bool,
    /// The text the object was read from, whose formatting a rewrite keeps.
    source: Option<String>,
}

impl Object {
    /// The object in `text`: `None` when it is not JSON (or holds a lone
    /// surrogate escape beside a character it maps onto), `Some(Err)` when
    /// it is JSON but not an object.
    pub(crate) fn parse(text: &str) -> Option<Result<Self, ()>> {
        let parsed = crate::pyjson::parse_mapping_lone_surrogates(text).ok()?;
        if parsed.mapped && parsed.collision {
            return None;
        }
        Some(match parsed.value {
            PyVal::Dict(entries) => Ok(Self {
                entries,
                mapped: parsed.mapped,
                source: Some(text.to_owned()),
            }),
            _ => Err(()),
        })
    }

    /// `payload[key] = value`, keeping an existing key's position.
    pub(crate) fn set(&mut self, key: &str, value: PyVal) {
        let mut doc = Doc(std::mem::take(&mut self.entries));
        doc.set(key, value);
        self.entries = doc.0;
    }

    /// Whether a lone surrogate escape was mapped on the way in.
    pub(crate) fn mapped(&self) -> bool {
        self.mapped
    }

    /// `json.dumps(payload, indent=2)`.
    pub(crate) fn render(&self) -> Step<String> {
        let value = PyVal::Dict(self.entries.clone());
        if self.mapped {
            render_restoring_surrogates(&value)
        } else {
            render(&value)
        }
    }

    /// The file text to write: [`Self::render`] laid over the formatting of
    /// the text the object was read from, so members Guard did not touch keep
    /// the user's bytes. A new file, or one holding a lone surrogate escape,
    /// is the plain render followed by `default_end`.
    pub(crate) fn render_document(&self, default_end: &str) -> Step<String> {
        let rendered = self.render()?;
        let original = self.source.as_deref().filter(|_| !self.mapped);
        Ok(crate::json_splice::document(
            original,
            &rendered,
            default_end,
        ))
    }
}

/// [`render`] for a value read with `pyjson::parse_mapping_lone_surrogates`:
/// each mapped character goes back out as the lone `\uXXXX` escape CPython
/// kept, so a rewrite leaves it as the user saved it.
fn render_restoring_surrogates(value: &PyVal) -> Step<String> {
    let rendered = render(value)?;
    let mut out = String::with_capacity(rendered.len());
    let mut rest = rendered.as_str();
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let step = match mapped_surrogate(tail) {
            Some(code) => {
                out.push_str(&format!("\\u{code:04x}"));
                12
            }
            None => {
                out.push_str(&tail[..2]);
                2
            }
        };
        rest = &tail[step..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The lone surrogate a `\uHIGH\uLOW` pair escape at the start of `tail`
/// stands for, when it encodes a character in the mapped range.
fn mapped_surrogate(tail: &str) -> Option<u32> {
    let unit = |start: usize| {
        let escape = tail.get(start..start + 6)?;
        let digits = escape.strip_prefix("\\u")?;
        digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
            .then(|| u32::from_str_radix(digits, 16).ok())
            .flatten()
    };
    let (high, low) = (unit(0)?, unit(6)?);
    if !(0xd800..0xdc00).contains(&high) || !(0xdc00..0xe000).contains(&low) {
        return None;
    }
    let code = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
    let offset = code.checked_sub(crate::pyjson::SURROGATE_PLANE_BASE)?;
    (offset < 0x800).then_some(0xd800 + offset)
}
