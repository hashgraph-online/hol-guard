//! Bridge validated JSON values into serde's buffered enum representation.
//! serde_json::Number emits u128/i128 from deserialize_any for wide integers,
//! but serde's tagged/untagged Content visitor cannot carry those events. Use
//! serde_json's arbitrary-precision number-map representation only for that
//! event; concrete numeric fields still use Number's typed deserializers.

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};
use serde::Deserializer;
use serde_json::{Error, Number, Value};

pub(super) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    T::deserialize(JsonValue(value))
}

struct JsonValue(Value);

macro_rules! numeric_methods {
    ($($method:ident),+ $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            match self.0 {
                Value::Number(number) => number.$method(visitor),
                other => JsonValue(other).deserialize_any(visitor),
            }
        })+
    };
}

impl<'de> Deserializer<'de> for JsonValue {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(value) => visitor.visit_bool(value),
            Value::String(value) => visitor.visit_string(value),
            Value::Array(values) => visitor.visit_seq(JsonSequence(values.into_iter())),
            Value::Object(values) => visitor.visit_map(JsonObject {
                entries: values.into_iter(),
                pending: None,
            }),
            Value::Number(number) => {
                if let Some(value) = number.as_u64() {
                    visitor.visit_u64(value)
                } else if let Some(value) = number.as_i64() {
                    visitor.visit_i64(value)
                } else if number
                    .as_str()
                    .bytes()
                    .any(|byte| matches!(byte, b'.' | b'e' | b'E'))
                {
                    let value = number
                        .as_f64()
                        .filter(|value| value.is_finite())
                        .ok_or_else(|| de::Error::custom("native_json_number_invalid"))?;
                    visitor.visit_f64(value)
                } else {
                    visitor.visit_map(WideNumber {
                        number,
                        key_pending: true,
                    })
                }
            }
        }
    }

    numeric_methods!(
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
    );

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.0.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Value::String(variant) => visitor.visit_enum(variant.into_deserializer()),
            Value::Object(values) if values.len() == 1 => {
                let (variant, value) = values.into_iter().next().unwrap();
                visitor.visit_enum(JsonEnum { variant, value })
            }
            _ => Err(de::Error::custom("native_json_enum_invalid")),
        }
    }

    serde::forward_to_deserialize_any! {
        bool char str string bytes byte_buf unit unit_struct seq tuple tuple_struct
        map struct identifier ignored_any
    }
}

struct JsonSequence(std::vec::IntoIter<Value>);

impl<'de> SeqAccess<'de> for JsonSequence {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|value| seed.deserialize(JsonValue(value)))
            .transpose()
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

struct JsonObject {
    entries: serde_json::map::IntoIter,
    pending: Option<Value>,
}

impl<'de> MapAccess<'de> for JsonObject {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.entries.next() {
            Some((key, value)) => {
                self.pending = Some(value);
                seed.deserialize(key.into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let value = self
            .pending
            .take()
            .ok_or_else(|| de::Error::custom("native_json_value_state_invalid"))?;
        seed.deserialize(JsonValue(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

struct WideNumber {
    number: Number,
    key_pending: bool,
}

impl<'de> MapAccess<'de> for WideNumber {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if !self.key_pending {
            return Ok(None);
        }
        self.key_pending = false;
        seed.deserialize(de::value::BorrowedStrDeserializer::new(
            "$serde_json::private::Number",
        ))
        .map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        // StrDeserializer cannot lend this temporary number's bytes to a caller.
        seed.deserialize(de::value::StrDeserializer::new(self.number.as_str()))
    }
}

struct JsonEnum {
    variant: String,
    value: Value,
}

impl<'de> de::EnumAccess<'de> for JsonEnum {
    type Error = Error;
    type Variant = JsonValue;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, JsonValue), Error> {
        let variant = seed.deserialize(self.variant.into_deserializer())?;
        Ok((variant, JsonValue(self.value)))
    }
}

impl<'de> de::VariantAccess<'de> for JsonValue {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        serde::Deserialize::deserialize(self)
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_tuple(len, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_struct("", fields, visitor)
    }
}
