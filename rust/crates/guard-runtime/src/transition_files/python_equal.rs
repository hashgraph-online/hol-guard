//! Equality as Python's `==` reads two decoded JSON values.
//!
//! A reviewed plan is compared with one the runtime rebuilt, as the Python
//! `payload() != value` checks compared them: `1 == 1.0` and `True == 1`, and
//! two containers are equal when every member is. `serde_json::Value`
//! equality keeps those apart, which would refuse a plan Python accepted.

use serde_json::{Number, Value};

/// A number or boolean as the exact integer or float Python compares.
enum Scalar {
    Int(i128),
    Float(f64),
}

fn integer(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

fn scalar(value: &Value) -> Option<Scalar> {
    match value {
        Value::Bool(flag) => Some(Scalar::Int(i128::from(*flag))),
        Value::Number(number) => integer(number)
            .map(Scalar::Int)
            .or_else(|| number.as_f64().map(Scalar::Float)),
        _ => None,
    }
}

fn same_scalar(left: &Scalar, right: &Scalar) -> bool {
    match (left, right) {
        (Scalar::Int(a), Scalar::Int(b)) => a == b,
        (Scalar::Float(a), Scalar::Float(b)) => a == b,
        (Scalar::Int(a), Scalar::Float(b)) | (Scalar::Float(b), Scalar::Int(a)) => {
            b.fract() == 0.0 && b.abs() < 1e38 && *b as i128 == *a
        }
    }
}

pub(super) fn python_equal(left: &Value, right: &Value) -> bool {
    if let (Some(a), Some(b)) = (scalar(left), scalar(right)) {
        return same_scalar(&a, &b);
    }
    match (left, right) {
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| python_equal(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, x)| b.get(key).is_some_and(|y| python_equal(x, y)))
        }
        _ => left == right,
    }
}

#[cfg(test)]
mod tests {
    use super::python_equal;
    use serde_json::json;

    #[test]
    fn numbers_and_booleans_compare_as_python_compares_them() {
        assert!(python_equal(&json!(1), &json!(1.0)));
        assert!(python_equal(
            &json!({"a": [1, true]}),
            &json!({"a": [1.0, 1]})
        ));
        assert!(python_equal(&json!(0), &json!(false)));
        assert!(!python_equal(&json!(1), &json!(1.5)));
        assert!(!python_equal(&json!(1), &json!("1")));
        assert!(!python_equal(&json!({"a": 1}), &json!({"a": 1, "b": 1})));
        assert!(!python_equal(&json!([1, 2]), &json!([2, 1])));
        assert!(python_equal(&json!(null), &json!(null)));
        assert!(!python_equal(&json!(null), &json!(false)));
    }
}
