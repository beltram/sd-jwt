use crate::core::disclosure::Disclosure;
use crate::crypto::CryptoBackend;
use serde_json::Value;
use std::str::FromStr;

/// Home baked JSON Pointer implementation that also drops the selected value
///
/// For more information read [RFC6901](https://tools.ietf.org/html/rfc6901)
pub trait JsonPointer {
    /// Finds the value by JSON Pointer then removes the key from the JSON Value
    /// and returns the key name and value in order to build a [crate::core::disclosure::Disclosure]
    // TODO: have this return a Result
    fn find_drop(&mut self, pointer: &str) -> Option<(String, Value)>;
}

impl JsonPointer for Value {
    fn find_drop(&mut self, pointer: &str) -> Option<(String, Value)> {
        if pointer.is_empty() || !pointer.starts_with('/') {
            return None;
        }
        let tokens = pointer
            .split('/')
            .skip(1)
            .map(|x| x.replace("~1", "/").replace("~0", "~"))
            .collect::<Vec<_>>();
        let tokens_len = tokens.len();

        let mut sd_value = None;

        let result = tokens.into_iter().enumerate().try_fold(
            (String::new(), Some(self)),
            |(_, acc), (index, token)| match acc {
                Some(Value::Object(map)) => {
                    let is_last_token = index == tokens_len - 1;
                    if is_last_token {
                        sd_value = map.remove(&token);
                        Some((token, None))
                    } else {
                        map.get_mut(&token).map(|value| (token, Some(value)))
                    }
                }
                Some(Value::Array(list)) => {
                    let item_index = usize::from_str(&token).unwrap();
                    let item = list.get_mut(item_index)?;

                    let disclosure = Disclosure::try_new(&mut CryptoBackend::new(), None, item.clone()).unwrap();
                    let hash = disclosure.hash().unwrap();
                    *item = serde_json::json!({"...": hash});

                    None
                }
                _ => None,
            },
        );

        result.and_then(move |(name, _)| sd_value.map(|v| (name, v)))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn should_find_and_take_primitive() {
        let mut input = json!({
            "string": "s",
            "int": 42,
            "float": 4.13,
            "bool": false,
            "obj": {
                "a": 1,
                "b": 2
            },
            "array": [0, 1, 2]
        });

        // string
        let (path, value) = input.find_drop("/string").unwrap();
        assert_eq!(path, "string");
        assert_eq!(value, "s");
        assert_eq!(
            input,
            json!({
                "int": 42,
                "float": 4.13,
                "bool": false,
                "obj": {
                    "a": 1,
                    "b": 2
                },
                "array": [0, 1, 2]
            })
        );

        // int
        let (path, value) = input.find_drop("/int").unwrap();
        assert_eq!(path, "int");
        assert_eq!(value, 42);
        assert_eq!(
            input,
            json!({
                "float": 4.13,
                "bool": false,
                "obj": {
                    "a": 1,
                    "b": 2
                },
                "array": [0, 1, 2]
            })
        );

        // float
        let (path, value) = input.find_drop("/float").unwrap();
        assert_eq!(path, "float");
        assert_eq!(value, 4.13);
        assert_eq!(
            input,
            json!({
                "bool": false,
                "obj": {
                    "a": 1,
                    "b": 2
                },
                "array": [0, 1, 2]
            })
        );

        // bool
        let (path, value) = input.find_drop("/bool").unwrap();
        assert_eq!(path, "bool");
        assert_eq!(value, false);
        assert_eq!(
            input,
            json!({
                "obj": {
                    "a": 1,
                    "b": 2
                },
                "array": [0, 1, 2]
            })
        );

        // object
        let (path, value) = input.find_drop("/obj").unwrap();
        assert_eq!(path, "obj");
        assert_eq!(value, json!({"a": 1, "b": 2}));
        assert_eq!(input, json!({"array": [0, 1, 2]}));

        // array
        let (path, value) = input.find_drop("/array").unwrap();
        assert_eq!(path, "array");
        assert_eq!(value, json!([0, 1, 2]));
        assert_eq!(input, json!({}));
    }

    #[test]
    fn should_find_and_replace_array_item() {
        let mut input = json!({
            "array": [0, 1, 2]
        });

        assert!(input.find_drop("/array/2").is_none());

        let array = input.get("array").unwrap().as_array().unwrap();
        assert_eq!(array.get(0).unwrap(), &json!(0));
        assert_eq!(array.get(1).unwrap(), &json!(1));

        let disclosure = array.get(2).unwrap().as_object().unwrap();
        assert!(!disclosure.get("...").unwrap().as_str().unwrap().is_empty());
    }

    #[test]
    fn should_return_none_when_not_found() {
        let mut input = json!({"a": 1});
        assert!(input.find_drop("/b").is_none());
    }
}
